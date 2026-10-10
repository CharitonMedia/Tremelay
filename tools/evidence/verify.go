package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const twoBuildScope = "two workspaces and two compilation caches on one builder; not independent-builder or cross-platform reproducibility"

// Verify checks one evidence directory against the pinned schema and the binary.
func Verify(evidenceDir, schemaDir string) error {
	if err := CheckSchemaFiles(schemaDir); err != nil {
		return err
	}
	if err := verifySums(evidenceDir); err != nil {
		return err
	}
	binHash, err := FileSHA256(filepath.Join(evidenceDir, "tremelay"))
	if err != nil {
		return err
	}
	var inputs BuildInputs
	var receipt TwoBuildReceipt
	var infoDoc BuildInfoDoc
	var inventory SourceInventory
	var validation ValidationReport
	var sourceMeta, binaryMeta ScanMeta
	if err := readJSON(filepath.Join(evidenceDir, "build-inputs.json"), &inputs); err != nil {
		return err
	}
	if err := readJSON(filepath.Join(evidenceDir, "two-build-receipt.json"), &receipt); err != nil {
		return err
	}
	if err := readJSON(filepath.Join(evidenceDir, "binary-buildinfo.json"), &infoDoc); err != nil {
		return err
	}
	if err := readJSON(filepath.Join(evidenceDir, "source-inventory.json"), &inventory); err != nil {
		return err
	}
	if err := readJSON(filepath.Join(evidenceDir, "sbom-validation.json"), &validation); err != nil {
		return err
	}
	if err := readJSON(filepath.Join(evidenceDir, "govulncheck-source-meta.json"), &sourceMeta); err != nil {
		return err
	}
	if err := readJSON(filepath.Join(evidenceDir, "govulncheck-binary-meta.json"), &binaryMeta); err != nil {
		return err
	}
	id := Identity{
		SourceCommit:   inputs.SourceCommit,
		SourceTree:     inputs.SourceTree,
		ArtifactSHA256: binHash,
		GoModSHA256:    inputs.GoModSHA256,
		GoSumSHA256:    inputs.GoSumSHA256,
	}
	if !hex40(id.SourceCommit) || !hex40(id.SourceTree) {
		return fmt.Errorf("source commit or tree is not 40 hex digits")
	}
	if err := sameIdentity(id, receipt.SourceCommit, receipt.SourceTree, receipt.ArtifactSHA256, receipt.GoModSHA256, receipt.GoSumSHA256, "two-build receipt"); err != nil {
		return err
	}
	if err := sameIdentity(id, infoDoc.SourceCommit, infoDoc.SourceTree, infoDoc.ArtifactSHA256, infoDoc.GoModSHA256, infoDoc.GoSumSHA256, "buildinfo"); err != nil {
		return err
	}
	if err := sameIdentity(id, inventory.SourceCommit, inventory.SourceTree, inventory.ArtifactSHA256, inventory.GoModSHA256, inventory.GoSumSHA256, "source inventory"); err != nil {
		return err
	}
	if err := sameIdentity(id, validation.SourceCommit, validation.SourceTree, validation.ArtifactSHA256, inputs.GoModSHA256, inputs.GoSumSHA256, "sbom validation"); err != nil {
		return err
	}
	if err := sameIdentity(id, sourceMeta.SourceCommit, sourceMeta.SourceTree, sourceMeta.ArtifactSHA256, sourceMeta.GoModSHA256, sourceMeta.GoSumSHA256, "source scan"); err != nil {
		return err
	}
	if err := sameIdentity(id, binaryMeta.SourceCommit, binaryMeta.SourceTree, binaryMeta.ArtifactSHA256, binaryMeta.GoModSHA256, binaryMeta.GoSumSHA256, "binary scan"); err != nil {
		return err
	}
	if err := checkInputs(inputs); err != nil {
		return err
	}
	if err := checkReceipt(receipt, binHash); err != nil {
		return err
	}
	sbom, err := os.ReadFile(filepath.Join(evidenceDir, "sbom.cdx.json"))
	if err != nil {
		return err
	}
	if err := ValidateSBOM(schemaDir, sbom); err != nil {
		return err
	}
	if !validation.Valid || validation.SpecVersion != "1.6" || validation.SchemaCommit != SchemaCommit || validation.ValidatorSum != ValidatorSum || validation.GeneratorVersion != CycloneDXVer || validation.GeneratorSum != CycloneDXSum {
		return fmt.Errorf("sbom validation report does not match the pinned generator, validator, and schema")
	}
	for name, want := range SchemaSHA256 {
		if validation.SchemaFiles[name] != want {
			return fmt.Errorf("validation report schema hash for %s", name)
		}
	}
	gotHash, err := componentSHA256(sbom)
	if err != nil {
		return err
	}
	if gotHash != binHash {
		return fmt.Errorf("sbom artifact hash %s, binary %s", gotHash, binHash)
	}
	var root map[string]any
	if err := json.Unmarshal(sbom, &root); err != nil {
		return err
	}
	md, _ := root["metadata"].(map[string]any)
	props := propMap(md)
	if props["tremelay:source-commit"] != id.SourceCommit || props["tremelay:source-tree"] != id.SourceTree {
		return fmt.Errorf("sbom source identity does not match the candidate")
	}
	info, err := ReadBuildInfo(filepath.Join(evidenceDir, "tremelay"))
	if err != nil {
		return err
	}
	if err := CheckProfile(info); err != nil {
		return err
	}
	if err := compareRecorded(infoDoc, info); err != nil {
		return err
	}
	if infoDoc.Note != ReachNote {
		return fmt.Errorf("buildinfo note dropped the module-inventory limit")
	}
	if err := CompareBuildInfo(info, sbom); err != nil {
		return err
	}
	if err := checkInventory(inventory, info); err != nil {
		return err
	}
	readme, err := os.ReadFile(filepath.Join(evidenceDir, "README.md"))
	if err != nil {
		return err
	}
	if err := checkScan(evidenceDir, "source", sourceMeta, readme); err != nil {
		return err
	}
	if err := checkScan(evidenceDir, "binary", binaryMeta, readme); err != nil {
		return err
	}
	text := string(readme)
	for _, phrase := range []string{
		id.SourceCommit,
		binHash,
		"unsigned",
		"should not yet be trusted with production credentials",
		"not a claim that the candidate has no vulnerabilities",
		"does not prove that every module function remains linked or reachable",
		"one builder",
	} {
		if !strings.Contains(text, phrase) {
			return fmt.Errorf("assurance README missing %q", phrase)
		}
	}
	return nil
}

func checkInputs(in BuildInputs) error {
	if in.GoVersion != GoVersion || in.Toolchain != GoToolchain || in.Target != Target || in.GOAMD64 != TargetGOAMD64 || in.CGOEnabled != TargetCGO {
		return fmt.Errorf("build inputs do not match the linux/amd64 Go %s profile", GoVersion)
	}
	if !in.GoModUnchanged || !in.GoSumUnchanged {
		return fmt.Errorf("build inputs report a changed go.mod or go.sum")
	}
	joined := strings.Join(in.BuildCommand, " ")
	for _, flag := range []string{"-trimpath", "-buildvcs=false", "-mod=readonly", "-pgo=off", "./cmd/tremelay"} {
		if !strings.Contains(joined, flag) {
			return fmt.Errorf("build command missing %s", flag)
		}
	}
	if in.BuildEnv["GOTOOLCHAIN"] != GoToolchain || in.BuildEnv["GOOS"] != TargetGOOS || in.BuildEnv["GOARCH"] != TargetGOARCH || in.BuildEnv["GOAMD64"] != TargetGOAMD64 || in.BuildEnv["CGO_ENABLED"] != TargetCGO {
		return fmt.Errorf("recorded build environment does not match the profile")
	}
	if in.Tools["cyclonedx-gomod"] != CycloneDXModule+"@"+CycloneDXVer+" "+CycloneDXSum {
		return fmt.Errorf("cyclonedx-gomod pin mismatch")
	}
	if in.Tools["govulncheck"] != VulnModule+"@"+VulnVersion+" "+VulnSum {
		return fmt.Errorf("govulncheck pin mismatch")
	}
	if in.Tools["jsonschema"] != ValidatorModule+"@"+ValidatorVer+" "+ValidatorSum {
		return fmt.Errorf("jsonschema pin mismatch")
	}
	if in.Schema["commit"] != SchemaCommit || in.CIActionPins["actions/checkout"] != CheckoutSHA || in.CIActionPins["actions/setup-go"] != SetupGoSHA {
		return fmt.Errorf("schema or action pin mismatch")
	}
	if in.Builder["runner_image_revision"] == "" {
		return fmt.Errorf("builder image revision was not recorded")
	}
	return nil
}

func checkReceipt(r TwoBuildReceipt, binHash string) error {
	if !r.ByteIdentical || r.GoVersion != GoVersion || r.Scope != twoBuildScope {
		return fmt.Errorf("two-build receipt does not record a match within the one-builder scope")
	}
	if len(r.Builds) != 2 {
		return fmt.Errorf("two-build receipt has %d builds", len(r.Builds))
	}
	if r.Builds[0].Workspace == r.Builds[1].Workspace || r.Builds[0].Cache == r.Builds[1].Cache || r.Builds[0].Output == r.Builds[1].Output {
		return fmt.Errorf("two-build receipt reuses a workspace, cache, or output path")
	}
	for _, b := range r.Builds {
		if b.SHA256 != binHash || !filepath.IsAbs(b.Workspace) || !filepath.IsAbs(b.Cache) {
			return fmt.Errorf("two-build path or hash is not the candidate")
		}
	}
	if r.ModuleCache == "" || r.ModuleCacheNote == "" {
		return fmt.Errorf("module cache reuse was not recorded")
	}
	return nil
}

func compareRecorded(doc BuildInfoDoc, info *buildinfo.BuildInfo) error {
	if doc.GoVersion != info.GoVersion || doc.Path != info.Path || doc.Main.Path != info.Main.Path || doc.Main.Version != info.Main.Version || doc.Main.Sum != info.Main.Sum {
		return fmt.Errorf("recorded buildinfo does not match the binary")
	}
	if len(doc.Deps) != len(info.Deps) {
		return fmt.Errorf("recorded buildinfo has %d deps, binary has %d", len(doc.Deps), len(info.Deps))
	}
	for i, d := range info.Deps {
		if d == nil || !modEqual(doc.Deps[i], modFrom(*d)) {
			return fmt.Errorf("recorded buildinfo dep %d does not match the binary", i)
		}
	}
	for _, s := range info.Settings {
		if doc.Settings[s.Key] != s.Value {
			return fmt.Errorf("recorded build setting %s does not match the binary", s.Key)
		}
	}
	return nil
}

func modEqual(a, b ModID) bool {
	if a.Path != b.Path || a.Version != b.Version || a.Sum != b.Sum {
		return false
	}
	if (a.Replace == nil) != (b.Replace == nil) {
		return false
	}
	if a.Replace != nil && !modEqual(*a.Replace, *b.Replace) {
		return false
	}
	return true
}

func checkInventory(inv SourceInventory, info *buildinfo.BuildInfo) error {
	if inv.Inventory != "source-test-reference-and-build-tool" || !inv.NotBinaryInventory {
		return fmt.Errorf("source inventory is not labeled separately from the binary SBOM")
	}
	if !strings.Contains(inv.Note, "not the CLI binary inventory") {
		return fmt.Errorf("source inventory note is missing")
	}
	inBinary, binVer := mcpFromInfo(info)
	inSource, srcVer := mcpFromMods(inv.MainModuleGraph)
	if inv.MCPSDKInBinary != inBinary || inv.MCPSDKBinaryVersion != binVer || inv.MCPSDKInSourceGraph != inSource || inv.MCPSDKSourceVersion != srcVer {
		return fmt.Errorf("MCP SDK classification does not match the binary and source graph")
	}
	return nil
}

func mcpFromInfo(info *buildinfo.BuildInfo) (bool, string) {
	for _, d := range info.Deps {
		if d == nil {
			continue
		}
		e := d
		if d.Replace != nil {
			e = d.Replace
		}
		if e.Path == MCPSDKPath {
			return true, e.Version
		}
	}
	return false, ""
}

func mcpFromMods(mods []Mod) (bool, string) {
	for _, m := range mods {
		if m.Path == MCPSDKPath {
			return true, m.Version
		}
	}
	return false, ""
}

func checkScan(dir, scope string, meta ScanMeta, readme []byte) error {
	if meta.Scope != scope {
		return fmt.Errorf("scan meta scope %s, want %s", meta.Scope, scope)
	}
	raw, err := os.ReadFile(filepath.Join(dir, meta.RawReport))
	if err != nil {
		return err
	}
	a, err := Assess(raw, meta.ExitStatus)
	if err != nil {
		return fmt.Errorf("%s scan: %w", scope, err)
	}
	if meta.ClaimsVulnerabilityAbsence {
		return fmt.Errorf("%s scan claims vulnerability absence", scope)
	}
	if meta.ScannerVersion != VulnVersion || meta.ScannerSum != VulnSum || meta.Limits != ScanLimit || meta.DatabaseNote != DBNote {
		return fmt.Errorf("%s scan metadata does not match the pinned govulncheck contract", scope)
	}
	if meta.DatabaseSnapshotID != nil {
		return fmt.Errorf("%s scan invented a database snapshot id", scope)
	}
	if meta.CalledFindings != a.Called || meta.ImportedFindings != a.Imported || meta.ModuleFindings != a.Required || meta.SymbolGatePass != a.SymbolGatePass {
		return fmt.Errorf("%s scan metadata does not match the raw findings", scope)
	}
	if !sameIDs(meta.FindingIDs, a.FindingIDs) {
		return fmt.Errorf("%s scan finding ids do not match the raw report", scope)
	}
	if meta.DatabaseEndpoint != a.DatabaseEndpoint || meta.DatabaseLastModifiedAvailable != a.DatabaseLastModifiedAvailable || meta.DatabaseLastModified != a.DatabaseLastModified {
		return fmt.Errorf("%s scan database metadata does not match the raw report", scope)
	}
	if a.Blocked || !a.SymbolGatePass {
		reason := a.BlockReason
		if reason == "" {
			reason = "symbol gate did not pass"
		}
		return fmt.Errorf("%s scan: %s", scope, reason)
	}
	text := string(readme)
	for _, id := range a.FindingIDs {
		if !strings.Contains(text, id) {
			return fmt.Errorf("assurance README omits %s finding %s", scope, id)
		}
	}
	return nil
}

func sameIDs(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameIdentity(id Identity, commit, tree, artifact, gomod, gosum, what string) error {
	if commit != id.SourceCommit || tree != id.SourceTree || artifact != id.ArtifactSHA256 || gomod != id.GoModSHA256 || gosum != id.GoSumSHA256 {
		return fmt.Errorf("%s does not identify this candidate", what)
	}
	return nil
}

func propMap(md map[string]any) map[string]string {
	out := map[string]string{}
	raw, _ := md["properties"].([]any)
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		val, _ := m["value"].(string)
		out[name] = val
	}
	return out
}

func verifySums(dir string) error {
	f, err := os.Open(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	defer f.Close()
	listed := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 || strings.Contains(name, "/") || name == "SHA256SUMS" || name == "" {
			return fmt.Errorf("malformed checksum line %q", line)
		}
		if _, dup := listed[name]; dup {
			return fmt.Errorf("duplicate checksum for %s", name)
		}
		listed[name] = sum
	}
	if err := sc.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			return fmt.Errorf("unexpected directory %s in evidence", e.Name())
		}
		seen[e.Name()] = true
		if e.Name() == "SHA256SUMS" {
			continue
		}
		want, ok := listed[e.Name()]
		if !ok {
			return fmt.Errorf("missing checksum for %s", e.Name())
		}
		got, err := FileSHA256(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("checksum mismatch for %s", e.Name())
		}
	}
	for name := range listed {
		if !seen[name] {
			return fmt.Errorf("checksum lists missing file %s", name)
		}
	}
	for _, name := range EvidenceFiles {
		if !seen[name] {
			return fmt.Errorf("evidence missing %s", name)
		}
	}
	if len(seen) != len(EvidenceFiles)+1 {
		return fmt.Errorf("evidence directory has unexpected files")
	}
	return nil
}

// WriteSHA256SUMS writes sums for the evidence files present in dir.
func WriteSHA256SUMS(dir string) error {
	var buf bytes.Buffer
	for _, name := range EvidenceFiles {
		sum, err := FileSHA256(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		fmt.Fprintf(&buf, "%s  %s\n", sum, name)
	}
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS"), buf.Bytes(), 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

// HashBytes is the hex SHA-256 of b.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
