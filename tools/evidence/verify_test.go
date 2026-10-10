package evidence

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func TestEvidenceBundle(t *testing.T) {
	schema := schemaDir(t)
	bin, info := buildSynth(t)
	id := Identity{
		SourceCommit:   strings.Repeat("a", 40),
		SourceTree:     strings.Repeat("b", 40),
		GoModSHA256:    strings.Repeat("c", 64),
		GoSumSHA256:    strings.Repeat("d", 64),
		ArtifactSHA256: "",
	}
	sum, err := FileSHA256(bin)
	if err != nil {
		t.Fatal(err)
	}
	id.ArtifactSHA256 = sum
	binBytes, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("match", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, nil)
		if err := Verify(dir, schema); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("binary hash mismatch", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, nil)
		sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
		if err != nil {
			t.Fatal(err)
		}
		text := string(sums)
		text = strings.Replace(text, sum, strings.Repeat("0", 64), 1)
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := Verify(dir, schema); err == nil {
			t.Fatal("expected checksum mismatch")
		}
	})
	t.Run("missing runtime module", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, func(sbom map[string]any) {
			sbom["components"] = []any{stdComponent()}
		})
		if err := Verify(dir, schema); err == nil || !strings.Contains(err.Error(), "missing runtime module") {
			t.Fatal(err)
		}
	})
	t.Run("extra runtime module", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, func(sbom map[string]any) {
			comps := sbom["components"].([]any)
			comps = append(comps, map[string]any{"type": "library", "name": "github.com/extra/mod", "version": "v0.1.0"})
			sbom["components"] = comps
		})
		if err := Verify(dir, schema); err == nil || !strings.Contains(err.Error(), "unexplained sbom module") {
			t.Fatal(err)
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, func(sbom map[string]any) {
			for _, item := range sbom["components"].([]any) {
				m := item.(map[string]any)
				if m["name"] != "std" {
					m["version"] = "v9.9.9"
				}
			}
		})
		if err := Verify(dir, schema); err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatal(err)
		}
	})
	t.Run("invalid sbom schema", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, nil)
		if err := os.WriteFile(filepath.Join(dir, "sbom.cdx.json"), []byte("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"not-a-field\":true}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := WriteSHA256SUMS(dir); err != nil {
			t.Fatal(err)
		}
		if err := Verify(dir, schema); err == nil || !strings.Contains(err.Error(), "schema") {
			t.Fatal(err)
		}
	})
	t.Run("structured exit zero with findings", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, nil)
		raw := []byte(`{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.8.0","db":"https://vuln.go.dev","db_last_modified":"2026-10-08T22:31:09Z","scan_level":"symbol","scan_mode":"binary"}}
{"finding":{"osv":"GO-2026-0001","trace":[{"module":"example.com/dep","function":"F"}]}}
`)
		if err := os.WriteFile(filepath.Join(dir, "govulncheck-binary.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		assessed, err := Assess(raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		meta := ScanMetaFrom("binary", "govulncheck-binary.json", []string{"govulncheck", "-mode=binary", "-format=json", "tremelay"}, id, time.Now().UTC(), time.Now().UTC(), "", assessed)
		if meta.ExitStatus != 0 || meta.SymbolGatePass {
			t.Fatalf("exit %d gate %v", meta.ExitStatus, meta.SymbolGatePass)
		}
		if err := WriteJSON(filepath.Join(dir, "govulncheck-binary-meta.json"), meta); err != nil {
			t.Fatal(err)
		}
		readme := AssuranceREADME(READMEInput{ID: id, BinaryFindings: meta.FindingIDs})
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := WriteSHA256SUMS(dir); err != nil {
			t.Fatal(err)
		}
		err = Verify(dir, schema)
		if err == nil || !strings.Contains(err.Error(), "not a clean result") {
			t.Fatal(err)
		}
	})
	t.Run("manifest artifact hash mismatch", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, nil)
		path := filepath.Join(dir, "build-inputs.json")
		var doc map[string]any
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		doc["artifact_sha256"] = strings.Repeat("e", 64)
		if err := WriteJSON(path, doc); err != nil {
			t.Fatal(err)
		}
		if err := WriteSHA256SUMS(dir); err != nil {
			t.Fatal(err)
		}
		err = Verify(dir, schema)
		if err == nil || !strings.Contains(err.Error(), "build inputs artifact hash") {
			t.Fatal(err)
		}
	})
	t.Run("binary metadata points at source report", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, nil)
		path := filepath.Join(dir, "govulncheck-binary-meta.json")
		var meta ScanMeta
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &meta); err != nil {
			t.Fatal(err)
		}
		meta.RawReport = "govulncheck-source.json"
		if err := WriteJSON(path, meta); err != nil {
			t.Fatal(err)
		}
		if err := WriteSHA256SUMS(dir); err != nil {
			t.Fatal(err)
		}
		err = Verify(dir, schema)
		if err == nil || !strings.Contains(err.Error(), "report path") {
			t.Fatal(err)
		}
	})
	t.Run("binary report is a source scan", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, nil)
		if err := os.WriteFile(filepath.Join(dir, "govulncheck-binary.json"), scanFixture("source"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := WriteSHA256SUMS(dir); err != nil {
			t.Fatal(err)
		}
		err := Verify(dir, schema)
		if err == nil || !strings.Contains(err.Error(), "scan_mode") {
			t.Fatal(err)
		}
	})
	t.Run("scanner identity mismatch", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, nil)
		raw := bytes.Replace(scanFixture("binary"), []byte(VulnVersion), []byte("v0.0.1"), 1)
		if err := os.WriteFile(filepath.Join(dir, "govulncheck-binary.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := WriteSHA256SUMS(dir); err != nil {
			t.Fatal(err)
		}
		err := Verify(dir, schema)
		if err == nil || !strings.Contains(err.Error(), "scanner_version") {
			t.Fatal(err)
		}
	})
	t.Run("nested metadata component", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, func(sbom map[string]any) {
			md := sbom["metadata"].(map[string]any)
			comp := md["component"].(map[string]any)
			comp["components"] = []any{map[string]any{"type": "library", "name": "github.com/hidden/mod", "version": "v0.0.1"}}
		})
		sbom, err := os.ReadFile(filepath.Join(dir, "sbom.cdx.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateSBOM(schema, sbom); err != nil {
			t.Fatal(err)
		}
		err = Verify(dir, schema)
		if err == nil || !strings.Contains(err.Error(), "nested sbom component") {
			t.Fatal(err)
		}
	})
	t.Run("nested root component", func(t *testing.T) {
		dir := t.TempDir()
		writeBundle(t, dir, schema, binBytes, info, id, func(sbom map[string]any) {
			comps := sbom["components"].([]any)
			comps[0].(map[string]any)["components"] = []any{map[string]any{"type": "library", "name": "github.com/hidden/mod", "version": "v0.0.1"}}
			sbom["components"] = comps
		})
		sbom, err := os.ReadFile(filepath.Join(dir, "sbom.cdx.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateSBOM(schema, sbom); err != nil {
			t.Fatal(err)
		}
		err = Verify(dir, schema)
		if err == nil || !strings.Contains(err.Error(), "nested sbom component") {
			t.Fatal(err)
		}
	})
}

func TestCheckProfileRejectsExperiment(t *testing.T) {
	info := &buildinfo.BuildInfo{
		GoVersion: GoVersion,
		Settings: []debug.BuildSetting{
			{Key: "-buildmode", Value: "exe"},
			{Key: "-compiler", Value: "gc"},
			{Key: "-trimpath", Value: "true"},
			{Key: "CGO_ENABLED", Value: "0"},
			{Key: "GOARCH", Value: "amd64"},
			{Key: "GOOS", Value: "linux"},
			{Key: "GOAMD64", Value: "v1"},
			{Key: "GOEXPERIMENT", Value: "fieldtrack"},
		},
	}
	err := CheckProfile(info)
	if err == nil || !strings.Contains(err.Error(), "GOEXPERIMENT") {
		t.Fatal(err)
	}
}

func TestSchemaBytesSurviveCheckout(t *testing.T) {
	if err := CheckSchemaFiles(schemaDir(t)); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(schemaDir(t), "..", "..", "..")
	for name := range SchemaSHA256 {
		rel := filepath.ToSlash(filepath.Join("tools", "schema", "cyclonedx", name))
		cmd := exec.Command("git", "check-attr", "text", "--", rel)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v\n%s", rel, err, out)
		}
		if !bytes.Contains(out, []byte("text: unset")) {
			t.Fatalf("%s checkout can rewrite pinned bytes: %s", rel, out)
		}
	}
}

func TestUnreadableBuildInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tremelay")
	if err := os.WriteFile(path, []byte("not a go binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ReadBuildInfo(path)
	if err == nil || !strings.Contains(err.Error(), "unreadable build information") {
		t.Fatal(err)
	}
}

func TestModuleFindingDoesNotClaimAbsence(t *testing.T) {
	raw := []byte(`{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.8.0","db":"https://vuln.go.dev","db_last_modified":"2026-10-08T22:31:09Z","scan_level":"symbol","scan_mode":"binary"}}
{"finding":{"osv":"GO-2026-0002","fixed_version":"v1.2.4","trace":[{"module":"example.com/dep","version":"v1.2.3"}]}}
`)
	a, err := Assess(raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.Blocked || !a.SymbolGatePass || a.Required != 1 || a.Called != 0 {
		t.Fatalf("module finding should stay visible without failing the symbol gate: %+v", a)
	}
	meta := ScanMetaFrom("binary", "govulncheck-binary.json", nil, Identity{}, time.Now(), time.Now(), "", a)
	if meta.ClaimsVulnerabilityAbsence || meta.ModuleFindings != 1 {
		t.Fatalf("%+v", meta)
	}
}

func schemaDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "schema", "cyclonedx")
}

func buildSynth(t *testing.T) (string, *buildinfo.BuildInfo) {
	t.Helper()
	dir := t.TempDir()
	dep := filepath.Join(dir, "dep")
	if err := os.Mkdir(dep, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/synth\n\ngo 1.26.9\n\nrequire example.com/dep v1.2.3\n\nreplace example.com/dep => ./dep\n")
	write("main.go", "package main\n\nimport \"example.com/dep\"\n\nfunc main() { dep.F() }\n")
	if err := os.WriteFile(filepath.Join(dep, "go.mod"), []byte("module example.com/dep\n\ngo 1.26.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dep, "dep.go"), []byte("package dep\n\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "tremelay")
	cache := filepath.Join(dir, "gocache")
	if err := os.Mkdir(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-pgo=off", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOENV=off",
		"GOWORK=off",
		"GOEXPERIMENT=",
		"GOCACHEPROG=",
		"GOFIPS140=off",
		"GOTOOLCHAIN="+GoToolchain,
		"GOOS=linux",
		"GOARCH=amd64",
		"GOAMD64=v1",
		"CGO_ENABLED=0",
		"GOFLAGS=",
		"GOCACHE="+cache,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("synth build: %v\n%s", err, out)
	}
	info, err := ReadBuildInfo(bin)
	if err != nil {
		t.Fatal(err)
	}
	return bin, info
}

func writeBundle(t *testing.T, dir, schema string, bin []byte, info *buildinfo.BuildInfo, id Identity, mutate func(map[string]any)) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "tremelay"), bin, 0o755); err != nil {
		t.Fatal(err)
	}
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"metadata": map[string]any{
			"tools": []any{map[string]any{"name": "cyclonedx-gomod", "version": CycloneDXVer}},
			"component": map[string]any{
				"type": "application",
				"name": info.Main.Path,
			},
			"properties": []any{map[string]any{"name": "cdx:gomod:binary:hash:SHA-256", "value": id.ArtifactSHA256}},
		},
		"components": []any{stdComponent()},
	}
	comps := sbom["components"].([]any)
	for _, d := range info.Deps {
		if d == nil {
			continue
		}
		e := d
		if d.Replace != nil {
			e = d.Replace
		}
		comps = append(comps, map[string]any{"type": "library", "name": e.Path, "version": e.Version})
	}
	sbom["components"] = comps
	if mutate != nil {
		mutate(sbom)
	}
	raw, err := json.Marshal(sbom)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindSBOM(raw, id)
	if err != nil {
		t.Fatal(err)
	}
	if mutate == nil {
		if err := ValidateSBOM(schema, bound); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "sbom.cdx.json"), bound, 0o644); err != nil {
		t.Fatal(err)
	}
	wsA := filepath.Join(os.TempDir(), "tremelay-evidence-a")
	wsB := filepath.Join(os.TempDir(), "tremelay-evidence-b")
	cacheA := filepath.Join(os.TempDir(), "tremelay-evidence-cache-a")
	cacheB := filepath.Join(os.TempDir(), "tremelay-evidence-cache-b")
	inputs := BuildInputs{
		SourceCommit: id.SourceCommit, SourceTree: id.SourceTree, ArtifactSHA256: id.ArtifactSHA256,
		GoModSHA256: id.GoModSHA256, GoSumSHA256: id.GoSumSHA256, GoModUnchanged: true, GoSumUnchanged: true,
		GoVersion: GoVersion, Toolchain: GoToolchain, Target: Target, GOAMD64: TargetGOAMD64, CGOEnabled: TargetCGO,
		BuildCommand:    []string{"go", "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-pgo=off", "-o", "<output>/tremelay", "./cmd/tremelay"},
		BuildEnv:        pinnedBuildEnv(),
		GoEnv:           pinnedGoEnv(),
		GoVersionOutput: "go version " + GoVersion + " linux/amd64",
		ModuleCache:     filepath.Join(os.TempDir(), "modcache"),
		Builder:         map[string]string{"runner_image_revision": "not exposed by this builder"},
		Tools: map[string]string{
			"cyclonedx-gomod": CycloneDXModule + "@" + CycloneDXVer + " " + CycloneDXSum,
			"govulncheck":     VulnModule + "@" + VulnVersion + " " + VulnSum,
			"jsonschema":      ValidatorModule + "@" + ValidatorVer + " " + ValidatorSum,
		},
		Schema:       map[string]string{"commit": SchemaCommit},
		CIActionPins: map[string]string{"actions/checkout": CheckoutSHA, "actions/setup-go": SetupGoSHA},
		VCSNote:      "authoritative commit is in this manifest",
		RecipeNote:   "byte match is the check",
	}
	receipt := TwoBuildReceipt{
		SourceCommit: id.SourceCommit, SourceTree: id.SourceTree, ArtifactSHA256: id.ArtifactSHA256,
		GoModSHA256: id.GoModSHA256, GoSumSHA256: id.GoSumSHA256, GoVersion: GoVersion, ByteIdentical: true,
		Builds: []BuildSide{
			{Workspace: wsA, Output: filepath.Join(wsA, "tremelay"), Cache: cacheA, SHA256: id.ArtifactSHA256},
			{Workspace: wsB, Output: filepath.Join(wsB, "tremelay"), Cache: cacheB, SHA256: id.ArtifactSHA256},
		},
		ModuleCache: filepath.Join(os.TempDir(), "modcache"), ModuleCacheNote: "shared download cache recorded",
		ModuleCacheVerified: ModuleCacheVerified,
		Scope:               twoBuildScope,
	}
	sourceRaw := scanFixture("source")
	binaryRaw := scanFixture("binary")
	sourceAssessed, err := Assess(sourceRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	binaryAssessed, err := Assess(binaryRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	sourceMeta := ScanMetaFrom("source", ReportName("source"), []string{"govulncheck", "-format=json", "./..."}, id, now, now, "", sourceAssessed)
	binaryMeta := ScanMetaFrom("binary", ReportName("binary"), []string{"govulncheck", "-mode=binary", "-format=json", "tremelay"}, id, now, now, "", binaryAssessed)
	files := map[string]any{
		"build-inputs.json":            inputs,
		"two-build-receipt.json":       receipt,
		"binary-buildinfo.json":        BuildInfoDocFrom(info, id),
		"source-inventory.json":        testInventory(id),
		"sbom-validation.json":         testValidation(id),
		"govulncheck-source-meta.json": sourceMeta,
		"govulncheck-binary-meta.json": binaryMeta,
	}
	for name, doc := range files {
		if err := WriteJSON(filepath.Join(dir, name), doc); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "govulncheck-source.json"), sourceRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "govulncheck-binary.json"), binaryRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	readme := AssuranceREADME(READMEInput{ID: id, MCPSDKInBinary: false})
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteSHA256SUMS(dir); err != nil {
		t.Fatal(err)
	}
}

func pinnedBuildEnv() map[string]string {
	return map[string]string{
		"GOTOOLCHAIN": GoToolchain, "GOOS": TargetGOOS, "GOARCH": TargetGOARCH,
		"GOAMD64": TargetGOAMD64, "CGO_ENABLED": TargetCGO, "GOENV": "off",
		"GOWORK": "off", "GOEXPERIMENT": "", "GOCACHEPROG": "", "GOFIPS140": "off",
		"GOFLAGS": "-mod=readonly",
	}
}

func pinnedGoEnv() map[string]string {
	return map[string]string{
		"GOVERSION": GoVersion, "GOTOOLCHAIN": GoToolchain, "GOOS": TargetGOOS,
		"GOARCH": TargetGOARCH, "GOAMD64": TargetGOAMD64, "CGO_ENABLED": TargetCGO,
		"GOWORK": "off", "GOEXPERIMENT": "", "GOCACHEPROG": "", "GOFIPS140": "off",
	}
}

func scanFixture(mode string) []byte {
	return []byte(`{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"` + VulnVersion + `","db":"https://vuln.go.dev","db_last_modified":"2026-10-08T22:31:09Z","scan_level":"symbol","scan_mode":"` + mode + `"}}` + "\n")
}

func stdComponent() map[string]any {
	return map[string]any{"type": "library", "name": "std", "version": GoVersion}
}

func testInventory(id Identity) SourceInventory {
	return SourceInventory{
		Inventory: "source-test-reference-and-build-tool", NotBinaryInventory: true,
		SourceCommit: id.SourceCommit, SourceTree: id.SourceTree, ArtifactSHA256: id.ArtifactSHA256,
		GoModSHA256: id.GoModSHA256, GoSumSHA256: id.GoSumSHA256,
		MainModuleGraph: []Mod{{Path: "example.com/synth"}, {Path: "example.com/dep", Version: "v1.2.3"}},
		BuildTools:      []Mod{},
		Note:            "It is not the CLI binary inventory.",
	}
}

func testValidation(id Identity) ValidationReport {
	return ValidationReport{
		SourceCommit: id.SourceCommit, SourceTree: id.SourceTree, ArtifactSHA256: id.ArtifactSHA256,
		SchemaName: "CycloneDX BOM 1.6", SchemaTag: SchemaTag, SchemaCommit: SchemaCommit, SchemaFiles: SchemaSHA256,
		ValidatorModule: ValidatorModule, ValidatorVersion: ValidatorVer, ValidatorSum: ValidatorSum,
		GeneratorModule: CycloneDXModule, GeneratorVersion: CycloneDXVer, GeneratorSum: CycloneDXSum,
		GeneratorCommand: "cyclonedx-gomod bin -json -output-version 1.6 -std -noserial -notimestamp",
		Valid:            true, SpecVersion: "1.6",
	}
}
