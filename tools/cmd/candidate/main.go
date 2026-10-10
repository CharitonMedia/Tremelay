package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CharitonMedia/Tremelay/tools/evidence"
)

func main() {
	root := flag.String("root", "..", "repository root")
	out := flag.String("out", "", "evidence directory (default <root>/dist/m11a-candidate)")
	flag.Parse()
	if err := run(*root, *out); err != nil {
		fmt.Fprintf(os.Stderr, "candidate: %v\n", err)
		os.Exit(1)
	}
}

func run(root, out string) error {
	if runtime.Version() != evidence.GoVersion {
		return fmt.Errorf("evidence tool runtime %s, want %s", runtime.Version(), evidence.GoVersion)
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if out == "" {
		out = filepath.Join(root, "dist", "m11a-candidate")
	}
	out, err = filepath.Abs(out)
	if err != nil {
		return err
	}
	if filepath.Base(out) != "m11a-candidate" {
		return fmt.Errorf("refusing to replace %s", out)
	}
	toolsDir := filepath.Join(root, "tools")
	schemaDir := filepath.Join(toolsDir, "schema", "cyclonedx")
	if err := evidence.CheckSchemaFiles(schemaDir); err != nil {
		return err
	}
	sumText, err := os.ReadFile(filepath.Join(toolsDir, "go.sum"))
	if err != nil {
		return err
	}
	for _, pin := range []struct{ module, version, sum string }{
		{evidence.CycloneDXModule, evidence.CycloneDXVer, evidence.CycloneDXSum},
		{evidence.VulnModule, evidence.VulnVersion, evidence.VulnSum},
		{evidence.ValidatorModule, evidence.ValidatorVer, evidence.ValidatorSum},
	} {
		got, err := evidence.ModuleSum(sumText, pin.module, pin.version)
		if err != nil {
			return err
		}
		if got != pin.sum {
			return fmt.Errorf("%s@%s sum %s, pin %s", pin.module, pin.version, got, pin.sum)
		}
	}
	goBin, err := toolchainGo()
	if err != nil {
		return err
	}
	commit, err := gitOut(root, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	tree, err := gitOut(root, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	if len(commit) != 40 || len(tree) != 40 {
		return fmt.Errorf("refusing ambiguous git identity commit=%q tree=%q", commit, tree)
	}
	status, err := gitOut(root, "status", "--porcelain")
	if err != nil {
		return err
	}
	if status != "" {
		return fmt.Errorf("refusing modified source:\n%s", status)
	}
	goMod := filepath.Join(root, "go.mod")
	goSum := filepath.Join(root, "go.sum")
	modHash, err := evidence.FileSHA256(goMod)
	if err != nil {
		return err
	}
	sumHash, err := evidence.FileSHA256(goSum)
	if err != nil {
		return err
	}
	modCache, err := goEnvOne(goBin, root, "GOMODCACHE")
	if err != nil {
		return err
	}
	parent, err := os.MkdirTemp("", "tremelay-m11a-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(parent)
	type side struct {
		name string
		src  string
		bin  string
		sum  string
	}
	var sides [2]side
	for i, name := range []string{"a", "b"} {
		src := filepath.Join(parent, name, "src")
		cache := filepath.Join(parent, name, "gocache")
		bin := filepath.Join(parent, name, "out", "tremelay")
		if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
			return err
		}
		if err := os.MkdirAll(cache, 0o755); err != nil {
			return err
		}
		if err := extractArchive(root, src); err != nil {
			return err
		}
		if got, err := evidence.FileSHA256(filepath.Join(src, "go.mod")); err != nil || got != modHash {
			return fmt.Errorf("workspace %s go.mod hash %s, source %s (%v)", name, got, modHash, err)
		}
		if got, err := evidence.FileSHA256(filepath.Join(src, "go.sum")); err != nil || got != sumHash {
			return fmt.Errorf("workspace %s go.sum hash %s, source %s (%v)", name, got, sumHash, err)
		}
		if err := build(goBin, src, cache, modCache, bin); err != nil {
			return fmt.Errorf("build %s: %w", name, err)
		}
		if got, err := evidence.FileSHA256(filepath.Join(src, "go.mod")); err != nil || got != modHash {
			return fmt.Errorf("build %s changed go.mod", name)
		}
		if got, err := evidence.FileSHA256(filepath.Join(src, "go.sum")); err != nil || got != sumHash {
			return fmt.Errorf("build %s changed go.sum", name)
		}
		sum, err := evidence.FileSHA256(bin)
		if err != nil {
			return err
		}
		absSrc, err := filepath.Abs(src)
		if err != nil {
			return err
		}
		absBin, err := filepath.Abs(bin)
		if err != nil {
			return err
		}
		sides[i] = side{name: name, src: absSrc, bin: absBin, sum: sum}
	}
	caches := [2]string{
		mustAbs(filepath.Join(parent, "a", "gocache")),
		mustAbs(filepath.Join(parent, "b", "gocache")),
	}
	same, err := fileEqual(sides[0].bin, sides[1].bin)
	if err != nil {
		return err
	}
	if !same || sides[0].sum != sides[1].sum {
		return fmt.Errorf("builds differ: %s %s and %s %s", sides[0].bin, sides[0].sum, sides[1].bin, sides[1].sum)
	}
	if got, err := evidence.FileSHA256(goMod); err != nil || got != modHash {
		return fmt.Errorf("preparing the candidate changed go.mod")
	}
	if got, err := evidence.FileSHA256(goSum); err != nil || got != sumHash {
		return fmt.Errorf("preparing the candidate changed go.sum")
	}
	if err := os.RemoveAll(out); err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	binPath := filepath.Join(out, "tremelay")
	if err := copyFile(binPath, sides[0].bin, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		return err
	}
	id := evidence.Identity{
		SourceCommit:   commit,
		SourceTree:     tree,
		ArtifactSHA256: sides[0].sum,
		GoModSHA256:    modHash,
		GoSumSHA256:    sumHash,
	}
	info, err := evidence.ReadBuildInfo(binPath)
	if err != nil {
		return err
	}
	if err := evidence.CheckProfile(info); err != nil {
		return err
	}
	infoDoc := evidence.BuildInfoDocFrom(info, id)
	sbomPath := filepath.Join(out, "sbom.cdx.json")
	toolCache, err := os.MkdirTemp("", "tremelay-m11a-tool-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(toolCache)
	if err := runTool(goBin, toolsDir, modCache, toolCache, "cyclonedx-gomod", "bin", "-json", "-output-version", "1.6", "-std", "-noserial", "-notimestamp", "-output", sbomPath, binPath); err != nil {
		return fmt.Errorf("cyclonedx-gomod: %w", err)
	}
	rawSBOM, err := os.ReadFile(sbomPath)
	if err != nil {
		return err
	}
	bound, err := evidence.BindSBOM(rawSBOM, id)
	if err != nil {
		return err
	}
	if err := evidence.ValidateSBOM(schemaDir, bound); err != nil {
		return err
	}
	if err := os.WriteFile(sbomPath, bound, 0o644); err != nil {
		return err
	}
	if err := evidence.CompareBuildInfo(info, bound); err != nil {
		return err
	}
	mainGraph, err := listModules(goBin, sides[0].src, modCache)
	if err != nil {
		return fmt.Errorf("source module graph: %w", err)
	}
	toolGraph, err := listModules(goBin, toolsDir, modCache)
	if err != nil {
		return fmt.Errorf("build-tool module graph: %w", err)
	}
	inBinary, binVer := false, ""
	for _, d := range info.Deps {
		if d != nil && d.Path == evidence.MCPSDKPath && (d.Replace == nil || d.Replace.Path == evidence.MCPSDKPath) {
			inBinary, binVer = true, d.Version
			if d.Replace != nil {
				binVer = d.Replace.Version
			}
		}
	}
	inSource, srcVer := false, ""
	for _, m := range mainGraph {
		if m.Path == evidence.MCPSDKPath {
			inSource, srcVer = true, m.Version
		}
	}
	buildEnv := profileEnv(goBin, modCache, caches[0])
	goEnv, err := goEnvJSON(goBin, sides[0].src, buildEnv)
	if err != nil {
		return err
	}
	versionOut, err := commandOutput(goBin, sides[0].src, buildEnv, "version")
	if err != nil {
		return err
	}
	inputs := evidence.BuildInputs{
		SourceCommit:    commit,
		SourceTree:      tree,
		ArtifactSHA256:  id.ArtifactSHA256,
		GoModSHA256:     modHash,
		GoSumSHA256:     sumHash,
		GoModUnchanged:  true,
		GoSumUnchanged:  true,
		GoVersion:       evidence.GoVersion,
		Toolchain:       evidence.GoToolchain,
		Target:          evidence.Target,
		GOAMD64:         evidence.TargetGOAMD64,
		CGOEnabled:      evidence.TargetCGO,
		BuildCommand:    []string{"go", "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-pgo=off", "-o", "<output>/tremelay", "./cmd/tremelay"},
		BuildEnv:        envMap(buildEnv),
		GoEnv:           goEnv,
		GoVersionOutput: strings.TrimSpace(versionOut),
		ModuleCache:     modCache,
		Builder:         builderIdentity(),
		Tools: map[string]string{
			"cyclonedx-gomod": evidence.CycloneDXModule + "@" + evidence.CycloneDXVer + " " + evidence.CycloneDXSum,
			"govulncheck":     evidence.VulnModule + "@" + evidence.VulnVersion + " " + evidence.VulnSum,
			"jsonschema":      evidence.ValidatorModule + "@" + evidence.ValidatorVer + " " + evidence.ValidatorSum,
		},
		Schema: map[string]string{
			"name":                 "CycloneDX BOM",
			"tag":                  evidence.SchemaTag,
			"commit":               evidence.SchemaCommit,
			"bom-1.6.schema.json":  evidence.SchemaSHA256["bom-1.6.schema.json"],
			"jsf-0.82.schema.json": evidence.SchemaSHA256["jsf-0.82.schema.json"],
			"spdx.schema.json":     evidence.SchemaSHA256["spdx.schema.json"],
		},
		CIActionPins: map[string]string{
			"actions/checkout": evidence.CheckoutSHA,
			"actions/setup-go": evidence.SetupGoSHA,
		},
		VCSNote:    "The executable is built with -buildvcs=false. Source commit and tree in this manifest are authoritative.",
		RecipeNote: "Reproducibility is the byte match of the two builds, not the flag list. Scope is this toolchain, target, flags, and the observed builder.",
	}
	receipt := evidence.TwoBuildReceipt{
		SourceCommit:   commit,
		SourceTree:     tree,
		ArtifactSHA256: id.ArtifactSHA256,
		GoModSHA256:    modHash,
		GoSumSHA256:    sumHash,
		GoVersion:      evidence.GoVersion,
		ByteIdentical:  true,
		Builds: []evidence.BuildSide{
			{Workspace: sides[0].src, Output: sides[0].bin, Cache: caches[0], SHA256: sides[0].sum},
			{Workspace: sides[1].src, Output: sides[1].bin, Cache: caches[1], SHA256: sides[1].sum},
		},
		ModuleCache:     modCache,
		ModuleCacheNote: "The module download cache was shared and recorded. Compiled output caches were separate and initially empty.",
		Scope:           "two workspaces and two compilation caches on one builder; not independent-builder or cross-platform reproducibility",
	}
	validation := evidence.ValidationReport{
		SourceCommit:     commit,
		SourceTree:       tree,
		ArtifactSHA256:   id.ArtifactSHA256,
		SchemaName:       "CycloneDX BOM 1.6",
		SchemaTag:        evidence.SchemaTag,
		SchemaCommit:     evidence.SchemaCommit,
		SchemaFiles:      evidence.SchemaSHA256,
		ValidatorModule:  evidence.ValidatorModule,
		ValidatorVersion: evidence.ValidatorVer,
		ValidatorSum:     evidence.ValidatorSum,
		GeneratorModule:  evidence.CycloneDXModule,
		GeneratorVersion: evidence.CycloneDXVer,
		GeneratorSum:     evidence.CycloneDXSum,
		GeneratorCommand: "cyclonedx-gomod bin -json -output-version 1.6 -std -noserial -notimestamp",
		Valid:            true,
		SpecVersion:      "1.6",
	}
	inventory := evidence.SourceInventory{
		Inventory:           "source-test-reference-and-build-tool",
		NotBinaryInventory:  true,
		SourceCommit:        commit,
		SourceTree:          tree,
		ArtifactSHA256:      id.ArtifactSHA256,
		GoModSHA256:         modHash,
		GoSumSHA256:         sumHash,
		MainModuleGraph:     mainGraph,
		BuildTools:          toolGraph,
		MCPSDKInBinary:      inBinary,
		MCPSDKBinaryVersion: binVer,
		MCPSDKInSourceGraph: inSource,
		MCPSDKSourceVersion: srcVer,
		Note:                "This is the go list -m all graph of the application module, including test dependencies of that module, plus the pinned build-tool module graph. It is not the CLI binary inventory.",
	}
	sourceRaw, sourceMeta, err := scan(goBin, toolsDir, modCache, toolCache, "source", []string{"govulncheck", "-C", sides[0].src, "-format=json", "./..."}, id)
	if err != nil {
		return err
	}
	binaryRaw, binaryMeta, err := scan(goBin, toolsDir, modCache, toolCache, "binary", []string{"govulncheck", "-mode=binary", "-format=json", binPath}, id)
	if err != nil {
		return err
	}
	readme := evidence.AssuranceREADME(evidence.READMEInput{
		ID:             id,
		SourceFindings: sourceMeta.FindingIDs,
		BinaryFindings: binaryMeta.FindingIDs,
		MCPSDKInBinary: inBinary,
		MCPSDKVersion:  binVer,
	})
	if err := evidence.WriteJSON(filepath.Join(out, "build-inputs.json"), inputs); err != nil {
		return err
	}
	if err := evidence.WriteJSON(filepath.Join(out, "two-build-receipt.json"), receipt); err != nil {
		return err
	}
	if err := evidence.WriteJSON(filepath.Join(out, "binary-buildinfo.json"), infoDoc); err != nil {
		return err
	}
	if err := evidence.WriteJSON(filepath.Join(out, "source-inventory.json"), inventory); err != nil {
		return err
	}
	if err := evidence.WriteJSON(filepath.Join(out, "sbom-validation.json"), validation); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "govulncheck-source.json"), sourceRaw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "govulncheck-binary.json"), binaryRaw, 0o644); err != nil {
		return err
	}
	if err := evidence.WriteJSON(filepath.Join(out, "govulncheck-source-meta.json"), sourceMeta); err != nil {
		return err
	}
	if err := evidence.WriteJSON(filepath.Join(out, "govulncheck-binary-meta.json"), binaryMeta); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "README.md"), []byte(readme), 0o644); err != nil {
		return err
	}
	if err := evidence.WriteSHA256SUMS(out); err != nil {
		return err
	}
	if got, err := evidence.FileSHA256(goMod); err != nil || got != modHash {
		return fmt.Errorf("preparing the candidate changed go.mod")
	}
	if got, err := evidence.FileSHA256(goSum); err != nil || got != sumHash {
		return fmt.Errorf("preparing the candidate changed go.sum")
	}
	return evidence.Verify(out, schemaDir)
}

func scan(goBin, toolsDir, modCache, toolCache, scope string, args []string, id evidence.Identity) ([]byte, evidence.ScanMeta, error) {
	start := time.Now().UTC()
	cmd := exec.Command(goBin, append([]string{"tool"}, args...)...)
	cmd.Dir = toolsDir
	cmd.Env = toolEnv(goBin, modCache, toolCache)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	end := time.Now().UTC()
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, evidence.ScanMeta{}, err
		}
		exit = ee.ExitCode()
	}
	raw := stdout.Bytes()
	assessed, aerr := evidence.Assess(raw, exit)
	meta := evidence.ScanMetaFrom(scope, "govulncheck-"+scope+".json", args, id, start, end, stderr.String(), assessed)
	if aerr != nil {
		meta.SymbolGatePass = false
		meta.ClaimsVulnerabilityAbsence = false
		return raw, meta, fmt.Errorf("%s scan: %w", scope, aerr)
	}
	return raw, meta, nil
}

func listModules(goBin, dir, modCache string) ([]evidence.Mod, error) {
	cache, err := os.MkdirTemp("", "tremelay-m11a-list-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cache)
	cmd := exec.Command(goBin, "list", "-m", "-json", "all")
	cmd.Dir = dir
	cmd.Env = profileEnv(goBin, modCache, cache)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%w: %s", err, ee.Stderr)
		}
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	var mods []evidence.Mod
	for {
		var m evidence.Mod
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		mods = append(mods, m)
	}
	if mods == nil {
		mods = []evidence.Mod{}
	}
	return mods, nil
}

func build(goBin, src, cache, modCache, out string) error {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	empty, err := os.ReadDir(cache)
	if err != nil {
		return err
	}
	if len(empty) != 0 {
		return fmt.Errorf("compilation cache %s is not empty", cache)
	}
	cmd := exec.Command(goBin, "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-pgo=off", "-o", out, "./cmd/tremelay")
	cmd.Dir = src
	cmd.Env = profileEnv(goBin, modCache, cache)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runTool(goBin, toolsDir, modCache, toolCache string, args ...string) error {
	cmd := exec.Command(goBin, append([]string{"tool"}, args...)...)
	cmd.Dir = toolsDir
	cmd.Env = toolEnv(goBin, modCache, toolCache)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func profileEnv(goBin, modCache, goCache string) []string {
	env := baseEnv(goBin)
	env = append(env,
		"GOTOOLCHAIN="+evidence.GoToolchain,
		"GOOS="+evidence.TargetGOOS,
		"GOARCH="+evidence.TargetGOARCH,
		"GOAMD64="+evidence.TargetGOAMD64,
		"CGO_ENABLED="+evidence.TargetCGO,
		"GO111MODULE=on",
		"GOFLAGS=-mod=readonly",
		"GOCACHE="+goCache,
		"GOMODCACHE="+modCache,
		"GOPROXY=https://proxy.golang.org,direct",
		"GOSUMDB=sum.golang.org",
		"GOTELEMETRY=off",
	)
	return env
}

func toolEnv(goBin, modCache, cache string) []string {
	env := baseEnv(goBin)
	env = append(env,
		"GOTOOLCHAIN="+evidence.GoToolchain,
		"GO111MODULE=on",
		"GOFLAGS=-mod=readonly",
		"GOCACHE="+cache,
		"GOMODCACHE="+modCache,
		"GOPROXY=https://proxy.golang.org,direct",
		"GOSUMDB=sum.golang.org",
		"GOTELEMETRY=off",
	)
	return env
}

func baseEnv(goBin string) []string {
	env := []string{
		"PATH=" + filepath.Dir(goBin) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + os.TempDir(),
	}
	for _, k := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func envMap(env []string) map[string]string {
	out := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "PATH" || k == "HOME" || k == "TMPDIR" || strings.Contains(strings.ToLower(k), "proxy") || strings.HasPrefix(k, "SSL_") {
			continue
		}
		out[k] = v
	}
	return out
}

func toolchainGo() (string, error) {
	cmd := exec.Command("go", "env", "GOROOT")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN="+evidence.GoToolchain)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go env GOROOT: %w", err)
	}
	bin := filepath.Join(strings.TrimSpace(string(out)), "bin", "go")
	ver, err := exec.Command(bin, "version").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(ver))
	if len(fields) < 3 || fields[2] != evidence.GoVersion {
		return "", fmt.Errorf("toolchain %s reports %q, want %s", bin, strings.TrimSpace(string(ver)), evidence.GoVersion)
	}
	return bin, nil
}

func goEnvOne(goBin, dir, key string) (string, error) {
	cmd := exec.Command(goBin, "env", key)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN="+evidence.GoToolchain)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func goEnvJSON(goBin, dir string, env []string) (map[string]string, error) {
	keys := []string{"GOVERSION", "GOOS", "GOARCH", "GOAMD64", "CGO_ENABLED", "GOTOOLCHAIN", "GO111MODULE", "GOPROXY", "GOSUMDB", "GOMODCACHE", "GOFLAGS"}
	cmd := exec.Command(goBin, append([]string{"env", "-json"}, keys...)...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func commandOutput(bin, dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func gitOut(root string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), ee.Stderr)
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func extractArchive(root, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	archive := exec.Command("git", "archive", "--format=tar", "HEAD")
	archive.Dir = root
	extract := exec.Command("tar", "-xf", "-", "-C", dest)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		return err
	}
	extract.Stdin = pipe
	var aerr, terr bytes.Buffer
	archive.Stderr = &aerr
	extract.Stderr = &terr
	if err := archive.Start(); err != nil {
		return err
	}
	if err := extract.Start(); err != nil {
		return err
	}
	if err := archive.Wait(); err != nil {
		return fmt.Errorf("git archive: %w: %s", err, aerr.String())
	}
	if err := extract.Wait(); err != nil {
		return fmt.Errorf("tar: %w: %s", err, terr.String())
	}
	return nil
}

func builderIdentity() map[string]string {
	id := map[string]string{
		"goos":   runtime.GOOS,
		"goarch": runtime.GOARCH,
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "ID", "VERSION_ID", "VERSION", "PRETTY_NAME":
				id["os_release_"+k] = v
			}
		}
	}
	if out, err := exec.Command("uname", "-srm").Output(); err == nil {
		id["uname"] = strings.TrimSpace(string(out))
	}
	if v := os.Getenv("ImageOS"); v != "" {
		id["ImageOS"] = v
	}
	if v := os.Getenv("ImageVersion"); v != "" {
		id["runner_image_revision"] = v
	} else {
		id["runner_image_revision"] = "not exposed by this builder"
	}
	return id
}

func copyFile(dst, src string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fileEqual(a, b string) (bool, error) {
	ab, err := os.ReadFile(a)
	if err != nil {
		return false, err
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ab, bb), nil
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
