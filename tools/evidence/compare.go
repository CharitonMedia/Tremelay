package evidence

import (
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

// ReadBuildInfo reads Go build information without executing the file.
func ReadBuildInfo(path string) (*buildinfo.BuildInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := buildinfo.Read(f)
	if err != nil {
		return nil, fmt.Errorf("unreadable build information: %w", err)
	}
	return info, nil
}

// CheckProfile requires the M11a linux/amd64 recipe in the binary's own settings.
func CheckProfile(info *buildinfo.BuildInfo) error {
	if info.GoVersion != GoVersion {
		return fmt.Errorf("binary go version %s, want %s", info.GoVersion, GoVersion)
	}
	want := map[string]string{
		"-trimpath":   "true",
		"CGO_ENABLED": TargetCGO,
		"GOARCH":      TargetGOARCH,
		"GOOS":        TargetGOOS,
		"GOAMD64":     TargetGOAMD64,
	}
	got := map[string]string{}
	for _, s := range info.Settings {
		if strings.HasPrefix(s.Key, "vcs.") {
			return fmt.Errorf("build setting %s is present; -buildvcs=false did not drop VCS metadata", s.Key)
		}
		got[s.Key] = s.Value
	}
	for k, v := range want {
		if got[k] != v {
			return fmt.Errorf("build setting %s=%q, want %q", k, got[k], v)
		}
	}
	return nil
}

// BuildInfoDocFrom records the independent buildinfo read.
func BuildInfoDocFrom(info *buildinfo.BuildInfo, id Identity) BuildInfoDoc {
	doc := BuildInfoDoc{
		SourceCommit:   id.SourceCommit,
		SourceTree:     id.SourceTree,
		ArtifactSHA256: id.ArtifactSHA256,
		GoModSHA256:    id.GoModSHA256,
		GoSumSHA256:    id.GoSumSHA256,
		GoVersion:      info.GoVersion,
		Path:           info.Path,
		Main:           modFrom(info.Main),
		Deps:           []ModID{},
		Settings:       map[string]string{},
		Note:           ReachNote,
	}
	for _, d := range info.Deps {
		if d == nil {
			continue
		}
		doc.Deps = append(doc.Deps, modFrom(*d))
	}
	for _, s := range info.Settings {
		doc.Settings[s.Key] = s.Value
	}
	return doc
}

func modFrom(m debug.Module) ModID {
	out := ModID{Path: m.Path, Version: m.Version, Sum: m.Sum}
	if m.Replace != nil {
		r := modFrom(*m.Replace)
		out.Replace = &r
	}
	return out
}

type sbomMod struct {
	version string
	hash    string
}

// CompareBuildInfo checks the SBOM's runtime modules against build information.
// The standard library is required. A replacement module is the effective one.
func CompareBuildInfo(info *buildinfo.BuildInfo, sbom []byte) error {
	if info.GoVersion != GoVersion {
		return fmt.Errorf("binary go version %s, want %s", info.GoVersion, GoVersion)
	}
	var root map[string]any
	if err := json.Unmarshal(sbom, &root); err != nil {
		return err
	}
	if root["bomFormat"] != "CycloneDX" || root["specVersion"] != "1.6" {
		return fmt.Errorf("sbom is not CycloneDX 1.6")
	}
	md, _ := root["metadata"].(map[string]any)
	if md == nil {
		return fmt.Errorf("sbom missing metadata")
	}
	if err := checkBinding(md, info.GoVersion); err != nil {
		return err
	}
	comp, _ := md["component"].(map[string]any)
	if comp == nil {
		return fmt.Errorf("sbom missing metadata.component")
	}
	name, _ := comp["name"].(string)
	if name != info.Main.Path {
		return fmt.Errorf("sbom main %q, buildinfo %q", name, info.Main.Path)
	}
	ver, _ := comp["version"].(string)
	if ver != "" && ver != info.Main.Version {
		return fmt.Errorf("sbom main version %q, buildinfo %q", ver, info.Main.Version)
	}
	mods, err := sbomModules(root)
	if err != nil {
		return err
	}
	expected := map[string]debug.Module{}
	for _, d := range info.Deps {
		if d == nil {
			continue
		}
		e := *d
		if d.Replace != nil {
			e = *d.Replace
		}
		if _, ok := expected[e.Path]; ok {
			return fmt.Errorf("duplicate buildinfo module %s", e.Path)
		}
		expected[e.Path] = e
	}
	for path, e := range expected {
		got, ok := mods[path]
		if !ok {
			return fmt.Errorf("sbom missing runtime module %s@%s", path, e.Version)
		}
		if got.version != e.Version {
			return fmt.Errorf("runtime module %s version %s, buildinfo %s", path, got.version, e.Version)
		}
		if e.Sum != "" {
			if got.hash == "" {
				return fmt.Errorf("sbom missing checksum for %s", path)
			}
			if !sumMatch(e.Sum, got.hash) {
				return fmt.Errorf("checksum mismatch for %s", path)
			}
		}
		delete(mods, path)
	}
	for path, got := range mods {
		return fmt.Errorf("unexplained sbom module %s@%s", path, got.version)
	}
	if err := checkGenerator(md); err != nil {
		return err
	}
	return nil
}

func checkBinding(md map[string]any, goVersion string) error {
	props := map[string]string{}
	raw, _ := md["properties"].([]any)
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		val, _ := m["value"].(string)
		props[name] = val
	}
	want := map[string]string{
		"tremelay:go-version":  goVersion,
		"tremelay:target":      Target,
		"tremelay:goamd64":     TargetGOAMD64,
		"tremelay:cgo-enabled": TargetCGO,
	}
	for k, v := range want {
		if props[k] != v {
			return fmt.Errorf("sbom property %s=%q, want %q", k, props[k], v)
		}
	}
	if !hex40(props["tremelay:source-commit"]) || !hex40(props["tremelay:source-tree"]) {
		return fmt.Errorf("sbom source identity is not a git commit and tree")
	}
	return nil
}

func checkGenerator(md map[string]any) error {
	raw, ok := md["tools"].([]any)
	if !ok {
		return fmt.Errorf("sbom metadata.tools is not the generator list")
	}
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if m["name"] == "cyclonedx-gomod" && m["version"] == CycloneDXVer {
			return nil
		}
	}
	return fmt.Errorf("sbom generator is not cyclonedx-gomod %s", CycloneDXVer)
}

func sbomModules(root map[string]any) (map[string]sbomMod, error) {
	raw, _ := root["components"].([]any)
	out := map[string]sbomMod{}
	std := 0
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("sbom component is not an object")
		}
		name, _ := m["name"].(string)
		ver, _ := m["version"].(string)
		kind, _ := m["type"].(string)
		hash := sha256Hash(m["hashes"])
		if name == "std" || purlPath(m["purl"]) == "std" {
			if kind != "library" {
				return nil, fmt.Errorf("stdlib component type %s", kind)
			}
			std++
			if ver != GoVersion {
				return nil, fmt.Errorf("stdlib version %s, want %s", ver, GoVersion)
			}
			continue
		}
		if kind != "library" {
			return nil, fmt.Errorf("unexplained sbom component %s type %s", name, kind)
		}
		if p := purlPath(m["purl"]); p != "" && p != name {
			return nil, fmt.Errorf("sbom purl path %s, name %s", p, name)
		}
		if pv := purlVersion(m["purl"]); pv != "" && pv != ver {
			return nil, fmt.Errorf("sbom purl version %s, version %s", pv, ver)
		}
		if _, ok := out[name]; ok {
			return nil, fmt.Errorf("duplicate sbom module %s", name)
		}
		out[name] = sbomMod{version: ver, hash: hash}
	}
	if std != 1 {
		return nil, fmt.Errorf("sbom stdlib components = %d, want 1", std)
	}
	return out, nil
}

func sha256Hash(v any) string {
	raw, _ := v.([]any)
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok || m["alg"] != "SHA-256" {
			continue
		}
		s, _ := m["content"].(string)
		return strings.ToLower(s)
	}
	return ""
}

func purlPath(v any) string {
	s, _ := v.(string)
	const prefix = "pkg:golang/"
	if !strings.HasPrefix(s, prefix) {
		return ""
	}
	rest := s[len(prefix):]
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		return rest[:i]
	}
	return rest
}

func purlVersion(v any) string {
	s, _ := v.(string)
	const prefix = "pkg:golang/"
	if !strings.HasPrefix(s, prefix) {
		return ""
	}
	rest := s[len(prefix):]
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		return rest[i+1:]
	}
	return ""
}

func sumMatch(h1sum, hexHash string) bool {
	if !strings.HasPrefix(h1sum, "h1:") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h1sum, "h1:"))
	if err != nil {
		return false
	}
	return hex.EncodeToString(raw) == strings.ToLower(hexHash)
}

func componentSHA256(sbom []byte) (string, error) {
	var root map[string]any
	if err := json.Unmarshal(sbom, &root); err != nil {
		return "", err
	}
	md, _ := root["metadata"].(map[string]any)
	if md == nil {
		return "", fmt.Errorf("sbom missing metadata")
	}
	comp, _ := md["component"].(map[string]any)
	if comp == nil {
		return "", fmt.Errorf("sbom missing metadata.component")
	}
	sum := sha256Hash(comp["hashes"])
	if sum == "" {
		return "", fmt.Errorf("sbom metadata.component has no SHA-256")
	}
	props, _ := md["properties"].([]any)
	for _, item := range props {
		m, ok := item.(map[string]any)
		if !ok || m["name"] != "cdx:gomod:binary:hash:SHA-256" {
			continue
		}
		val, _ := m["value"].(string)
		if strings.ToLower(val) != sum {
			return "", fmt.Errorf("sbom binary hash property does not match component hash")
		}
	}
	return sum, nil
}

func hex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
