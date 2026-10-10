package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	schemaOnce sync.Once
	schemaCmp  *jsonschema.Schema
	schemaErr  error
)

// CheckSchemaFiles hashes the pinned schema set before it is used.
func CheckSchemaFiles(dir string) error {
	for name, want := range SchemaSHA256 {
		got, err := FileSHA256(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("schema %s sha256 %s, pin %s", name, got, want)
		}
	}
	return nil
}

func compileSchema(dir string) (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		if err := CheckSchemaFiles(dir); err != nil {
			schemaErr = err
			return
		}
		c := jsonschema.NewCompiler()
		for name := range SchemaSHA256 {
			f, err := os.Open(filepath.Join(dir, name))
			if err != nil {
				schemaErr = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(f)
			f.Close()
			if err != nil {
				schemaErr = fmt.Errorf("schema %s: %w", name, err)
				return
			}
			if err := c.AddResource(SchemaBase+name, doc); err != nil {
				schemaErr = err
				return
			}
		}
		schemaCmp, schemaErr = c.Compile(SchemaBase + "bom-1.6.schema.json")
	})
	return schemaCmp, schemaErr
}

// ValidateSBOM checks a CycloneDX document against the pinned 1.6 schema.
func ValidateSBOM(schemaDir string, doc []byte) error {
	sch, err := compileSchema(schemaDir)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return fmt.Errorf("sbom json: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("sbom schema: %w", err)
	}
	return nil
}

// BindSBOM records the candidate hash and source identity on a generated
// CycloneDX document. The component inventory is left to the generator.
func BindSBOM(doc []byte, id Identity) ([]byte, error) {
	var root map[string]any
	if err := json.Unmarshal(doc, &root); err != nil {
		return nil, err
	}
	root["bomFormat"] = "CycloneDX"
	root["specVersion"] = "1.6"
	md, _ := root["metadata"].(map[string]any)
	if md == nil {
		return nil, fmt.Errorf("sbom missing metadata")
	}
	want := map[string]string{
		"tremelay:source-commit": id.SourceCommit,
		"tremelay:source-tree":   id.SourceTree,
		"tremelay:go-version":    GoVersion,
		"tremelay:target":        Target,
		"tremelay:goamd64":       TargetGOAMD64,
		"tremelay:cgo-enabled":   TargetCGO,
	}
	var props []any
	if raw, ok := md["properties"].([]any); ok {
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				props = append(props, item)
				continue
			}
			name, _ := m["name"].(string)
			if _, repl := want[name]; repl {
				continue
			}
			props = append(props, m)
		}
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		props = append(props, map[string]any{"name": name, "value": want[name]})
	}
	md["properties"] = props
	comp, _ := md["component"].(map[string]any)
	if comp == nil {
		return nil, fmt.Errorf("sbom missing metadata.component")
	}
	var hashes []any
	if raw, ok := comp["hashes"].([]any); ok {
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok || m["alg"] == "SHA-256" {
				continue
			}
			hashes = append(hashes, m)
		}
	}
	hashes = append(hashes, map[string]any{"alg": "SHA-256", "content": id.ArtifactSHA256})
	comp["hashes"] = hashes
	return marshal(root)
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// FileSHA256 returns the lowercase hex SHA-256 of a file.
func FileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// WriteJSON writes indented JSON.
func WriteJSON(path string, v any) error {
	b, err := marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ModuleSum returns the h1 sum recorded for module@version in a go.sum file.
func ModuleSum(goSum []byte, module, version string) (string, error) {
	prefix := module + " " + version + " "
	for _, line := range strings.Split(string(goSum), "\n") {
		if !strings.HasPrefix(line, prefix) || strings.Contains(line, "/go.mod") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.HasPrefix(fields[2], "h1:") {
			return fields[2], nil
		}
	}
	return "", fmt.Errorf("go.sum has no h1 sum for %s@%s", module, version)
}
