package evidence

// Identity is the candidate a report describes.
type Identity struct {
	SourceCommit   string
	SourceTree     string
	ArtifactSHA256 string
	GoModSHA256    string
	GoSumSHA256    string
}

// ModID is one module from Go build information.
type ModID struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum,omitempty"`
	Replace *ModID `json:"replace,omitempty"`
}

// BuildInfoDoc is the independent read of the candidate's Go build information.
type BuildInfoDoc struct {
	SourceCommit   string            `json:"source_commit"`
	SourceTree     string            `json:"source_tree"`
	ArtifactSHA256 string            `json:"artifact_sha256"`
	GoModSHA256    string            `json:"go_mod_sha256"`
	GoSumSHA256    string            `json:"go_sum_sha256"`
	GoVersion      string            `json:"go_version"`
	Path           string            `json:"path"`
	Main           ModID             `json:"main"`
	Deps           []ModID           `json:"deps"`
	Settings       map[string]string `json:"settings"`
	Note           string            `json:"note"`
}

// BuildSide is one of the two clean builds.
type BuildSide struct {
	Workspace string `json:"workspace"`
	Output    string `json:"output"`
	Cache     string `json:"cache"`
	SHA256    string `json:"sha256"`
}

// TwoBuildReceipt records the byte comparison. Only the executable must match.
type TwoBuildReceipt struct {
	SourceCommit        string      `json:"source_commit"`
	SourceTree          string      `json:"source_tree"`
	ArtifactSHA256      string      `json:"artifact_sha256"`
	GoModSHA256         string      `json:"go_mod_sha256"`
	GoSumSHA256         string      `json:"go_sum_sha256"`
	GoVersion           string      `json:"go_version"`
	ByteIdentical       bool        `json:"byte_identical"`
	Builds              []BuildSide `json:"builds"`
	ModuleCache         string      `json:"module_cache"`
	ModuleCacheNote     string      `json:"module_cache_note"`
	ModuleCacheVerified string      `json:"module_cache_verified"`
	Scope               string      `json:"scope"`
}

// BuildInputs is the recorded recipe. It is an allowlist, not an environment dump.
type BuildInputs struct {
	SourceCommit    string            `json:"source_commit"`
	SourceTree      string            `json:"source_tree"`
	ArtifactSHA256  string            `json:"artifact_sha256"`
	GoModSHA256     string            `json:"go_mod_sha256"`
	GoSumSHA256     string            `json:"go_sum_sha256"`
	GoModUnchanged  bool              `json:"go_mod_unchanged"`
	GoSumUnchanged  bool              `json:"go_sum_unchanged"`
	GoVersion       string            `json:"go_version"`
	Toolchain       string            `json:"toolchain"`
	Target          string            `json:"target"`
	GOAMD64         string            `json:"goamd64"`
	CGOEnabled      string            `json:"cgo_enabled"`
	BuildCommand    []string          `json:"build_command"`
	BuildEnv        map[string]string `json:"build_env"`
	GoEnv           map[string]string `json:"go_env"`
	GoVersionOutput string            `json:"go_version_output"`
	ModuleCache     string            `json:"module_cache"`
	Builder         map[string]string `json:"builder"`
	Tools           map[string]string `json:"tools"`
	Schema          map[string]string `json:"schema"`
	CIActionPins    map[string]string `json:"ci_action_pins"`
	VCSNote         string            `json:"vcs_note"`
	RecipeNote      string            `json:"recipe_note"`
}

// SourceInventory is the module graph plus build tools. It is not the binary SBOM.
type SourceInventory struct {
	Inventory           string `json:"inventory"`
	NotBinaryInventory  bool   `json:"not_binary_inventory"`
	SourceCommit        string `json:"source_commit"`
	SourceTree          string `json:"source_tree"`
	ArtifactSHA256      string `json:"artifact_sha256"`
	GoModSHA256         string `json:"go_mod_sha256"`
	GoSumSHA256         string `json:"go_sum_sha256"`
	MainModuleGraph     []Mod  `json:"main_module_graph"`
	BuildTools          []Mod  `json:"build_tools"`
	MCPSDKInBinary      bool   `json:"mcp_sdk_in_binary_buildinfo"`
	MCPSDKBinaryVersion string `json:"mcp_sdk_binary_version,omitempty"`
	MCPSDKInSourceGraph bool   `json:"mcp_sdk_in_source_graph"`
	MCPSDKSourceVersion string `json:"mcp_sdk_source_version,omitempty"`
	Note                string `json:"note"`
}

// Mod is one entry from `go list -m -json`.
type Mod struct {
	Path    string `json:"Path"`
	Version string `json:"Version,omitempty"`
	Sum     string `json:"Sum,omitempty"`
}

// ValidationReport is the schema validation result for one candidate.
type ValidationReport struct {
	SourceCommit     string            `json:"source_commit"`
	SourceTree       string            `json:"source_tree"`
	ArtifactSHA256   string            `json:"artifact_sha256"`
	SchemaName       string            `json:"schema_name"`
	SchemaTag        string            `json:"schema_tag"`
	SchemaCommit     string            `json:"schema_commit"`
	SchemaFiles      map[string]string `json:"schema_files"`
	ValidatorModule  string            `json:"validator_module"`
	ValidatorVersion string            `json:"validator_version"`
	ValidatorSum     string            `json:"validator_sum"`
	GeneratorModule  string            `json:"generator_module"`
	GeneratorVersion string            `json:"generator_version"`
	GeneratorSum     string            `json:"generator_sum"`
	GeneratorCommand string            `json:"generator_command"`
	Valid            bool              `json:"valid"`
	SpecVersion      string            `json:"spec_version"`
}

// ScanMeta is the findings-aware record of one govulncheck invocation.
type ScanMeta struct {
	Scope                         string   `json:"scope"`
	Command                       []string `json:"command"`
	ScannerModule                 string   `json:"scanner_module"`
	ScannerVersion                string   `json:"scanner_version"`
	ScannerSum                    string   `json:"scanner_sum"`
	StartedUTC                    string   `json:"started_utc"`
	EndedUTC                      string   `json:"ended_utc"`
	ExitStatus                    int      `json:"exit_status"`
	DatabaseEndpoint              string   `json:"database_endpoint"`
	DatabaseLastModified          string   `json:"database_last_modified,omitempty"`
	DatabaseLastModifiedAvailable bool     `json:"database_last_modified_available"`
	DatabaseSnapshotID            any      `json:"database_snapshot_id"`
	DatabaseNote                  string   `json:"database_note"`
	SourceCommit                  string   `json:"source_commit"`
	SourceTree                    string   `json:"source_tree"`
	ArtifactSHA256                string   `json:"artifact_sha256"`
	GoModSHA256                   string   `json:"go_mod_sha256"`
	GoSumSHA256                   string   `json:"go_sum_sha256"`
	CalledFindings                int      `json:"called_findings"`
	ImportedFindings              int      `json:"imported_findings"`
	ModuleFindings                int      `json:"module_findings"`
	FindingIDs                    []string `json:"finding_ids"`
	SymbolGatePass                bool     `json:"symbol_gate_pass"`
	ClaimsVulnerabilityAbsence    bool     `json:"claims_vulnerability_absence"`
	Limits                        string   `json:"limits"`
	RawReport                     string   `json:"raw_report"`
	Stderr                        string   `json:"stderr,omitempty"`
}

// Assessment is the parse of a govulncheck JSON stream.
type Assessment struct {
	ExitStatus                    int
	DatabaseEndpoint              string
	DatabaseLastModified          string
	DatabaseLastModifiedAvailable bool
	Called                        int
	Imported                      int
	Required                      int
	FindingIDs                    []string
	OSVEntries                    int
	SymbolGatePass                bool
	Blocked                       bool
	BlockReason                   string
	ScanMode                      string
	ScannerName                   string
	ScannerVersion                string
}
