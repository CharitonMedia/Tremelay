package evidence

// Pinned build/evidence inputs. These are not application dependencies.
// The application module already declares go 1.26.9. GOTOOLCHAIN=go1.26.9
// selects that toolchain and refuses a newer one. A toolchain line in go.mod
// is not used: go 1.26 go mod tidy deletes it, and -mod=readonly then fails.
const (
	GoVersion       = "go1.26.9"
	GoToolchain     = "go1.26.9"
	TargetGOOS      = "linux"
	TargetGOARCH    = "amd64"
	TargetGOAMD64   = "v1"
	TargetCGO       = "0"
	Target          = "linux/amd64"
	MCPSDKPath      = "github.com/modelcontextprotocol/go-sdk"
	SchemaCommit    = "e833d732337dd33aceb45ff1991f896796f1e5e7"
	SchemaTag       = "1.6.2"
	SchemaBase      = "http://cyclonedx.org/schema/"
	CycloneDXModule = "github.com/CycloneDX/cyclonedx-gomod"
	CycloneDXVer    = "v1.12.0"
	CycloneDXSum    = "h1:OuFUYNhnjpju7RNArOVPPchFPWNobGfhrHODDPKcgZs="
	VulnModule      = "golang.org/x/vuln"
	VulnCommand     = "golang.org/x/vuln/cmd/govulncheck"
	VulnVersion     = "v1.8.0"
	VulnSum         = "h1:clG4qBU6zH5VKjti8n5j8BBuYzoSha392xXMkXS351U="
	ValidatorModule = "github.com/santhosh-tekuri/jsonschema/v6"
	ValidatorVer    = "v6.0.3"
	ValidatorSum    = "h1:1EYB5IzjZawrrnELUi78f9fPu57HuXjmddZPjrls/28="
	CheckoutAction  = "actions/checkout"
	CheckoutSHA     = "11d5960a326750d5838078e36cf38b85af677262" // v4.4.0
	SetupGoAction   = "actions/setup-go"
	SetupGoSHA      = "40f1582b2485089dde7abd97c1529aa768e1baff" // v5.6.0
	DBNote          = "db_last_modified is the database endpoint's reported update time, not an immutable content snapshot. No snapshot identifier is invented when the tool does not report one."
	ReachNote       = "Module metadata does not prove that every module function remains linked or reachable."
	ScanLimit       = "Source and binary scans are different evidence. Symbol-level govulncheck uses static analysis or a binary symbol table and can miss or over-approximate affected code. A clean symbol gate does not prove absence of vulnerabilities or exploitability. JSON and SARIF modes exit 0 even when findings exist; this gate reads the findings. Module-level findings are preserved and block any claim of vulnerability absence."
)

// SchemaSHA256 is the pinned CycloneDX 1.6.2 schema set.
var SchemaSHA256 = map[string]string{
	"bom-1.6.schema.json":  "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d",
	"jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
	"spdx.schema.json":     "c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6",
}

// EvidenceFiles are the reviewable artifacts. SHA256SUMS lists these names
// and is not itself listed.
var EvidenceFiles = []string{
	"README.md",
	"binary-buildinfo.json",
	"build-inputs.json",
	"govulncheck-binary-meta.json",
	"govulncheck-binary.json",
	"govulncheck-source-meta.json",
	"govulncheck-source.json",
	"sbom-validation.json",
	"sbom.cdx.json",
	"source-inventory.json",
	"tremelay",
	"two-build-receipt.json",
}
