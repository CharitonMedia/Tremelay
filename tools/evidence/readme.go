package evidence

import (
	"fmt"
	"strings"
)

// READMEInput is the assurance summary stored beside the candidate.
type READMEInput struct {
	ID             Identity
	SourceFindings []string
	BinaryFindings []string
	MCPSDKInBinary bool
	MCPSDKVersion  string
}

// AssuranceREADME is the short evidence note. It does not claim a signature
// or the absence of vulnerabilities.
func AssuranceREADME(in READMEInput) string {
	mcp := "The MCP Go SDK was not in this binary's build information. If the module remains in the source graph, it is only in the separately labeled source inventory."
	if in.MCPSDKInBinary {
		mcp = fmt.Sprintf("Build information records %s %s, so the binary SBOM includes it. That is module presence, not proof that every function of the module remains linked or reachable. The in-memory M10b reference is not a network deployment.", MCPSDKPath, in.MCPSDKVersion)
	}
	return fmt.Sprintf(`# Tremelay unsigned Linux CLI candidate

This directory is build evidence for one unsigned linux/amd64 prerelease candidate of the tremelay human CLI. It is not a published release, a signed binary, or an attestation. SHA256SUMS detects a changed or missing file. It does not authenticate provenance.

Source commit: %s
Source tree: %s
Artifact SHA-256: %s
Go: %s
Target: %s GOAMD64=%s CGO_ENABLED=%s

The executable was built with -buildvcs=false, so it does not carry VCS metadata. The commit and tree above are the authoritative source identity. Tremelay is pre-release security software and should not yet be trusted with production credentials. M9, M10, and M11 remain open. This candidate does not complete them.

Two builds used separate absolute workspaces and separate compilation caches on one builder. A shared module download cache may have been reused and is named in the two-build receipt. Matching executable bytes support only this toolchain, target, flag set, and observed builder. They do not prove independent-builder or cross-platform reproducibility.

The CycloneDX 1.6 SBOM was produced by pinned cyclonedx-gomod bin from the built executable and validated against the pinned official schema. It is a module-level inventory. It does not prove that every module function remains linked or reachable. The source inventory file is the go.mod graph plus pinned build tools. It is not the CLI binary inventory.

%s

Vulnerability reports are dated evidence for this candidate and source, not a claim that the candidate has no vulnerabilities. govulncheck JSON can exit 0 when findings exist; the gate reads the findings. Symbol-level results do not prove a function is absent or that a finding is exploitable. The database time is the endpoint's reported update time, not an immutable snapshot.

Source scan finding IDs: %s
Binary scan finding IDs: %s
`, in.ID.SourceCommit, in.ID.SourceTree, in.ID.ArtifactSHA256, GoVersion, Target, TargetGOAMD64, TargetCGO, mcp, idList(in.SourceFindings), idList(in.BinaryFindings))
}

func idList(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}
