package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

type gvcMessage struct {
	Config  *gvcConfig  `json:"config"`
	OSV     *struct{}   `json:"osv"`
	Finding *gvcFinding `json:"finding"`
}

type gvcConfig struct {
	DB             string     `json:"db"`
	DBLastModified *time.Time `json:"db_last_modified"`
	ScanLevel      string     `json:"scan_level"`
	ScanMode       string     `json:"scan_mode"`
	ScannerName    string     `json:"scanner_name"`
	ScannerVersion string     `json:"scanner_version"`
}

type gvcFinding struct {
	OSV   string     `json:"osv"`
	Trace []gvcFrame `json:"trace"`
}

type gvcFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

// Assess parses govulncheck JSON. Exit status 0 is not treated as a clean result.
// A called symbol at the default symbol scan blocks assurance. Module-level
// findings are counted and must stay visible; they are not deleted.
func Assess(raw []byte, exitStatus int) (Assessment, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var a Assessment
	a.ExitStatus = exitStatus
	seen := map[string]struct{}{}
	var cfg *gvcConfig
	for {
		var msg gvcMessage
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return Assessment{}, fmt.Errorf("govulncheck json: %w", err)
		}
		if msg.Config != nil {
			cfg = msg.Config
		}
		if msg.OSV != nil {
			a.OSVEntries++
		}
		if msg.Finding == nil {
			continue
		}
		f := msg.Finding
		if f.OSV == "" || len(f.Trace) == 0 {
			a.Blocked = true
			a.BlockReason = "govulncheck finding has no id or trace"
			continue
		}
		seen[f.OSV] = struct{}{}
		fr := f.Trace[0]
		switch {
		case fr.Function != "":
			a.Called++
		case fr.Package != "":
			a.Imported++
		case fr.Module != "":
			a.Required++
		default:
			a.Blocked = true
			a.BlockReason = "govulncheck finding trace has no module"
		}
	}
	if cfg == nil {
		return Assessment{}, fmt.Errorf("govulncheck json has no config message")
	}
	if cfg.ScanLevel != "" && cfg.ScanLevel != "symbol" {
		return Assessment{}, fmt.Errorf("govulncheck scan_level %s, want symbol", cfg.ScanLevel)
	}
	a.DatabaseEndpoint = cfg.DB
	if cfg.DB == "" {
		a.Blocked = true
		a.BlockReason = "govulncheck config has no database endpoint"
	}
	if cfg.DBLastModified != nil {
		a.DatabaseLastModified = cfg.DBLastModified.UTC().Format(time.RFC3339)
		a.DatabaseLastModifiedAvailable = true
	}
	for id := range seen {
		a.FindingIDs = append(a.FindingIDs, id)
	}
	sort.Strings(a.FindingIDs)
	if a.Called > 0 {
		a.Blocked = true
		a.BlockReason = fmt.Sprintf("symbol-level findings present (exit status %d is not a clean result)", exitStatus)
	}
	if exitStatus != 0 {
		a.Blocked = true
		if a.BlockReason == "" {
			a.BlockReason = fmt.Sprintf("govulncheck exit status %d", exitStatus)
		}
	}
	a.SymbolGatePass = !a.Blocked && a.Called == 0 && exitStatus == 0
	return a, nil
}

// ScanMetaFrom fills the evidence record from an assessment.
func ScanMetaFrom(scope, rawName string, cmd []string, id Identity, started, ended time.Time, stderr string, a Assessment) ScanMeta {
	ids := a.FindingIDs
	if ids == nil {
		ids = []string{}
	}
	return ScanMeta{
		Scope:                         scope,
		Command:                       cmd,
		ScannerModule:                 VulnModule,
		ScannerVersion:                VulnVersion,
		ScannerSum:                    VulnSum,
		StartedUTC:                    started.UTC().Format(time.RFC3339Nano),
		EndedUTC:                      ended.UTC().Format(time.RFC3339Nano),
		ExitStatus:                    a.ExitStatus,
		DatabaseEndpoint:              a.DatabaseEndpoint,
		DatabaseLastModified:          a.DatabaseLastModified,
		DatabaseLastModifiedAvailable: a.DatabaseLastModifiedAvailable,
		DatabaseSnapshotID:            nil,
		DatabaseNote:                  DBNote,
		SourceCommit:                  id.SourceCommit,
		SourceTree:                    id.SourceTree,
		ArtifactSHA256:                id.ArtifactSHA256,
		GoModSHA256:                   id.GoModSHA256,
		GoSumSHA256:                   id.GoSumSHA256,
		CalledFindings:                a.Called,
		ImportedFindings:              a.Imported,
		ModuleFindings:                a.Required,
		FindingIDs:                    ids,
		SymbolGatePass:                a.SymbolGatePass,
		ClaimsVulnerabilityAbsence:    false,
		Limits:                        ScanLimit,
		RawReport:                     rawName,
		Stderr:                        stderr,
	}
}
