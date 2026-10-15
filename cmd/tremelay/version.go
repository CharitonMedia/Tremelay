package main

import (
	"fmt"
	"io"
	"runtime/debug"
	"strings"
)

// Injected by release-dry.sh when -buildvcs=false; otherwise unused.
var (
	versionOverride     string
	vcsRevisionOverride string
)

func cmdVersion(stdout io.Writer) int {
	if _, err := fmt.Fprintln(stdout, versionLine()); err != nil {
		return 1
	}
	return 0
}

func versionLine() string {
	ver, commit, modified := versionFromBuildInfo()
	line := "tremelay " + ver
	if commit != "" {
		line += " (commit " + commit
		if modified {
			line += ", modified"
		}
		line += ")"
	} else if modified {
		line += " (modified)"
	}
	return line
}

func versionFromBuildInfo() (ver string, commit string, modified bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return pickVersion("", versionOverride), shortRevision(vcsRevisionOverride), false
	}
	ver = pickVersion(info.Main.Version, versionOverride)
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = shortRevision(s.Value)
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if commit == "" {
		commit = shortRevision(vcsRevisionOverride)
	}
	return ver, commit, modified
}

func pickVersion(fromBuild string, override string) string {
	if fromBuild != "" && fromBuild != "(devel)" {
		return fromBuild
	}
	if override != "" {
		return override
	}
	if fromBuild != "" {
		return fromBuild
	}
	return "(devel)"
}

func shortRevision(rev string) string {
	rev = strings.TrimSpace(rev)
	if rev == "" {
		return ""
	}
	if len(rev) > 7 {
		return rev[:7]
	}
	return rev
}
