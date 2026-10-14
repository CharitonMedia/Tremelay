package vault

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
)

// secretForms is the set of spellings a credential could take on an output
// surface. A leak assertion that only looked for the raw bytes would miss an
// encoded copy.
func secretForms(secret []byte) []string {
	raw := string(secret)
	return []string{
		raw,
		jsonEscape(raw),
		url.QueryEscape(raw),
		hex.EncodeToString(secret),
		base64.StdEncoding.EncodeToString(secret),
	}
}

func containsForm(s string, forms []string) bool {
	for _, form := range forms {
		if form != "" && strings.Contains(s, form) {
			return true
		}
	}
	return false
}

func jsonEscape(s string) string {
	quoted, err := json.Marshal(s)
	if err != nil || len(quoted) < 2 {
		return ""
	}
	return string(quoted[1 : len(quoted)-1])
}
