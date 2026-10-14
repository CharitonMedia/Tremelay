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
	escaped := url.QueryEscape(raw)
	encodedHex := hex.EncodeToString(secret)
	return []string{
		raw,
		jsonEscape(raw),
		escaped,
		lowerPercentHex(escaped),
		mixedPercentHex(escaped),
		encodedHex,
		strings.ToUpper(encodedHex),
		base64.StdEncoding.EncodeToString(secret),
		base64.RawStdEncoding.EncodeToString(secret),
		base64.URLEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
	}
}

func lowerPercentHex(s string) string {
	out := []byte(s)
	for i := 0; i+2 < len(out); i++ {
		if out[i] != '%' {
			continue
		}
		for j := i + 1; j <= i+2; j++ {
			if out[j] >= 'A' && out[j] <= 'F' {
				out[j] += 'a' - 'A'
			}
		}
		i += 2
	}
	return string(out)
}

func mixedPercentHex(s string) string {
	out := []byte(s)
	for i := 0; i+2 < len(out); i++ {
		if out[i] != '%' {
			continue
		}
		for j := i + 1; j <= i+2; j++ {
			if out[j] >= 'A' && out[j] <= 'F' {
				out[j] += 'a' - 'A'
				return string(out)
			}
		}
		i += 2
	}
	return string(out)
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
