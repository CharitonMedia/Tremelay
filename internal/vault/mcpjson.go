package vault

import (
	"unicode/utf16"
	"unicode/utf8"
)

// jv is one JSON value from a raw MCP frame. Objects keep every key so a
// duplicate, including an escaped alias of an earlier key, fails closed.
// Arrays are rejected: this profile has no batch and no array argument.
type jv struct {
	kind   byte // 'o' object, 's' string, 'n' number, 'b' bool, 'z' null
	s      string
	raw    string
	i      int64
	okInt  bool
	b      bool
	obj    []jkv
	rawBeg int
	rawEnd int
}

type jkv struct {
	k string
	v jv
}

func (v jv) field(name string) (jv, bool) {
	for _, kv := range v.obj {
		if kv.k == name {
			return kv.v, true
		}
	}
	return jv{}, false
}

func (v jv) has(name string) bool {
	_, ok := v.field(name)
	return ok
}

const (
	mcpJSONDepth = 8
	mcpJSONKeys  = 32
)

func parseJSONValue(raw []byte) (jv, error) {
	if !utf8.Valid(raw) || len(raw) == 0 {
		return jv{}, errMCPSyntax
	}
	v, i, err := parseJV(raw, skipWS(raw, 0), 0)
	if err != nil {
		return jv{}, err
	}
	if skipWS(raw, i) != len(raw) {
		return jv{}, errMCPSyntax
	}
	return v, nil
}

func parseJV(raw []byte, i, depth int) (jv, int, error) {
	if i >= len(raw) || depth > mcpJSONDepth {
		return jv{}, i, errMCPSyntax
	}
	switch raw[i] {
	case '{':
		return parseObject(raw, i, depth)
	case '"':
		s, j, err := parseJSONString(raw, i)
		if err != nil {
			return jv{}, i, err
		}
		return jv{kind: 's', s: s, rawBeg: i, rawEnd: j}, j, nil
	case 't':
		if !matchLit(raw, i, "true") {
			return jv{}, i, errMCPSyntax
		}
		return jv{kind: 'b', b: true, rawBeg: i, rawEnd: i + 4}, i + 4, nil
	case 'f':
		if !matchLit(raw, i, "false") {
			return jv{}, i, errMCPSyntax
		}
		return jv{kind: 'b', b: false, rawBeg: i, rawEnd: i + 5}, i + 5, nil
	case 'n':
		if !matchLit(raw, i, "null") {
			return jv{}, i, errMCPSyntax
		}
		return jv{kind: 'z', rawBeg: i, rawEnd: i + 4}, i + 4, nil
	case '-':
		return jv{}, i, errMCPSyntax
	default:
		if raw[i] >= '0' && raw[i] <= '9' {
			return parseNumber(raw, i)
		}
		return jv{}, i, errMCPSyntax
	}
}

func parseObject(raw []byte, i, depth int) (jv, int, error) {
	if depth == mcpJSONDepth {
		return jv{}, i, errMCPSyntax
	}
	start := i
	i++
	i = skipWS(raw, i)
	out := jv{kind: 'o', rawBeg: start}
	if i < len(raw) && raw[i] == '}' {
		out.rawEnd = i + 1
		return out, i + 1, nil
	}
	seen := make(map[string]struct{})
	for {
		if i >= len(raw) || raw[i] != '"' {
			return jv{}, i, errMCPSyntax
		}
		key, j, err := parseJSONString(raw, i)
		if err != nil {
			return jv{}, i, err
		}
		if _, dup := seen[key]; dup || len(seen) >= mcpJSONKeys {
			return jv{}, i, errMCPSyntax
		}
		seen[key] = struct{}{}
		i = skipWS(raw, j)
		if i >= len(raw) || raw[i] != ':' {
			return jv{}, i, errMCPSyntax
		}
		val, k, err := parseJV(raw, skipWS(raw, i+1), depth+1)
		if err != nil {
			return jv{}, i, err
		}
		out.obj = append(out.obj, jkv{k: key, v: val})
		i = skipWS(raw, k)
		if i >= len(raw) {
			return jv{}, i, errMCPSyntax
		}
		if raw[i] == '}' {
			out.rawEnd = i + 1
			return out, i + 1, nil
		}
		if raw[i] != ',' {
			return jv{}, i, errMCPSyntax
		}
		i = skipWS(raw, i+1)
	}
}

func parseNumber(raw []byte, i int) (jv, int, error) {
	start := i
	if raw[i] == '0' {
		i++
	} else {
		for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
			i++
		}
	}
	if i < len(raw) && (raw[i] == '.' || raw[i] == 'e' || raw[i] == 'E') {
		return jv{}, start, errMCPSyntax
	}
	tok := string(raw[start:i])
	n, ok := parseI64(tok)
	return jv{kind: 'n', raw: tok, i: n, okInt: ok, rawBeg: start, rawEnd: i}, i, nil
}

func parseI64(tok string) (int64, bool) {
	if tok == "" || (len(tok) > 1 && tok[0] == '0') {
		return 0, false
	}
	var n int64
	for _, c := range tok {
		if c < '0' || c > '9' {
			return 0, false
		}
		d := int64(c - '0')
		if n > (1<<63-1)/10 || (n == (1<<63-1)/10 && d > (1<<63-1)%10) {
			return 0, false
		}
		n = n*10 + d
	}
	return n, true
}

func parseJSONString(raw []byte, i int) (string, int, error) {
	if i >= len(raw) || raw[i] != '"' {
		return "", i, errMCPSyntax
	}
	i++
	var b []byte
	for i < len(raw) {
		c := raw[i]
		if c == '"' {
			if !utf8.Valid(b) {
				return "", i, errMCPSyntax
			}
			return string(b), i + 1, nil
		}
		if c == '\\' {
			if i+1 >= len(raw) {
				return "", i, errMCPSyntax
			}
			switch raw[i+1] {
			case '"', '\\', '/':
				b = append(b, raw[i+1])
				i += 2
			case 'b':
				b = append(b, '\b')
				i += 2
			case 'f':
				b = append(b, '\f')
				i += 2
			case 'n':
				b = append(b, '\n')
				i += 2
			case 'r':
				b = append(b, '\r')
				i += 2
			case 't':
				b = append(b, '\t')
				i += 2
			case 'u':
				r, j, err := parseUEscape(raw, i)
				if err != nil {
					return "", i, err
				}
				b = utf8.AppendRune(b, r)
				i = j
			default:
				return "", i, errMCPSyntax
			}
			continue
		}
		if c < 0x20 {
			return "", i, errMCPSyntax
		}
		b = append(b, c)
		i++
	}
	return "", i, errMCPSyntax
}

func parseUEscape(raw []byte, i int) (rune, int, error) {
	r, j, err := hex4(raw, i)
	if err != nil {
		return 0, i, err
	}
	if r < 0xD800 || r > 0xDFFF {
		if r == 0 {
			return 0, i, errMCPSyntax
		}
		return r, j, nil
	}
	if r > 0xDBFF || j+1 >= len(raw) || raw[j] != '\\' || raw[j+1] != 'u' {
		return 0, i, errMCPSyntax
	}
	lo, k, err := hex4(raw, j)
	if err != nil || lo < 0xDC00 || lo > 0xDFFF {
		return 0, i, errMCPSyntax
	}
	return utf16.DecodeRune(r, lo), k, nil
}

func hex4(raw []byte, i int) (rune, int, error) {
	if i+6 > len(raw) || raw[i] != '\\' || raw[i+1] != 'u' {
		return 0, i, errMCPSyntax
	}
	var r rune
	for _, c := range raw[i+2 : i+6] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r += rune(c - '0')
		case c >= 'a' && c <= 'f':
			r += rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r += rune(c-'A') + 10
		default:
			return 0, i, errMCPSyntax
		}
	}
	return r, i + 6, nil
}

func matchLit(raw []byte, i int, lit string) bool {
	return i+len(lit) <= len(raw) && string(raw[i:i+len(lit)]) == lit
}

func skipWS(raw []byte, i int) int {
	for i < len(raw) {
		switch raw[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}
