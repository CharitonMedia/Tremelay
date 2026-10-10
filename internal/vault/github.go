package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	githubAPIHost        = "api.github.com"
	githubAccept         = "application/vnd.github+json"
	githubAPIVersion     = "2026-03-10"
	githubUserAgent      = "tremelay"
	githubIssueMaxBody   = 256 << 10
	githubJSONDepth      = 16
	githubMaxIssueNumber = 999_999_999
	// ponytail: comment counts above this fail closed.
	// Upgrade path: raise the constant if a real issue exceeds it.
	githubMaxComments = 1_000_000
)

// GitHubIssueRequest is the agent-facing issue-state read.
// It names a credential and one repository issue. It has no header, body,
// URL, or secret field. Owner, Repository, and Number are canonical text.
type GitHubIssueRequest struct {
	CredentialID string
	Owner        string
	Repository   string
	Number       string
}

// GitHubIssueState is the approved issue summary.
// Other GitHub fields are not present. JSON encoding is the four approved names.
type GitHubIssueState struct {
	Number   int64  `json:"number"`
	State    string `json:"state"`
	Locked   bool   `json:"locked"`
	Comments int64  `json:"comments"`
}

// GitHubIssueResource is the exact grant resource for one issue-state read.
// The spelling is case-sensitive and is the same text the broker authorizes.
func GitHubIssueResource(owner, repository, number string) (string, error) {
	target, _, err := canonicalGitHubIssue(owner, repository, number)
	if err != nil {
		return "", err
	}
	return http.MethodGet + " " + target, nil
}

func (s *Session) githubIssueState(agentID string, req GitHubIssueRequest) (GitHubIssueState, error) {
	if err := s.begin(); err != nil {
		return GitHubIssueState{}, err
	}
	defer s.end()
	if s.agentExists(agentID) && !s.agentActive(agentID) {
		_, err := s.brokerDeny(s.destinationEvent(agentID, req.CredentialID, resultDeniedAgent, OpGitHubIssueState), http.MethodGet, ErrDeniedAgent)
		return GitHubIssueState{}, err
	}
	target, number, err := canonicalGitHubIssue(req.Owner, req.Repository, req.Number)
	if err != nil {
		_, err = s.brokerDeny(auditEvent{Result: resultDenied}, "", ErrInvalid)
		return GitHubIssueState{}, err
	}
	var st GitHubIssueState
	_, err = s.brokerExchange(agentID, brokerAttempt{
		credentialID: req.CredentialID,
		method:       http.MethodGet,
		target:       target,
		operation:    OpGitHubIssueState,
		prepare:      prepareGitHub,
		accept: func(body []byte) error {
			parsed, err := parseGitHubIssueState(body, req.Owner, req.Repository, number)
			if err != nil {
				return err
			}
			st = parsed
			return nil
		},
	})
	if err != nil {
		return GitHubIssueState{}, err
	}
	return st, nil
}

func prepareGitHub(r *http.Request) {
	r.Header.Set("Accept", githubAccept)
	r.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	r.Header.Set("User-Agent", githubUserAgent)
}

func canonicalGitHubIssue(owner, repository, number string) (string, int64, error) {
	n, ok := canonicalIssueNumber(number)
	if !ok || !githubOwner(owner) || !githubRepo(repository) {
		return "", 0, ErrInvalid
	}
	target := "https://" + githubAPIHost + "/repos/" + owner + "/" + repository + "/issues/" + number
	resource, host, _, class := classifyTarget(http.MethodGet, target)
	if class != targetOK || host != githubAPIHost || resource != http.MethodGet+" "+target {
		return "", 0, ErrInvalid
	}
	return target, n, nil
}

func githubOwner(s string) bool {
	if len(s) < 1 || len(s) > 39 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !githubAlnum(s[i]) && s[i] != '-' {
			return false
		}
	}
	return true
}

func githubRepo(s string) bool {
	if len(s) < 1 || len(s) > 100 || s[0] == '.' || s[len(s)-1] == '.' {
		return false
	}
	if len(s) >= 4 && strings.EqualFold(s[len(s)-4:], ".git") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !githubAlnum(c) && c != '.' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func githubAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func canonicalIssueNumber(s string) (int64, bool) {
	if s == "" || len(s) > 9 || s[0] == '0' {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if n < 1 || n > githubMaxIssueNumber {
		return 0, false
	}
	return n, true
}

// parseGitHubIssueState keeps the approved summary.
// url, repository_url, number, state, locked, and comments are required.
// A pull_request member means this is not an issue. Every other member is
// optional and is discarded, including title, body, user, and html_url.
// Duplicate top-level names fail. Identity fields are compared to the
// authorized owner, repository, and issue number and are not returned.
func parseGitHubIssueState(body []byte, owner, repository string, number int64) (GitHubIssueState, error) {
	if len(body) == 0 || len(body) > githubIssueMaxBody || !githubJSONDepthOK(body) {
		return GitHubIssueState{}, ErrBrokerUpstream
	}
	fields, err := githubObject(body)
	if err != nil {
		return GitHubIssueState{}, ErrBrokerUpstream
	}
	if _, ok := fields["pull_request"]; ok {
		return GitHubIssueState{}, ErrBrokerUpstream
	}
	wantURL := "https://" + githubAPIHost + "/repos/" + owner + "/" + repository + "/issues/" + strconv.FormatInt(number, 10)
	wantRepo := "https://" + githubAPIHost + "/repos/" + owner + "/" + repository
	if !githubStringIs(fields["url"], wantURL) || !githubStringIs(fields["repository_url"], wantRepo) {
		return GitHubIssueState{}, ErrBrokerUpstream
	}
	if string(fields["number"]) != strconv.FormatInt(number, 10) {
		return GitHubIssueState{}, ErrBrokerUpstream
	}
	state, ok := githubExactString(fields["state"])
	if !ok || (state != "open" && state != "closed") {
		return GitHubIssueState{}, ErrBrokerUpstream
	}
	locked, ok := githubExactBool(fields["locked"])
	if !ok {
		return GitHubIssueState{}, ErrBrokerUpstream
	}
	comments, ok := githubExactInt(fields["comments"], 0, githubMaxComments)
	if !ok {
		return GitHubIssueState{}, ErrBrokerUpstream
	}
	return GitHubIssueState{Number: number, State: state, Locked: locked, Comments: comments}, nil
}

func githubObject(body []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, ErrBrokerUpstream
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, ErrBrokerUpstream
		}
		key, ok := keyTok.(string)
		if !ok || key == "" {
			return nil, ErrBrokerUpstream
		}
		if _, exists := fields[key]; exists {
			return nil, ErrBrokerUpstream
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, ErrBrokerUpstream
		}
		fields[key] = append(json.RawMessage(nil), raw...)
	}
	tok, err = dec.Token()
	if err != nil || tok != json.Delim('}') {
		return nil, ErrBrokerUpstream
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrBrokerUpstream
	}
	return fields, nil
}

func githubStringIs(raw json.RawMessage, want string) bool {
	got, ok := githubExactString(raw)
	return ok && got == want
}

func githubExactString(raw json.RawMessage) (string, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	again, err := json.Marshal(s)
	if err != nil || !bytes.Equal(again, raw) {
		return "", false
	}
	return s, true
}

func githubExactBool(raw json.RawMessage) (bool, bool) {
	switch string(raw) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func githubExactInt(raw json.RawMessage, min, max int64) (int64, bool) {
	if len(raw) == 0 || raw[0] == '-' || raw[0] == '+' {
		return 0, false
	}
	if len(raw) > 1 && raw[0] == '0' {
		return 0, false
	}
	var n int64
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
		if n > max/10 {
			return 0, false
		}
		n = n*10 + int64(c-'0')
		if n > max {
			return 0, false
		}
	}
	if n < min {
		return 0, false
	}
	return n, true
}

// ponytail: reject documents nested deeper than githubJSONDepth before decode.
// Upgrade path: raise the cap if a supported issue document nests deeper.
func githubJSONDepthOK(body []byte) bool {
	depth := 0
	in := false
	esc := false
	for _, c := range body {
		if in {
			if esc {
				esc = false
				continue
			}
			if c == '\\' {
				esc = true
				continue
			}
			if c == '"' {
				in = false
			}
			continue
		}
		switch c {
		case '"':
			in = true
		case '{', '[':
			depth++
			if depth > githubJSONDepth {
				return false
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return true
}
