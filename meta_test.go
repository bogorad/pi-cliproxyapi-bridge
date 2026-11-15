package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Fake secrets. The tests assert that none of them reach the document, an
// error, or a log line.
const (
	fakeManagementKey = "mgmt-fake-key-7d1c"
	fakeDCAToken      = "dca:fake-device-token-AAAA1111"
	fakeDCAToken2     = "dca:fake-device-token-BBBB2222"
	fakeMintedKey     = "sk-meta-fake-minted-key-9f3e"
	fakeUserEmail     = "fake.person@example.com"
	fakeUserFullName  = "Fakey McFakeface"
)

// metaSuccessBody mirrors the muse-code/key reply: usage plus the minted key
// and the user's identity, which must never be echoed.
const metaSuccessBody = `{
  "api_key": "` + fakeMintedKey + `",
  "user_email": "` + fakeUserEmail + `",
  "user_full_name": "` + fakeUserFullName + `",
  "subs_tier_name": "Muse Pro",
  "is_subs_active": true,
  "subs_usage": {
    "window": {"used_percent": 37.5, "resets_at": 1763251200, "window_duration_mins": 300},
    "weekly": {"used_percent": "80", "resets_at": 1763600000}
  }
}`

type metaUpstream struct {
	status int
	body   string
}

// fakeManagement is a CLIProxyAPI management API with the three routes the
// Meta reader uses. It records every api-call it receives.
type fakeManagement struct {
	t        *testing.T
	files    []map[string]any
	authFile map[string]string       // file name -> downloaded content
	upstream map[string]metaUpstream // dca token -> muse-code/key reply

	mu        sync.Mutex
	downloads []string
	calls     []apiCallRequest
}

func (f *fakeManagement) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+fakeManagementKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v0/management/auth-files":
		_ = json.NewEncoder(w).Encode(map[string]any{"files": f.files})
	case r.Method == http.MethodGet && r.URL.Path == "/v0/management/auth-files/download":
		name := r.URL.Query().Get("name")
		f.mu.Lock()
		f.downloads = append(f.downloads, name)
		f.mu.Unlock()
		content, ok := f.authFile[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"file not found"}`)
			return
		}
		_, _ = io.WriteString(w, content)
	case r.Method == http.MethodPost && r.URL.Path == "/v0/management/api-call":
		var req apiCallRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			f.t.Errorf("api-call body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, req)
		f.mu.Unlock()
		token := strings.TrimPrefix(req.Header["Authorization"], "Bearer ")
		reply, ok := f.upstream[token]
		if !ok {
			reply = metaUpstream{status: http.StatusUnauthorized, body: `{"error":"unknown token"}`}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status_code": reply.status,
			"header":      map[string][]string{"Content-Type": {"application/json"}},
			"body":        reply.body,
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func metaAuthFileJSON(token string) string {
	raw, _ := json.Marshal(map[string]any{
		"type":       "meta",
		"email":      fakeUserEmail,
		"dca_token":  token,
		"api_key":    fakeMintedKey,
		"expires_at": "2026-12-01T00:00:00Z",
	})
	return string(raw)
}

func metaFileEntry(index, name string) map[string]any {
	return map[string]any{
		"auth_index": index,
		"name":       name,
		"provider":   "meta",
		"type":       "meta",
		"email":      fakeUserEmail,
		"status":     "active",
	}
}

// newFakeManagement starts the fake and points a plugin config at it.
func newFakeManagement(t *testing.T, f *fakeManagement) pluginConfig {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	t.Setenv("PI_BRIDGE_TEST_MGMT_KEY", fakeManagementKey)
	cfg := defaultConfig()
	cfg.advanced.ManagementURL = srv.URL + "/v0/management"
	cfg.advanced.ManagementKeyEnv = "PI_BRIDGE_TEST_MGMT_KEY"
	return cfg
}

// captureLogs collects anything written through the standard logger while the
// test runs.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// assertNoSecrets fails when any fake secret appears in the rendered text.
func assertNoSecrets(t *testing.T, where, text string) {
	t.Helper()
	for _, secret := range []string{fakeDCAToken, fakeDCAToken2, "fake-device-token", fakeMintedKey, fakeUserFullName, fakeManagementKey} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s leaks %q: %s", where, secret, text)
		}
	}
}

func singleMetaAccount(t *testing.T, f *fakeManagement) usageAccount {
	t.Helper()
	logs := captureLogs(t)
	cfg := newFakeManagement(t, f)
	doc, err := buildUsage(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildUsage: %v", err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertNoSecrets(t, "usage document", string(encoded))
	assertNoSecrets(t, "logs", logs.String())
	if len(doc.Accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(doc.Accounts))
	}
	for _, p := range doc.Unsupported {
		if p == "meta" {
			t.Fatal("meta must not be listed as unsupported")
		}
	}
	return doc.Accounts[0]
}

func metaGroupsByID(groups []quotaGroup) map[string]quotaGroup {
	out := map[string]quotaGroup{}
	for _, g := range groups {
		out[g.ID] = g
	}
	return out
}

// The full chain: list, download the account's own file, then one api-call
// that carries the real device token and never the $TOKEN$ placeholder.
func TestMetaQuotaChainAndMapping(t *testing.T) {
	f := &fakeManagement{
		files:    []map[string]any{metaFileEntry("idx-1", "meta-one.json")},
		authFile: map[string]string{"meta-one.json": metaAuthFileJSON(fakeDCAToken)},
		upstream: map[string]metaUpstream{fakeDCAToken: {http.StatusOK, metaSuccessBody}},
	}
	account := singleMetaAccount(t, f)

	if len(f.downloads) != 1 || f.downloads[0] != "meta-one.json" {
		t.Fatalf("downloads = %v", f.downloads)
	}
	if len(f.calls) != 1 {
		t.Fatalf("api-calls = %d, want 1", len(f.calls))
	}
	call := f.calls[0]
	if call.AuthIndex != "idx-1" || call.Method != http.MethodPost || call.URL != metaQuotaURL || call.Data != "{}" {
		t.Fatalf("api-call = %+v", call)
	}
	if got := call.Header["Authorization"]; got != "Bearer "+fakeDCAToken {
		t.Fatal("Authorization header does not carry the dca token")
	}
	for name, value := range call.Header {
		if strings.Contains(value, "$TOKEN$") {
			t.Fatalf("header %s uses $TOKEN$", name)
		}
	}
	if call.Header["x-api-version"] != "1.0.0" || call.Header["Accept"] != "application/json" || call.Header["Content-Type"] != "application/json" {
		t.Fatalf("headers = %v", call.Header)
	}

	if !account.Supported || account.Error != "" {
		t.Fatalf("account = %+v", account)
	}
	groups := metaGroupsByID(account.Groups)
	if len(groups) != 2 {
		t.Fatalf("groups = %+v", account.Groups)
	}
	window := groups["usage-window"]
	if window.Label != "5h Window" || math.Abs(window.RemainingFraction-0.625) > 1e-9 || window.ResetTime != "2025-11-16T00:00:00Z" {
		t.Fatalf("usage window = %+v", window)
	}
	weekly := groups["seven-day"]
	if weekly.Label != "7d Weekly" || math.Abs(weekly.RemainingFraction-0.2) > 1e-9 || weekly.ResetTime != "2025-11-20T00:53:20Z" {
		t.Fatalf("weekly = %+v", weekly)
	}
	if len(weekly.Models) != 1 || weekly.Models[0].RemainingFraction != weekly.RemainingFraction {
		t.Fatalf("weekly models entry not mirrored: %+v", weekly.Models)
	}
}

// Operator decision: a valid reply without subs_usage reports both windows as
// 0, with no reset time.
func TestMetaMissingSubsUsageReportsZero(t *testing.T) {
	f := &fakeManagement{
		files:    []map[string]any{metaFileEntry("idx-1", "meta-one.json")},
		authFile: map[string]string{"meta-one.json": metaAuthFileJSON(fakeDCAToken)},
		upstream: map[string]metaUpstream{fakeDCAToken: {http.StatusOK,
			`{"api_key":"` + fakeMintedKey + `","user_full_name":"` + fakeUserFullName + `"}`}},
	}
	account := singleMetaAccount(t, f)
	if account.Error != "" {
		t.Fatalf("error = %q", account.Error)
	}
	groups := metaGroupsByID(account.Groups)
	if len(groups) != 2 {
		t.Fatalf("groups = %+v", account.Groups)
	}
	for _, id := range []string{"usage-window", "seven-day"} {
		if groups[id].RemainingFraction != 0 || groups[id].ResetTime != "" {
			t.Fatalf("%s = %+v", id, groups[id])
		}
	}
	if groups["usage-window"].Label != "Usage Window" || groups["seven-day"].Label != "7d Weekly" {
		t.Fatalf("labels = %q, %q", groups["usage-window"].Label, groups["seven-day"].Label)
	}
}

// A missing or null window reports 0; the window that is present keeps its
// real value, and a known reset or duration is kept.
func TestMetaMissingWindowReportsZero(t *testing.T) {
	for _, body := range []string{
		`{"subs_usage":{"weekly":{"used_percent":12,"resets_at":1763600000}}}`,
		`{"subs_usage":{"weekly":{"used_percent":12,"resets_at":1763600000},"window":{"used_percent":null,"window_duration_mins":300,"resets_at":1763251200}}}`,
	} {
		groups, err := parseMetaQuota(body)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got := metaGroupsByID(groups)
		if len(groups) != 2 || groups[0].ID != "usage-window" || groups[1].ID != "seven-day" {
			t.Fatalf("groups = %+v", groups)
		}
		if math.Abs(got["seven-day"].RemainingFraction-0.88) > 1e-9 {
			t.Fatalf("weekly = %+v", got["seven-day"])
		}
		if got["usage-window"].RemainingFraction != 0 {
			t.Fatalf("usage window = %+v", got["usage-window"])
		}
	}
	groups, _ := parseMetaQuota(`{"subs_usage":{"window":{"used_percent":null,"window_duration_mins":300,"resets_at":1763251200}}}`)
	got := metaGroupsByID(groups)
	if got["usage-window"].Label != "5h Window" || got["usage-window"].ResetTime != "2025-11-16T00:00:00Z" {
		t.Fatalf("known duration or reset lost: %+v", got["usage-window"])
	}
	if got["seven-day"].RemainingFraction != 0 || got["seven-day"].ResetTime != "" {
		t.Fatalf("missing weekly = %+v", got["seven-day"])
	}
}

func TestMetaUsedPercentIsClamped(t *testing.T) {
	groups, err := parseMetaQuota(`{"subs_usage":{"window":{"used_percent":140},"weekly":{"used_percent":-5}}}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := metaGroupsByID(groups)
	if got["usage-window"].RemainingFraction != 0 || got["seven-day"].RemainingFraction != 1 {
		t.Fatalf("groups = %+v", groups)
	}
	if got["usage-window"].Label != "Usage Window" || got["usage-window"].ResetTime != "" {
		t.Fatalf("window without duration or reset = %+v", got["usage-window"])
	}
}

func TestMeta429ReportsExhausted(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		wantReset string
	}{
		{"with resets_at", `{"error":{"type":"rate_limit","code":"usage_exhausted","resets_at":1763251200,"api_key":"` + fakeMintedKey + `"}}`, "2025-11-16T00:00:00Z"},
		{"without resets_at", `{"error":{"type":"rate_limit","message":"for ` + fakeUserFullName + `"}}`, ""},
		{"not json", `rate limited ` + fakeDCAToken, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeManagement{
				files:    []map[string]any{metaFileEntry("idx-1", "meta-one.json")},
				authFile: map[string]string{"meta-one.json": metaAuthFileJSON(fakeDCAToken)},
				upstream: map[string]metaUpstream{fakeDCAToken: {http.StatusTooManyRequests, tc.body}},
			}
			account := singleMetaAccount(t, f)
			if account.Error != "" {
				t.Fatalf("error = %q", account.Error)
			}
			groups := metaGroupsByID(account.Groups)
			if len(groups) != 2 {
				t.Fatalf("groups = %+v", account.Groups)
			}
			for _, id := range []string{"usage-window", "seven-day"} {
				if groups[id].RemainingFraction != 0 || groups[id].ResetTime != tc.wantReset {
					t.Fatalf("%s = %+v", id, groups[id])
				}
			}
		})
	}
}

// Other refusals report the status only. The 401 body here echoes every
// secret, as a careless upstream might.
func TestMetaRefusalReportsStatusOnly(t *testing.T) {
	leaky := `{"error":"bad token ` + fakeDCAToken + `","api_key":"` + fakeMintedKey + `","user_full_name":"` + fakeUserFullName + `"}`
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		f := &fakeManagement{
			files:    []map[string]any{metaFileEntry("idx-1", "meta-one.json")},
			authFile: map[string]string{"meta-one.json": metaAuthFileJSON(fakeDCAToken)},
			upstream: map[string]metaUpstream{fakeDCAToken: {status, leaky}},
		}
		account := singleMetaAccount(t, f)
		if account.Error != providerFailure(status).Error() || len(account.Groups) != 0 {
			t.Fatalf("status %d: account = %+v", status, account)
		}
	}
}

// A file without a device token must never fall back to another credential
// field, and must not reach the upstream at all.
func TestMetaRejectsNonDCAToken(t *testing.T) {
	for _, content := range []string{
		metaAuthFileJSON(fakeMintedKey),
		metaAuthFileJSON(""),
		metaAuthFileJSON("dca:"),
		metaAuthFileJSON("dca:has space"),
		`{"type":"meta","api_key":"` + fakeMintedKey + `"}`,
		`{"dca_token": 42}`,
		`[]`,
		`not json ` + fakeDCAToken,
	} {
		f := &fakeManagement{
			files:    []map[string]any{metaFileEntry("idx-1", "meta-one.json")},
			authFile: map[string]string{"meta-one.json": content},
		}
		account := singleMetaAccount(t, f)
		if account.Error != errMetaNoDCAToken.Error() && account.Error != errMetaInvalidFile.Error() {
			t.Fatalf("content %d bytes: error = %q", len(content), account.Error)
		}
		if len(f.calls) != 0 {
			t.Fatal("upstream was called without a valid dca token")
		}
	}
}

func TestMetaDownloadFailureAndMissingFile(t *testing.T) {
	runtimeOnly := metaFileEntry("idx-2", "meta-runtime")
	runtimeOnly["runtime_only"] = true
	noIndex := metaFileEntry("", "meta-noindex.json")
	f := &fakeManagement{
		files: []map[string]any{
			metaFileEntry("idx-1", "meta-"+fakeUserEmail+".json"),
			runtimeOnly,
			noIndex,
		},
		authFile: map[string]string{},
	}
	logs := captureLogs(t)
	cfg := newFakeManagement(t, f)
	doc, err := buildUsage(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildUsage: %v", err)
	}
	encoded, _ := json.Marshal(doc)
	assertNoSecrets(t, "usage document", string(encoded))
	assertNoSecrets(t, "logs", logs.String())
	// The file name embeds the email; errors must not quote it.
	if strings.Contains(string(encoded), fakeUserEmail) {
		t.Fatalf("document quotes the auth file name: %s", encoded)
	}
	want := []string{"meta auth file download failed: status 404", errMetaNoAuthFile.Error(), errMetaNoAuthIndex.Error()}
	for i, account := range doc.Accounts {
		if account.Error != want[i] {
			t.Fatalf("account %d error = %q, want %q", i, account.Error, want[i])
		}
	}
	if len(f.downloads) != 1 || len(f.calls) != 0 {
		t.Fatalf("downloads = %d, calls = %d", len(f.downloads), len(f.calls))
	}
}

// Each account sends its own device token, and one failing account does not
// affect the others.
func TestMetaMultipleAccounts(t *testing.T) {
	f := &fakeManagement{
		files: []map[string]any{
			metaFileEntry("idx-1", "meta-one.json"),
			metaFileEntry("idx-2", "meta-two.json"),
			metaFileEntry("idx-3", "meta-three.json"),
		},
		authFile: map[string]string{
			"meta-one.json":   metaAuthFileJSON(fakeDCAToken),
			"meta-two.json":   metaAuthFileJSON(fakeDCAToken2),
			"meta-three.json": metaAuthFileJSON("dca:fake-device-token-CCCC3333"),
		},
		upstream: map[string]metaUpstream{
			fakeDCAToken:  {http.StatusOK, metaSuccessBody},
			fakeDCAToken2: {http.StatusTooManyRequests, `{"error":{"resets_at":"1763251200"}}`},
		},
	}
	logs := captureLogs(t)
	cfg := newFakeManagement(t, f)
	doc, err := buildUsage(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildUsage: %v", err)
	}
	encoded, _ := json.Marshal(doc)
	assertNoSecrets(t, "usage document", string(encoded))
	assertNoSecrets(t, "logs", logs.String())

	if len(f.calls) != 3 {
		t.Fatalf("api-calls = %d, want 3", len(f.calls))
	}
	wantToken := map[string]string{"idx-1": fakeDCAToken, "idx-2": fakeDCAToken2, "idx-3": "dca:fake-device-token-CCCC3333"}
	for _, call := range f.calls {
		if call.Header["Authorization"] != "Bearer "+wantToken[call.AuthIndex] {
			t.Fatalf("auth index %s sent another account's token", call.AuthIndex)
		}
	}
	if len(doc.Accounts) != 3 {
		t.Fatalf("accounts = %d", len(doc.Accounts))
	}
	if g := metaGroupsByID(doc.Accounts[0].Groups); len(g) != 2 || doc.Accounts[0].Error != "" {
		t.Fatalf("account 1 = %+v", doc.Accounts[0])
	}
	if g := metaGroupsByID(doc.Accounts[1].Groups); g["seven-day"].RemainingFraction != 0 || g["seven-day"].ResetTime != "2025-11-16T00:00:00Z" {
		t.Fatalf("account 2 = %+v", doc.Accounts[1])
	}
	if doc.Accounts[2].Error != "provider API failed: 401" {
		t.Fatalf("account 3 = %+v", doc.Accounts[2])
	}
}

func TestMetaInvalidReplyIsAnError(t *testing.T) {
	for _, body := range []string{"", "null", "[]", "not json " + fakeMintedKey} {
		if _, err := parseMetaQuota(body); err != errMetaInvalidReply {
			t.Fatalf("body %q: err = %v", body, err)
		}
	}
}

func TestValidDCAToken(t *testing.T) {
	for token, want := range map[string]bool{
		"dca:abc":       true,
		"dca:":          false,
		"abc":           false,
		"dca:a b":       false,
		"dca:a\u00a0b":  false,
		"dca:a\x00b":    false,
		"Bearer dca:ab": false,
	} {
		if got := validDCAToken(token); got != want {
			t.Fatalf("validDCAToken(%q) = %v, want %v", token, got, want)
		}
	}
}
