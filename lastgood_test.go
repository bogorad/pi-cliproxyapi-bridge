package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// lgReply is what the fake management API answers for one auth index.
type lgReply struct {
	// managementStatus is the HTTP status of /api-call itself; 0 means 200.
	managementStatus int
	// upstreamStatus and body are the provider reply carried inside it.
	upstreamStatus int
	body           string
	// delay holds the reply back, to let a caller's deadline pass.
	delay time.Duration
}

// lgFake stands in for the management API with an editable auth-files list
// and an editable reply per auth index.
type lgFake struct {
	mu      sync.Mutex
	files   []authFile
	replies map[string]lgReply
}

func (f *lgFake) setFiles(files ...authFile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files = append([]authFile(nil), files...)
}

func (f *lgFake) setReply(authIndex string, reply lgReply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[authIndex] = reply
}

func newLGFake(t *testing.T) (*lgFake, pluginConfig) {
	t.Helper()
	fake := &lgFake{replies: map[string]lgReply{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/management/auth-files", func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		files := append([]authFile(nil), fake.files...)
		fake.mu.Unlock()
		_ = json.NewEncoder(w).Encode(authFilesResponse{Files: files})
	})
	mux.HandleFunc("/v0/management/api-call", func(w http.ResponseWriter, r *http.Request) {
		var req apiCallRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fake.mu.Lock()
		reply, ok := fake.replies[req.AuthIndex]
		fake.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if reply.delay > 0 {
			select {
			case <-time.After(reply.delay):
			case <-r.Context().Done():
				return
			}
		}
		if reply.managementStatus != 0 && reply.managementStatus != http.StatusOK {
			w.WriteHeader(reply.managementStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(apiCallResponse{StatusCode: reply.upstreamStatus, Body: reply.body})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	t.Setenv("PI_BRIDGE_LG_TEST_KEY", "lg-test-management-key")
	cfg := defaultConfig()
	cfg.advanced.ManagementURL = server.URL + "/v0/management"
	cfg.advanced.ManagementKeyEnv = "PI_BRIDGE_LG_TEST_KEY"
	return fake, cfg
}

func codexFile(index, email string) authFile {
	return authFile{AuthIndex: index, Name: "codex-" + index + ".json", Provider: "codex", Email: email, Status: "active"}
}

func codexOK(usedPercent float64) lgReply {
	return lgReply{upstreamStatus: http.StatusOK, body: fmt.Sprintf(
		`{"rate_limit":{"primary_window":{"used_percent":%g,"reset_at":1795000000,"limit_window_seconds":604800}}}`,
		usedPercent)}
}

var lgT0 = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func buildAt(t *testing.T, cfg pluginConfig, store *lastGoodStore, now time.Time) usageDocument {
	t.Helper()
	doc, err := buildUsageWith(context.Background(), cfg, store, now)
	if err != nil {
		t.Fatalf("buildUsageWith: %v", err)
	}
	return doc
}

func accountByIndex(t *testing.T, doc usageDocument, index string) usageAccount {
	t.Helper()
	for _, account := range doc.Accounts {
		if account.AuthIndex == index {
			return account
		}
	}
	t.Fatalf("account %s missing from %+v", index, doc.Accounts)
	return usageAccount{}
}

func requireFresh(t *testing.T, account usageAccount, remaining float64) {
	t.Helper()
	if account.Error != "" || account.Stale || account.LastGoodAt != "" || account.StaleSince != "" {
		t.Fatalf("want a fresh account, got %+v", account)
	}
	if len(account.Groups) != 1 || account.Groups[0].Stale {
		t.Fatalf("want one fresh group, got %+v", account.Groups)
	}
	if got := account.Groups[0].RemainingFraction; got != remaining {
		t.Fatalf("remaining = %v, want %v", got, remaining)
	}
}

func requireStale(t *testing.T, account usageAccount, remaining float64, lastGoodAt, staleSince time.Time) {
	t.Helper()
	if account.Error == "" {
		t.Fatalf("a stale account must carry the read error: %+v", account)
	}
	if !account.Stale {
		t.Fatalf("want stale, got %+v", account)
	}
	if account.LastGoodAt != lastGoodAt.Format(time.RFC3339) {
		t.Fatalf("lastGoodAt = %q, want %s", account.LastGoodAt, lastGoodAt.Format(time.RFC3339))
	}
	if account.StaleSince != staleSince.Format(time.RFC3339) {
		t.Fatalf("staleSince = %q, want %s", account.StaleSince, staleSince.Format(time.RFC3339))
	}
	if len(account.Groups) != 1 {
		t.Fatalf("want the last good group, got %+v", account.Groups)
	}
	group := account.Groups[0]
	if !group.Stale || group.RemainingFraction != remaining || group.ResetTime == "" {
		t.Fatalf("stale group = %+v, want stale with remaining %v and its reset", group, remaining)
	}
}

func requireUnknown(t *testing.T, account usageAccount) {
	t.Helper()
	if account.Error == "" || account.Stale || account.LastGoodAt != "" {
		t.Fatalf("want an unknown account (error, not stale), got %+v", account)
	}
	if account.Groups == nil || len(account.Groups) != 0 {
		t.Fatalf("want an empty groups list, got %#v", account.Groups)
	}
}

// Every kind of failed read serves the last good groups with a stale marker.
func TestLastGoodServedOnFailedRead(t *testing.T) {
	failures := map[string]lgReply{
		"provider 429":     {upstreamStatus: http.StatusTooManyRequests, body: `{"error":"rate limited"}`},
		"provider 401":     {upstreamStatus: http.StatusUnauthorized, body: `{}`},
		"provider 503":     {upstreamStatus: http.StatusServiceUnavailable, body: `oops`},
		"management 502":   {managementStatus: http.StatusBadGateway},
		"no quota windows": {upstreamStatus: http.StatusOK, body: `{"rate_limit":{"primary_window":{"used_percent":null}}}`},
		"invalid payload":  {upstreamStatus: http.StatusOK, body: `{"rate_limit":`},
	}
	for name, failure := range failures {
		t.Run(name, func(t *testing.T) {
			fake, cfg := newLGFake(t)
			store := newLastGoodStore()
			fake.setFiles(codexFile("c1", "one@example.com"))

			fake.setReply("c1", codexOK(40))
			requireFresh(t, accountByIndex(t, buildAt(t, cfg, store, lgT0), "c1"), 0.6)

			fake.setReply("c1", failure)
			t1 := lgT0.Add(3 * time.Minute)
			requireStale(t, accountByIndex(t, buildAt(t, cfg, store, t1), "c1"), 0.6, lgT0, t1)

			// staleSince stays at the first failed read.
			t2 := t1.Add(2 * time.Minute)
			requireStale(t, accountByIndex(t, buildAt(t, cfg, store, t2), "c1"), 0.6, lgT0, t1)
		})
	}
}

// A read that runs past the caller's deadline is a failed read too.
func TestLastGoodServedOnTimeout(t *testing.T) {
	fake, cfg := newLGFake(t)
	store := newLastGoodStore()
	fake.setFiles(codexFile("c1", "one@example.com"))
	fake.setReply("c1", codexOK(10))
	requireFresh(t, accountByIndex(t, buildAt(t, cfg, store, lgT0), "c1"), 0.9)

	slow := codexOK(99)
	slow.delay = 2 * time.Second
	fake.setReply("c1", slow)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	t1 := lgT0.Add(time.Minute)
	// The auth-files read is quick; only the quota read times out.
	doc, err := buildUsageWith(ctx, cfg, store, t1)
	if err != nil {
		t.Fatalf("buildUsageWith: %v", err)
	}
	requireStale(t, accountByIndex(t, doc, "c1"), 0.9, lgT0, t1)
}

// A first failed read stays unknown: the bridge never makes up quota.
func TestLastGoodFirstFailureStaysUnknown(t *testing.T) {
	fake, cfg := newLGFake(t)
	store := newLastGoodStore()
	fake.setFiles(codexFile("c1", "one@example.com"))
	fake.setReply("c1", lgReply{upstreamStatus: http.StatusTooManyRequests})
	requireUnknown(t, accountByIndex(t, buildAt(t, cfg, store, lgT0), "c1"))
}

// A good read replaces the last good groups and clears the stale state; the
// next failure starts a new stale period.
func TestLastGoodSuccessReplacesAndClearsStale(t *testing.T) {
	fake, cfg := newLGFake(t)
	store := newLastGoodStore()
	fake.setFiles(codexFile("c1", "one@example.com"))

	fake.setReply("c1", codexOK(40))
	buildAt(t, cfg, store, lgT0)

	fake.setReply("c1", lgReply{upstreamStatus: http.StatusTooManyRequests})
	t1 := lgT0.Add(time.Minute)
	requireStale(t, accountByIndex(t, buildAt(t, cfg, store, t1), "c1"), 0.6, lgT0, t1)

	fake.setReply("c1", codexOK(75))
	t2 := t1.Add(time.Minute)
	requireFresh(t, accountByIndex(t, buildAt(t, cfg, store, t2), "c1"), 0.25)

	fake.setReply("c1", lgReply{upstreamStatus: http.StatusTooManyRequests})
	t3 := t2.Add(time.Minute)
	requireStale(t, accountByIndex(t, buildAt(t, cfg, store, t3), "c1"), 0.25, t2, t3)
}

// A last good read older than the maximum age is dropped.
func TestLastGoodExpiresAfterMaxAge(t *testing.T) {
	fake, cfg := newLGFake(t)
	cfg.advanced.LastGoodMaxAgeSeconds = 600
	store := newLastGoodStore()
	fake.setFiles(codexFile("c1", "one@example.com"))
	fake.setReply("c1", codexOK(40))
	buildAt(t, cfg, store, lgT0)

	fake.setReply("c1", lgReply{upstreamStatus: http.StatusTooManyRequests})
	t1 := lgT0.Add(10 * time.Minute)
	requireStale(t, accountByIndex(t, buildAt(t, cfg, store, t1), "c1"), 0.6, lgT0, t1)

	t2 := lgT0.Add(10*time.Minute + time.Second)
	requireUnknown(t, accountByIndex(t, buildAt(t, cfg, store, t2), "c1"))
	if n := store.len(); n != 0 {
		t.Fatalf("store keeps %d expired entries", n)
	}
}

// The default maximum age is one day.
func TestLastGoodDefaultMaxAge(t *testing.T) {
	fake, cfg := newLGFake(t)
	store := newLastGoodStore()
	fake.setFiles(codexFile("c1", "one@example.com"))
	fake.setReply("c1", codexOK(40))
	buildAt(t, cfg, store, lgT0)

	fake.setReply("c1", lgReply{upstreamStatus: http.StatusTooManyRequests})
	t1 := lgT0.Add(24 * time.Hour)
	requireStale(t, accountByIndex(t, buildAt(t, cfg, store, t1), "c1"), 0.6, lgT0, t1)
	requireUnknown(t, accountByIndex(t, buildAt(t, cfg, store, t1.Add(time.Second)), "c1"))
}

// A negative maximum age turns the fallback off.
func TestLastGoodCanBeDisabled(t *testing.T) {
	fake, cfg := newLGFake(t)
	cfg.advanced.LastGoodMaxAgeSeconds = -1
	store := newLastGoodStore()
	fake.setFiles(codexFile("c1", "one@example.com"))
	fake.setReply("c1", codexOK(40))
	buildAt(t, cfg, store, lgT0)

	fake.setReply("c1", lgReply{upstreamStatus: http.StatusTooManyRequests})
	requireUnknown(t, accountByIndex(t, buildAt(t, cfg, store, lgT0.Add(time.Second)), "c1"))
}

// An account that leaves auth-files loses its last good read, and a
// credential that replaces another does not inherit its groups.
func TestLastGoodDroppedWhenAccountRemoved(t *testing.T) {
	fake, cfg := newLGFake(t)
	store := newLastGoodStore()
	fake.setFiles(codexFile("c1", "one@example.com"), codexFile("c2", "two@example.com"))
	fake.setReply("c1", codexOK(40))
	fake.setReply("c2", codexOK(20))
	buildAt(t, cfg, store, lgT0)
	if n := store.len(); n != 2 {
		t.Fatalf("store has %d entries, want 2", n)
	}

	fake.setFiles(codexFile("c2", "two@example.com"))
	doc := buildAt(t, cfg, store, lgT0.Add(time.Minute))
	if len(doc.Accounts) != 1 {
		t.Fatalf("accounts = %+v, want only c2", doc.Accounts)
	}
	if n := store.len(); n != 1 {
		t.Fatalf("store has %d entries after removal, want 1", n)
	}

	// c1 comes back and its read fails: nothing to fall back to.
	fake.setFiles(codexFile("c1", "one@example.com"), codexFile("c2", "two@example.com"))
	fake.setReply("c1", lgReply{upstreamStatus: http.StatusTooManyRequests})
	requireUnknown(t, accountByIndex(t, buildAt(t, cfg, store, lgT0.Add(2*time.Minute)), "c1"))

	// A different login at c2's auth index and file name is a new credential.
	fake.setFiles(codexFile("c2", "other@example.com"))
	fake.setReply("c2", lgReply{upstreamStatus: http.StatusTooManyRequests})
	requireUnknown(t, accountByIndex(t, buildAt(t, cfg, store, lgT0.Add(3*time.Minute)), "c2"))
}

// The 2026-11-15/16 case: codex accounts flip to status "error" and
// unavailable for a few minutes. They must stay in the document with their
// quota, from a good read or from the last good one.
func TestLastGoodCooldownAccountKeepsQuota(t *testing.T) {
	fake, cfg := newLGFake(t)
	store := newLastGoodStore()
	healthy := codexFile("c1", "one@example.com")
	cooling := healthy
	cooling.Status = "error"
	cooling.Unavailable = true

	fake.setFiles(healthy)
	fake.setReply("c1", codexOK(40))
	buildAt(t, cfg, store, lgT0)

	fake.setFiles(cooling)
	t1 := lgT0.Add(time.Minute)
	account := accountByIndex(t, buildAt(t, cfg, store, t1), "c1")
	if account.Status != "error" || !account.Unavailable {
		t.Fatalf("status = %q unavailable = %v", account.Status, account.Unavailable)
	}
	requireFresh(t, account, 0.6)

	fake.setReply("c1", lgReply{upstreamStatus: http.StatusTooManyRequests})
	t2 := lgT0.Add(2 * time.Minute)
	account = accountByIndex(t, buildAt(t, cfg, store, t2), "c1")
	if account.Status != "error" || !account.Unavailable || !account.Supported {
		t.Fatalf("account = %+v", account)
	}
	requireStale(t, account, 0.6, t1, t2)
}

// Many concurrent builds share one store. Run with -race.
func TestLastGoodConcurrentBuilds(t *testing.T) {
	fake, cfg := newLGFake(t)
	store := newLastGoodStore()
	fake.setFiles(codexFile("c1", "one@example.com"), codexFile("c2", "two@example.com"))
	fake.setReply("c1", codexOK(40))
	fake.setReply("c2", codexOK(20))
	buildAt(t, cfg, store, lgT0)

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Flip replies while other builds read, so record and fallback
			// interleave.
			if i%4 == 0 {
				fake.setReply("c1", lgReply{upstreamStatus: http.StatusTooManyRequests})
			} else if i%4 == 2 {
				fake.setReply("c1", codexOK(40))
			}
			doc, err := buildUsageWith(context.Background(), cfg, store, lgT0.Add(time.Duration(i)*time.Second))
			if err != nil {
				errs <- err
				return
			}
			for _, account := range doc.Accounts {
				if len(account.Groups) != 1 || account.Groups[0].RemainingFraction <= 0 {
					errs <- fmt.Errorf("build %d: account %s lost its quota: %+v", i, account.AuthIndex, account)
					return
				}
				if account.Stale != (account.Error != "") {
					errs <- fmt.Errorf("build %d: stale and error disagree: %+v", i, account)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := store.len(); n != 2 {
		t.Fatalf("store has %d entries, want 2", n)
	}
}

// Callers cannot change stored groups through the slices they get.
func TestLastGoodStoreCopies(t *testing.T) {
	store := newLastGoodStore()
	groups := []quotaGroup{simpleGroup("g", "G", 0.5, "")}
	store.record("k", groups, lgT0)
	groups[0].RemainingFraction = 0
	groups[0].Models[0].RemainingFraction = 0

	got, _, _, ok := store.fallback("k", lgT0, time.Hour)
	if !ok || got[0].RemainingFraction != 0.5 || got[0].Models[0].RemainingFraction != 0.5 {
		t.Fatalf("store shares memory with the caller: %+v", got)
	}
	got[0].Models[0].RemainingFraction = 0
	again, _, _, _ := store.fallback("k", lgT0, time.Hour)
	if again[0].Models[0].RemainingFraction != 0.5 {
		t.Fatalf("store shares memory with a reader: %+v", again)
	}
}

// A reset in the past marks the group stale and keeps the reset time.
func TestPassedResetMarkedStale(t *testing.T) {
	now := lgT0
	doc := usageDocument{Accounts: []usageAccount{{Groups: []quotaGroup{
		{ID: "past", ResetTime: now.Add(-time.Minute).Format(time.RFC3339)},
		{ID: "future", ResetTime: now.Add(time.Minute).Format(time.RFC3339)},
		{ID: "none"},
		{ID: "garbage", ResetTime: "soon"},
	}}}}
	markPassedResets(&doc, now)
	want := map[string]bool{"past": true, "future": false, "none": false, "garbage": false}
	for _, group := range doc.Accounts[0].Groups {
		if group.Stale != want[group.ID] {
			t.Errorf("group %s stale = %v, want %v", group.ID, group.Stale, want[group.ID])
		}
	}
	if got := doc.Accounts[0].Groups[0].ResetTime; got != now.Add(-time.Minute).Format(time.RFC3339) {
		t.Fatalf("reset time changed to %q", got)
	}
}

func staleSampleJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(usageDocument{
		SchemaVersion: 1,
		GeneratedAt:   "2026-11-17T12:03:00Z",
		Accounts: []usageAccount{
			{Provider: "codex", AuthIndex: "c1", Supported: true, Error: "provider API failed: 429",
				Stale: true, LastGoodAt: "2026-11-17T12:00:00Z", StaleSince: "2026-11-17T12:03:00Z",
				Groups: []quotaGroup{{ID: "primary-window", RemainingFraction: 0.6, ResetTime: "2099-01-01T00:00:00Z", Stale: true}}},
			{Provider: "codex", AuthIndex: "c2", Supported: true,
				Groups: []quotaGroup{{ID: "primary-window", RemainingFraction: 0.8, ResetTime: "2020-01-01T00:00:00Z"}}},
		},
		Unsupported: []string{},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// v2 serves the last good groups with their markers, and marks a fresh
// group whose reset has passed.
func TestShapeV2CarriesStaleMarkers(t *testing.T) {
	shaped := shapeForContract(staleSampleJSON(t), contractLatest, authenticatedClient{KeyHint: "sk-abc…1234"}, lgT0, time.Minute)
	var doc usageDocument
	if err := json.Unmarshal(shaped, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	stale := doc.Accounts[0]
	if !stale.Stale || stale.LastGoodAt == "" || stale.StaleSince == "" || len(stale.Groups) != 1 || !stale.Groups[0].Stale {
		t.Fatalf("stale account = %+v", stale)
	}
	fresh := doc.Accounts[1]
	if fresh.Stale || len(fresh.Groups) != 1 || !fresh.Groups[0].Stale || fresh.Groups[0].ResetTime != "2020-01-01T00:00:00Z" {
		t.Fatalf("passed reset not marked, or reset lost: %+v", fresh)
	}
	if doc.Cache == nil || doc.Cache.Stale {
		t.Fatalf("cache section = %+v, want present and not stale", doc.Cache)
	}
}

// v1 keeps the sidecar's shape: a failed read is an error with no groups, and
// no stale field appears.
func TestShapeV1DropsLastGood(t *testing.T) {
	shaped := shapeForContract(staleSampleJSON(t), contractV1, authenticatedClient{}, lgT0, time.Minute)
	for _, field := range []string{`"stale"`, `"lastGoodAt"`, `"staleSince"`, `"cache"`, `"client"`} {
		if strings.Contains(string(shaped), field) {
			t.Fatalf("v1 document contains %s: %s", field, shaped)
		}
	}
	var doc usageDocument
	if err := json.Unmarshal(shaped, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Accounts[0].Error == "" || doc.Accounts[0].Groups == nil || len(doc.Accounts[0].Groups) != 0 {
		t.Fatalf("v1 failed account = %+v, want an error and an empty groups list", doc.Accounts[0])
	}
	if len(doc.Accounts[1].Groups) != 1 {
		t.Fatalf("v1 fresh account lost its groups: %+v", doc.Accounts[1])
	}
}

func TestLastGoodMaxAgeConfig(t *testing.T) {
	cases := map[string]struct {
		advanced string
		want     time.Duration
	}{
		"default":  {``, 24 * time.Hour},
		"zero":     {`{"last_good_max_age_seconds":0}`, 24 * time.Hour},
		"custom":   {`{"last_good_max_age_seconds":3600}`, time.Hour},
		"disabled": {`{"last_good_max_age_seconds":-1}`, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"advanced": tc.advanced})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			cfg, err := parseConfig(raw)
			if err != nil {
				t.Fatalf("parseConfig: %v", err)
			}
			if got := cfg.lastGoodMaxAge(); got != tc.want {
				t.Fatalf("max age = %v, want %v", got, tc.want)
			}
		})
	}
}
