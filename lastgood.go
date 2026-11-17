package main

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// A provider quota read fails now and then: a 429 from the usage endpoint, a
// timeout, a 5xx, or a payload without windows. The credential itself usually
// keeps serving requests. Dropping its groups on such a read makes a client
// count one account less until the next good read, so the bridge keeps the
// last good groups of each account in memory and serves them, marked stale,
// while reads fail.
//
// The memory is bounded: an entry expires after a maximum age, and an entry
// goes away when its account is no longer in auth-files. A first failure is
// still reported as unknown (an error and no groups); the bridge never makes
// up quota it did not read.

// lastGoodKey identifies one credential. It covers the identity fields as well
// as the auth index, so a replaced credential at the same index or under the
// same file name does not inherit the groups of the credential it replaced.
func lastGoodKey(provider string, file authFile) string {
	return strings.Join([]string{
		provider,
		strings.TrimSpace(file.AuthIndex),
		strings.TrimSpace(file.Name),
		strings.TrimSpace(file.Email),
		strings.TrimSpace(file.Account),
	}, "\x00")
}

type lastGoodEntry struct {
	groups []quotaGroup
	at     time.Time
	// failedSince is the first failed read after the last good one. It is
	// zero while reads succeed.
	failedSince time.Time
}

// lastGoodStore holds the last good quota groups per credential. It is safe
// for concurrent use; the stored slices are copies and never leave the store.
type lastGoodStore struct {
	mu      sync.Mutex
	entries map[string]lastGoodEntry
}

func newLastGoodStore() *lastGoodStore {
	return &lastGoodStore{entries: map[string]lastGoodEntry{}}
}

// record stores a successful read and clears any failure state.
func (s *lastGoodStore) record(key string, groups []quotaGroup, now time.Time) {
	copied := copyGroups(groups)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = lastGoodEntry{groups: copied, at: now}
}

// fallback returns the last good groups for a failed read, with the time of
// that read and the time reads started to fail. An entry older than maxAge is
// dropped and not returned. A maxAge of zero or less disables the fallback.
func (s *lastGoodStore) fallback(key string, now time.Time, maxAge time.Duration) ([]quotaGroup, time.Time, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		return nil, time.Time{}, time.Time{}, false
	}
	if maxAge <= 0 || now.Sub(entry.at) > maxAge {
		delete(s.entries, key)
		return nil, time.Time{}, time.Time{}, false
	}
	if entry.failedSince.IsZero() {
		entry.failedSince = now
		s.entries[key] = entry
	}
	return copyGroups(entry.groups), entry.at, entry.failedSince, true
}

// prune drops entries of credentials that are no longer present, and entries
// older than maxAge. present holds the keys of the current auth-files list.
func (s *lastGoodStore) prune(present map[string]bool, now time.Time, maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, entry := range s.entries {
		if !present[key] || maxAge <= 0 || now.Sub(entry.at) > maxAge {
			delete(s.entries, key)
		}
	}
}

// reset forgets everything, for example after a configuration change.
func (s *lastGoodStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = map[string]lastGoodEntry{}
}

func (s *lastGoodStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func copyGroups(groups []quotaGroup) []quotaGroup {
	out := make([]quotaGroup, len(groups))
	for i, group := range groups {
		out[i] = group
		if group.Models != nil {
			out[i].Models = append([]quotaModel(nil), group.Models...)
		}
	}
	return out
}

// markPassedResets flags every group whose reset time is already in the past.
// Its numbers describe a window that has ended, so they are not current. The
// reset time itself is kept, so a client can still see when the window ended.
func markPassedResets(doc *usageDocument, now time.Time) {
	for i := range doc.Accounts {
		groups := doc.Accounts[i].Groups
		for j := range groups {
			if resetPassed(groups[j].ResetTime, now) {
				groups[j].Stale = true
			}
		}
	}
}

func resetPassed(resetTime string, now time.Time) bool {
	value := strings.TrimSpace(resetTime)
	if value == "" {
		return false
	}
	reset, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return false
	}
	return reset.Before(now)
}

// withoutLastGood returns a contract v1 document: the sidecar reported a
// failed read as an error with no groups, and a v1 client has no field that
// says the numbers are old. So the last good groups and their markers are
// removed for v1. The error stays.
func withoutLastGood(encoded []byte) []byte {
	if !strings.Contains(string(encoded), `"stale":true`) {
		return encoded
	}
	var doc usageDocument
	if err := json.Unmarshal(encoded, &doc); err != nil {
		return encoded
	}
	changed := false
	for i := range doc.Accounts {
		account := &doc.Accounts[i]
		if !account.Stale {
			continue
		}
		account.Stale = false
		account.LastGoodAt = ""
		account.StaleSince = ""
		account.Groups = []quotaGroup{}
		changed = true
	}
	if !changed {
		return encoded
	}
	patched, err := json.Marshal(doc)
	if err != nil {
		return encoded
	}
	return patched
}
