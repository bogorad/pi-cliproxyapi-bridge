package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// metaQuotaURL is the Muse Code key endpoint. It is the only place Meta
// reports subscription usage, and it is the endpoint the CLIProxyAPI
// Management Center reads for the same purpose.
const metaQuotaURL = "https://api.meta.ai/muse-code/key"

// metaAuthFileLimit bounds how much of a downloaded auth file is read. A Meta
// credential is a few hundred bytes.
const metaAuthFileLimit = 1 << 20

// Client-visible Meta errors are fixed strings. They never carry the device
// token, the auth file name (it often embeds the account email), or any part
// of a response body, which can echo the minted api_key and user identity.
var (
	errMetaNoAuthIndex  = errors.New("meta credential has no auth index")
	errMetaNoAuthFile   = errors.New("meta credential has no auth file")
	errMetaDownload     = errors.New("meta auth file download failed")
	errMetaInvalidFile  = errors.New("meta auth file is invalid")
	errMetaNoDCAToken   = errors.New("meta auth file has no dca token")
	errMetaInvalidReply = errors.New("invalid Meta quota response")
)

// fetchMetaQuota reads Muse subscription usage for one Meta credential.
//
// Unlike the other providers, Meta cannot use $TOKEN$: CLIProxyAPI resolves it
// to the minted LLM api_key, and the key endpoint accepts only the dca: device
// token. The plugin therefore downloads the credential's auth file through the
// management API and reads dca_token itself. The token lives in this call
// only: it is never logged, cached, stored, put in an error, or returned.
func fetchMetaQuota(ctx context.Context, cfg pluginConfig, file authFile) ([]quotaGroup, error) {
	if strings.TrimSpace(file.AuthIndex) == "" {
		return nil, errMetaNoAuthIndex
	}
	if strings.TrimSpace(file.Name) == "" || file.RuntimeOnly {
		return nil, errMetaNoAuthFile
	}

	dcaToken, err := cfg.metaDCAToken(ctx, file.Name)
	if err != nil {
		return nil, err
	}

	// The header carries the literal token; $TOKEN$ would make CLIProxyAPI
	// substitute the minted LLM key, which the endpoint rejects with 401.
	resp, err := cfg.managementAPICall(ctx, apiCallRequest{
		AuthIndex: file.AuthIndex,
		Method:    http.MethodPost,
		URL:       metaQuotaURL,
		Header: map[string]string{
			"Accept":        "application/json",
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + dcaToken,
			"x-api-version": "1.0.0",
		},
		Data: "{}",
	})
	if err != nil {
		return nil, err
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		// The account is out of Muse usage. The 429 body is the only place
		// the reset time can come from.
		reset := metaExhaustedReset(resp.Body)
		return []quotaGroup{
			simpleGroup("usage-window", metaWindowLabel(nil), 0, reset),
			simpleGroup("seven-day", "7d Weekly", 0, reset),
		}, nil
	case resp.StatusCode != http.StatusOK:
		return nil, providerFailure(resp.StatusCode)
	}
	return parseMetaQuota(resp.Body)
}

// metaDCAToken downloads one auth file and returns only its dca_token. The
// rest of the file is decoded into nothing and discarded.
func (c pluginConfig) metaDCAToken(ctx context.Context, name string) (string, error) {
	key := c.managementKey()
	if key == "" {
		return "", fmt.Errorf("management key is not configured")
	}
	target := c.advanced.ManagementURL + "/auth-files/download?name=" + url.QueryEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", errMetaDownload
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)

	// Transport errors are not wrapped: they quote the URL, and the URL quotes
	// the file name.
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", errMetaDownload
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, metaAuthFileLimit))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status %d", errMetaDownload, resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, metaAuthFileLimit))
	if err != nil {
		return "", errMetaDownload
	}
	if !isJSONObject(raw) {
		return "", errMetaInvalidFile
	}
	var credential struct {
		DCAToken any `json:"dca_token"`
	}
	if err := json.Unmarshal(raw, &credential); err != nil {
		return "", errMetaInvalidFile
	}
	token, _ := credential.DCAToken.(string)
	token = strings.TrimSpace(token)
	if !validDCAToken(token) {
		return "", errMetaNoDCAToken
	}
	return token, nil
}

// validDCAToken accepts only a device token: the dca: prefix and no
// whitespace, so the minted LLM key can never be sent by mistake.
func validDCAToken(token string) bool {
	rest, ok := strings.CutPrefix(token, "dca:")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r <= ' ' || r == 0x7f || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// metaWindowUsage is one subs_usage window. Only the fields the quota view
// needs are decoded.
type metaWindowUsage struct {
	UsedPercent        flexNumber `json:"used_percent"`
	ResetsAt           flexNumber `json:"resets_at"`
	WindowDurationMins flexNumber `json:"window_duration_mins"`
}

// metaQuotaPayload names only the usage fields. The response also carries
// api_key, user_email and user_full_name; they are never decoded.
type metaQuotaPayload struct {
	SubsUsage *struct {
		Window *metaWindowUsage `json:"window"`
		Weekly *metaWindowUsage `json:"weekly"`
	} `json:"subs_usage"`
}

// parseMetaQuota maps subs_usage onto the two Muse windows. Both groups are
// always reported. Operator decision: a reply without subs_usage, or a window
// without used_percent, reports that window as 0. An idle 5h window gives
// the same reply, so a window can show 0 while credits remain.
func parseMetaQuota(body string) ([]quotaGroup, error) {
	if !isJSONObject([]byte(body)) {
		return nil, errMetaInvalidReply
	}
	var payload metaQuotaPayload
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return nil, errMetaInvalidReply
	}
	var rolling, weekly *metaWindowUsage
	if payload.SubsUsage != nil {
		rolling, weekly = payload.SubsUsage.Window, payload.SubsUsage.Weekly
	}

	groups := make([]quotaGroup, 0, 2)
	for _, w := range []struct {
		id     string
		label  string
		window *metaWindowUsage
	}{
		{"usage-window", "", rolling},
		{"seven-day", "7d Weekly", weekly},
	} {
		var (
			remaining float64
			reset     string
			minutes   *float64
		)
		if w.window != nil {
			minutes = w.window.WindowDurationMins.positive()
			reset = unixToRFC3339(w.window.ResetsAt.unixSeconds())
			if w.window.UsedPercent.valid {
				remaining = remainingFromPercent(math.Min(100, math.Max(0, w.window.UsedPercent.value)))
			}
		}
		label := w.label
		if label == "" {
			label = metaWindowLabel(minutes)
		}
		groups = append(groups, simpleGroup(w.id, label, remaining, reset))
	}
	return groups, nil
}

// metaWindowLabel names the rolling window by its duration ("5h Window").
func metaWindowLabel(minutes *float64) string {
	if minutes == nil {
		return "Usage Window"
	}
	seconds := int64(math.Round(*minutes * 60))
	return codexWindowLabel(&seconds, "Usage")
}

// metaExhaustedReset reads error.resets_at from a 429 body. Nothing else in
// that body is decoded, and an unreadable body yields no reset time.
func metaExhaustedReset(body string) string {
	if !isJSONObject([]byte(body)) {
		return ""
	}
	var payload struct {
		Error *struct {
			ResetsAt flexNumber `json:"resets_at"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil || payload.Error == nil {
		return ""
	}
	return unixToRFC3339(payload.Error.ResetsAt.unixSeconds())
}

// flexNumber decodes a JSON number or a numeric string, as Meta has sent
// both. Any other value, including null, decodes as absent instead of
// failing the whole reply.
type flexNumber struct {
	value float64
	valid bool
}

func (n *flexNumber) UnmarshalJSON(raw []byte) error {
	*n = flexNumber{}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	var f float64
	switch t := v.(type) {
	case float64:
		f = t
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil {
			return nil
		}
		f = parsed
	default:
		return nil
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	*n = flexNumber{value: f, valid: true}
	return nil
}

func (n flexNumber) positive() *float64 {
	if !n.valid || n.value <= 0 {
		return nil
	}
	v := n.value
	return &v
}

// unixSeconds returns a positive timestamp in whole seconds, or nil.
func (n flexNumber) unixSeconds() *int64 {
	p := n.positive()
	if p == nil || *p > math.MaxInt64/2 {
		return nil
	}
	ts := int64(*p)
	return &ts
}
