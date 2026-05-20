// Package wafplugin registers the @plugin/waf adapter.
package wafplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"lazuli.dev/runtime/lazuli"
	"lazuli.dev/runtime/lazuli/waf"
)

const AdapterRef = "@plugin/waf"

var ErrUnimplemented = errors.New("lazuli-plugin-waf: vendor unimplemented")

type CloudflareWAF struct {
	BaseURL string
	ZoneID  string
	Token   string
	Client  *http.Client
}

var _ waf.Filter = (*CloudflareWAF)(nil)

func init() { lazuli.RegisterAdapter("@plugin/waf", &CloudflareWAF{}) }

func (c *CloudflareWAF) Inspect(ctx context.Context, r *http.Request) (waf.Decision, error) {
	zoneID := env(c.ZoneID, "CLOUDFLARE_WAF_ZONE_ID")
	token := env(c.Token, "CLOUDFLARE_WAF_API_TOKEN")
	if zoneID == "" || token == "" {
		return waf.Allow, waf.ErrFilterUnavailable
	}
	body, _ := json.Marshal(map[string]string{
		"method":     r.Method,
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"user_agent": r.UserAgent(),
		"remote":     r.RemoteAddr,
	})
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	base := env(c.BaseURL, "CLOUDFLARE_WAF_API_BASE")
	if base == "" {
		base = "https://api.cloudflare.com"
	}
	path := "/client/v4/zones/" + url.PathEscape(zoneID) + "/waf/inspect"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return waf.Allow, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return waf.Allow, waf.ErrFilterUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return waf.Allow, waf.ErrFilterUnavailable
	}
	var out struct {
		Result struct {
			Action string `json:"action"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return waf.Allow, err
	}
	switch strings.ToLower(out.Result.Action) {
	case "deny", "block":
		return waf.Deny, nil
	case "tarpit":
		return waf.Tarpit, nil
	default:
		return waf.Allow, nil
	}
}

func (c *CloudflareWAF) Close() error { return nil }

func env(value, name string) string {
	if value != "" {
		return value
	}
	return os.Getenv(name)
}

type stubWAF struct{}

func (stubWAF) Inspect(context.Context, *http.Request) (waf.Decision, error) {
	return waf.Allow, ErrUnimplemented
}
func (stubWAF) Close() error { return nil }

type AWSWAF struct{ stubWAF }
type ImpervaWAF struct{ stubWAF }
type ModSecurityWAF struct{ stubWAF }
