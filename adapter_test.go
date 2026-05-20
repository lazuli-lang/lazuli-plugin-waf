package wafplugin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazuli.dev/runtime/lazuli/waf"
)

func TestCloudflareWAFDeniesKnownBadRequest(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client/v4/zones/zone-1/waf/inspect" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("unexpected authorization: %s", got)
		}
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatal(err)
		}
		action := "allow"
		if strings.Contains(strings.ToLower(in["query"]), "union") {
			action = "deny"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"result":  map[string]string{"action": action},
		})
	}))
	defer api.Close()

	filter := &CloudflareWAF{
		BaseURL: api.URL,
		ZoneID:  "zone-1",
		Token:   "test-token",
		Client:  api.Client(),
	}
	req := httptest.NewRequest("GET", "/search?q=%27+UNION+SELECT", nil)
	decision, err := filter.Inspect(req.Context(), req)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if decision != waf.Deny {
		t.Fatalf("known-bad request must Deny; got %v", decision)
	}
}
