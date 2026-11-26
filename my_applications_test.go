package account

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestMyApplicationsUsesUserSessionAndFreshMemberships(t *testing.T) {
	var disabled atomic.Bool
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "" {
			t.Error("application credentials sent to browser endpoint")
		}
		switch r.URL.Path {
		case "/auth/email/config":
			_, _ = w.Write([]byte(`{"csrf_token":"flow-token"}`))
		case "/auth/email/login":
			http.SetCookie(w, &http.Cookie{Name: "ca_session", Value: "user-cookie", Path: "/"})
			_, _ = w.Write([]byte(`{"url":"/account"}`))
		case "/api/v1/me/applications":
			if cookie, err := r.Cookie("ca_session"); err != nil || cookie.Value != "user-cookie" {
				t.Error("missing user session")
			}
			if r.Method != http.MethodGet || r.URL.Query().Get("page") != "2" || r.URL.Query().Get("page_size") != "10" || len(r.URL.Query()) != 2 {
				t.Error("wrong list request", r.URL)
			}
			status := "active"
			if disabled.Load() {
				status = "disabled"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{"application_id": "app-public", "application_name": "Example", "application_status": "active", "status": status, "roles": []map[string]string{{"key": "member", "name": "普通用户"}}, "joined_at": "2026-11-26T00:00:00Z"}},
				"page":  2, "page_size": 10, "total": 11, "total_pages": 2, "has_next": false, "has_previous": true,
			})
		default:
			t.Error("unexpected endpoint", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := context.Background()
	if _, err := c.BrowserEmailConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BrowserEmailLogin(ctx, BrowserEmailInput{Email: "fixture@example.test", Password: "fixture-password"}); err != nil {
		t.Fatal(err)
	}
	page, pageSize := int64(2), int64(10)
	for _, status := range []string{"active", "disabled"} {
		disabled.Store(status == "disabled")
		out, err := c.ListMyApplications(ctx, ListMyApplicationsQuery{Page: &page, PageSize: &pageSize})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Items) != 1 || out.Items[0].Status != status || len(out.Items[0].Roles) != 1 || out.Items[0].Roles[0].Key != "member" || out.Page != page || out.Total != 11 || out.HasNext || !out.HasPrevious {
			t.Fatal("membership or pagination contract", out)
		}
	}
}
