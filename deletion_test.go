package account

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestDeletionUsesAdminCSRFAndExplicitRevision(t *testing.T) {
	requests := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "" {
			t.Error("application credentials leaked to admin operation")
		}
		if r.URL.Path == "/api/admin/v1/auth/login" {
			http.SetCookie(w, &http.Cookie{Name: "ca_admin", Value: "admin-session", Path: "/"})
			_, _ = w.Write([]byte(`{"csrf_token":"admin-csrf","user":{"id":"admin"}}`))
			return
		}
		requests++
		if r.Method != "DELETE" || r.Header.Get("X-CSRF-Token") != "admin-csrf" || r.Header.Get("Origin") == "" {
			t.Error("missing DELETE/Origin/admin CSRF")
		}
		if cookie, err := r.Cookie("ca_admin"); err != nil || cookie.Value != "admin-session" {
			t.Error("missing admin cookie")
		}
		var in map[string]int64
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in) != 1 || in["version"] != 7 {
			t.Error("explicit revision not sent")
		}
		switch r.URL.Path {
		case "/api/admin/v1/applications/app":
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/api/admin/v1/applications/app/access/members/user":
			_, _ = w.Write([]byte(`{"application_id":"app","policy":{"mode":"open","version":8},"roles":[],"permissions":[]}`))
		default:
			t.Error("unexpected deletion path", r.URL.Path)
		}
	})
	ctx := context.Background()
	if _, err := c.DeleteApplication(ctx, "app", DeletionInput{Version: 7}); err == nil || requests != 0 {
		t.Fatal("deletion sent before admin initialization")
	}
	if _, err := c.AdminLogin(ctx, AdminLoginInput{Username: "admin", Password: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if out, err := c.DeleteApplication(ctx, "app", DeletionInput{Version: 7}); err != nil || !out.Ok {
		t.Fatal(out, err)
	}
	if out, err := c.RemoveApplicationMember(ctx, "app", "user", DeletionInput{Version: 7}); err != nil || out.Policy.Version != 8 {
		t.Fatal(out, err)
	}
	if requests != 2 {
		t.Fatal("deletions retried unexpectedly")
	}
}
