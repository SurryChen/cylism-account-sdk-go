package account

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplicationSessionCacheOnlineLogoutAndFailures(t *testing.T) {
	var calls atomic.Int32
	var state atomic.Int32
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "app" || secret != "secret" || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" {
			t.Error("session endpoint leaked credentials")
		}
		if r.URL.Path == "/api/app/v1/sessions/logout" {
			state.Store(401)
			w.WriteHeader(204)
			return
		}
		if r.URL.Path != "/api/app/v1/sessions/verify" {
			t.Error(r.URL.Path)
		}
		calls.Add(1)
		if status := state.Load(); status != 0 {
			w.WriteHeader(int(status))
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "session_expired"}})
			return
		}
		email := "person@example.test"
		_ = json.NewEncoder(w).Encode(ApplicationSessionIdentity{ApplicationID: "app", SessionID: "session", Subject: "user", Email: &email, EmailVerified: true, ExpiresAt: time.Now().Add(time.Hour), AbsoluteExpiresAt: time.Now().Add(2 * time.Hour), ValidUntil: time.Now().Add(time.Minute)})
	})
	ctx := context.Background()
	in := VerifyApplicationSessionInput{Token: strings.Repeat("t", 43)}
	first, err := client.VerifyApplicationSession(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	*first.Email = "changed"
	second, err := client.VerifyApplicationSession(ctx, in)
	if err != nil || *second.Email != "person@example.test" || calls.Load() != 1 {
		t.Fatal("cache missing or mutable", second, err, calls.Load())
	}
	state.Store(503)
	if _, err = client.VerifyApplicationSessionOnline(ctx, in); err == nil || errors.Is(err, ErrUnauthenticated) {
		t.Fatal("temporary fault treated as revoked identity", err)
	}
	state.Store(0)
	if _, err = client.VerifyApplicationSession(ctx, in); err != nil {
		t.Fatal("temporary fault prevented recovery", err)
	}
	if err = client.LogoutApplicationSession(ctx, LogoutApplicationSessionInput{Token: in.Token}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.VerifyApplicationSession(ctx, in); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("logout retained cached identity", err)
	}
}
func TestApplicationSessionRejectsMissingOrInvalidLifetime(t *testing.T) {
	for _, out := range []ApplicationSessionIdentity{
		{Subject: "user"},
		{ApplicationID: "app", SessionID: "session", Subject: "user", ExpiresAt: time.Now().Add(time.Hour), AbsoluteExpiresAt: time.Now().Add(2 * time.Hour)},
		{ApplicationID: "app", SessionID: "session", Subject: "user", ExpiresAt: time.Now().Add(time.Hour), AbsoluteExpiresAt: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Minute)},
	} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(out) })
		if _, err := c.VerifyApplicationSession(context.Background(), VerifyApplicationSessionInput{Token: strings.Repeat("t", 43)}); !errors.Is(err, ErrInvalidResponse) {
			t.Fatal("unbounded identity accepted", err)
		}
	}
}
