package account

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestActivityCoalescesAndNeverRefreshesInBackground(t *testing.T) {
	var calls atomic.Int32
	var verifies atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/app/v1/sessions/renew" {
			calls.Add(1)
		} else if r.URL.Path == "/api/app/v1/sessions/verify" {
			verifies.Add(1)
		} else {
			t.Error(r.URL.Path)
		}
		renew := time.Now().Add(5 * time.Minute)
		cookie := time.Now().Add(30 * 24 * time.Hour)
		next := strings.Repeat("n", 43)
		_ = json.NewEncoder(w).Encode(ApplicationSessionIdentity{ApplicationID: "app", SessionID: "session", Subject: "user", ExpiresAt: cookie, AbsoluteExpiresAt: cookie.Add(time.Hour), ValidUntil: time.Now().Add(time.Minute), CookieExpiresAt: &cookie, RenewAfter: &renew, Token: &next})
	})
	in := RenewApplicationSessionInput{Token: strings.Repeat("a", 43)}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, e := c.RenewApplicationSession(context.Background(), in)
			if e != nil {
				t.Error(e)
				return
			}
			*out.Token = "changed"
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("activity not coalesced", calls.Load())
	}
	c.cache.refreshDue(time.Now().Add(time.Minute))
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("background renewed user activity")
	}
	out, e := c.RenewApplicationSession(context.Background(), in)
	if e != nil || *out.Token != strings.Repeat("n", 43) {
		t.Fatal("mutable activity credential", e)
	}
	// A new SDK instance has no local timestamp and can safely report again.
	c.cache.clear()
	_, e = c.RenewApplicationSession(context.Background(), in)
	if e != nil || calls.Load() != 2 {
		t.Fatal("activity restart recovery", e, calls.Load())
	}
}
func TestActivityFailureNeverCreatesLocalRenewal(t *testing.T) {
	var calls atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) })
	in := RenewApplicationSessionInput{Token: strings.Repeat("a", 43)}
	for i := 0; i < 2; i++ {
		if _, e := c.RenewApplicationSession(context.Background(), in); e == nil {
			t.Fatal("failed renewal accepted")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("failed activity cached as successful")
	}
}

func TestActivityReceiptCannotBypassFreshRevocation(t *testing.T) {
	var revoked atomic.Bool
	var renewals atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/app/v1/sessions/verify" && revoked.Load() {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"code":"session_expired"}}`))
			return
		}
		if r.URL.Path == "/api/app/v1/sessions/renew" {
			renewals.Add(1)
		}
		next := time.Now().Add(5 * time.Minute)
		expires := time.Now().Add(time.Hour)
		json.NewEncoder(w).Encode(ApplicationSessionIdentity{Subject: "user", ApplicationID: "app", SessionID: "session", ExpiresAt: expires, AbsoluteExpiresAt: expires.Add(time.Hour), ValidUntil: time.Now().Add(time.Minute), CookieExpiresAt: &expires, RenewAfter: &next})
	})
	in := RenewApplicationSessionInput{Token: strings.Repeat("a", 43)}
	if _, e := c.RenewApplicationSession(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	revoked.Store(true)
	c.cache.forget(tokenCacheKey("application-session", in.Token))
	if _, e := c.RenewApplicationSession(context.Background(), in); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("cached renewal bypassed revoked identity", e)
	}
	if renewals.Load() != 1 {
		t.Fatal("revoked identity triggered another renewal")
	}
}
