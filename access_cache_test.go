package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func snapshotJSON(subject, permission string) string {
	out := AccessEntitlements{ApplicationID: "application", Subject: subject, Status: "active", Roles: []string{"member"}, Permissions: []EffectivePermission{}, Version: 1, ValidUntil: time.Now().Add(time.Minute)}
	if permission != "" {
		out.Permissions = append(out.Permissions, EffectivePermission{Key: permission, Sources: []string{"direct"}})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func cachedTestClient(t *testing.T, config CacheConfig, handler http.HandlerFunc) *Client {
	t.Helper()
	host := httptest.NewServer(handler)
	t.Cleanup(host.Close)
	c, err := New(Config{BaseURL: host.URL, ClientID: "app", ClientSecret: "secret", AllowInsecureLoopback: true, Cache: config})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached before deadline")
}

func TestDefaultMiddlewareCachesBothIdentityAndPermissions(t *testing.T) {
	var identityCalls, permissionCalls atomic.Int64
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/introspect" {
			identityCalls.Add(1)
			_ = json.NewEncoder(w).Encode(Introspection{Active: true, Subject: "user", ClientID: "app", Audience: json.RawMessage(`["app"]`), ExpiresAt: time.Now().Add(time.Hour).Unix()})
		} else if r.URL.Path == "/api/app/v1/access/users/user" {
			permissionCalls.Add(1)
			fmt.Fprint(w, snapshotJSON("user", "orders:read"))
		} else {
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	handler := c.AuthenticateBearer(c.RequirePermission("orders:read")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })))
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest("GET", "/orders", nil)
		r.Header.Set("Authorization", "Bearer opaque-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if identityCalls.Load() != 1 || permissionCalls.Load() != 1 {
		t.Fatal("cache miss", identityCalls.Load(), permissionCalls.Load())
	}
}

func TestCacheCoalescesMissesAndCopiesSnapshots(t *testing.T) {
	var calls atomic.Int64
	entered, release := make(chan struct{}), make(chan struct{})
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		fmt.Fprint(w, snapshotJSON(strings.TrimPrefix(r.URL.Path, "/api/app/v1/access/users/"), "orders:read"))
	})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, err := c.Can(context.Background(), "user", "orders", "read")
			if err != nil || !allowed {
				t.Error(allowed, err)
			}
		}()
	}
	<-entered
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate lookup", calls.Load())
	}
	out, err := c.ApplicationEntitlements(context.Background(), "user")
	if err != nil {
		t.Fatal(err)
	}
	out.Permissions[0].Key = "orders:write"
	out.Permissions[0].Sources[0] = "mutated"
	out.Roles[0] = "admin"
	again, err := c.ApplicationEntitlements(context.Background(), "user")
	if err != nil || again.HasPermission("orders:write") || again.HasRole("admin") || again.Permissions[0].Sources[0] != "direct" {
		t.Fatal("caller mutated shared snapshot", err)
	}
	if ok, err := c.Can(context.Background(), "other", "orders", "read"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if calls.Load() != 2 {
		t.Fatal("users shared a cache entry")
	}
}

func TestBackgroundRefreshWithoutRequestsAndIdleEviction(t *testing.T) {
	var calls atomic.Int64
	var allow atomic.Bool
	allow.Store(true)
	c := cachedTestClient(t, CacheConfig{TTL: time.Second, RefreshInterval: 20 * time.Millisecond, IdleTimeout: 200 * time.Millisecond}, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		permission := ""
		if allow.Load() {
			permission = "orders:read"
		}
		fmt.Fprint(w, snapshotJSON("user", permission))
	})
	if ok, err := c.Can(context.Background(), "user", "orders", "read"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	allow.Store(false)
	// Observe the cache itself: no business call is allowed to trigger refresh.
	eventually(t, func() bool {
		c.cache.mu.Lock()
		defer c.cache.mu.Unlock()
		e := c.cache.entries[cacheKey{"permissions", "user"}]
		return e != nil && e.value != nil && !e.value.(AccessEntitlements).HasPermission("orders:read")
	})
	eventually(t, func() bool { c.cache.mu.Lock(); defer c.cache.mu.Unlock(); return len(c.cache.entries) == 0 })
	count := calls.Load()
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != count {
		t.Fatal("polling continued for an idle user")
	}
	if ok, err := c.Can(context.Background(), "user", "orders", "read"); err != nil || ok {
		t.Fatal(ok, err)
	}
	if calls.Load() <= count {
		t.Fatal("returning user did not reload")
	}
}

func TestRefreshFailureDoesNotExtendLeaseAndDenialClearsAllow(t *testing.T) {
	for _, status := range []int{503, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var failure atomic.Bool
			c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				if failure.Load() {
					w.WriteHeader(status)
					fmt.Fprint(w, `{"error":{"code":"application_access_denied"}}`)
					return
				}
				fmt.Fprint(w, snapshotJSON("user", "orders:read"))
			})
			if ok, err := c.Can(context.Background(), "user", "orders", "read"); err != nil || !ok {
				t.Fatal(ok, err)
			}
			failure.Store(true)
			key := cacheKey{"permissions", "user"}
			c.cache.mu.Lock()
			e := c.cache.entries[key]
			until := e.expires
			e.nextRefresh = time.Time{}
			c.cache.mu.Unlock()
			c.cache.refreshDue(time.Now())
			eventually(t, func() bool {
				c.cache.mu.Lock()
				defer c.cache.mu.Unlock()
				return e.flight == nil && !e.nextRefresh.IsZero()
			})
			if status == 503 {
				c.cache.mu.Lock()
				if e.expires != until {
					t.Error("failure extended lease")
				}
				c.cache.mu.Unlock()
				if ok, err := c.Can(context.Background(), "user", "orders", "read"); err != nil || !ok {
					t.Fatal("unexpired snapshot lost", ok, err)
				}
				c.cache.mu.Lock()
				e.expires = time.Now().Add(-time.Second)
				c.cache.mu.Unlock()
				if ok, err := c.Can(context.Background(), "user", "orders", "read"); err == nil || ok {
					t.Fatal("expired allow used during outage", ok, err)
				}
			} else {
				c.cache.mu.Lock()
				remains := e.value != nil
				c.cache.mu.Unlock()
				if remains {
					t.Fatal("explicit denial retained old allow")
				}
				if ok, err := c.Can(context.Background(), "user", "orders", "read"); err != nil || ok {
					t.Fatal(ok, err)
				}
			}
		})
	}
}

func TestTokenExpiryRevocationAndBackgroundIntrospection(t *testing.T) {
	var calls atomic.Int64
	var active atomic.Bool
	active.Store(true)
	c := cachedTestClient(t, CacheConfig{RefreshInterval: 20 * time.Millisecond}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/revoke" {
			active.Store(false)
			fmt.Fprint(w, `{}`)
			return
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(Introspection{Active: active.Load(), Subject: "user", ClientID: "app", ExpiresAt: time.Now().Add(time.Hour).Unix(), Audience: json.RawMessage(`["app"]`)})
	})
	out, err := c.Introspect(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	out.Audience[2] = 'x'
	if _, err = c.Introspect(context.Background(), "token"); err != nil {
		t.Fatal("audience mutation poisoned cache", err)
	}
	eventually(t, func() bool { return calls.Load() >= 2 })
	active.Store(false)
	eventually(t, func() bool {
		c.cache.mu.Lock()
		defer c.cache.mu.Unlock()
		e := c.cache.entries[tokenCacheKey("oidc", "token")]
		return e != nil && e.value == nil && e.flight == nil
	})
	if _, err = c.Introspect(context.Background(), "token"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	active.Store(true)
	if _, err = c.Introspect(context.Background(), "other-token"); err != nil {
		t.Fatal(err)
	}
	if err = c.Revoke(context.Background(), "other-token"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Introspect(context.Background(), "other-token"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("local revoke left authentication cached", err)
	}
}

func TestSnapshotAndTokenExpirationAreHardBounds(t *testing.T) {
	for _, kind := range []string{"permissions", "oidc", "password"} {
		t.Run(kind, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				switch kind {
				case "permissions":
					var out AccessEntitlements
					_ = json.Unmarshal([]byte(snapshotJSON("user", "orders:read")), &out)
					out.ValidUntil = time.Now().Add(40 * time.Millisecond)
					_ = json.NewEncoder(w).Encode(out)
				case "oidc":
					_ = json.NewEncoder(w).Encode(Introspection{Active: true, Subject: "user", ClientID: "app", Audience: json.RawMessage(`["app"]`), ExpiresAt: time.Now().Add(2 * time.Second).Unix()})
				case "password":
					_ = json.NewEncoder(w).Encode(PasswordSession{Subject: "user", ExpiresAt: time.Now().Add(40 * time.Millisecond)})
				}
			})
			key := cacheKey{"permissions", "user"}
			var err error
			switch kind {
			case "permissions":
				_, err = c.ApplicationEntitlements(context.Background(), "user")
			case "oidc":
				key = tokenCacheKey("oidc", "token")
				_, err = c.Introspect(context.Background(), "token")
			case "password":
				key = tokenCacheKey("password", "token")
				_, err = c.VerifyPasswordSession(context.Background(), PasswordTokenInput{Token: "token"})
			}
			if err != nil {
				t.Fatal(err)
			}
			c.cache.mu.Lock()
			e := c.cache.entries[key]
			remaining := time.Until(e.expires)
			hardExpiration := e.hardExpires
			c.cache.mu.Unlock()
			if remaining > 2*time.Second {
				t.Fatal("server/token expiry exceeded", remaining)
			}
			if kind != "permissions" {
				c.cache.refreshDue(hardExpiration.Add(time.Millisecond))
				c.cache.mu.Lock()
				_, retained := c.cache.entries[key]
				c.cache.mu.Unlock()
				if retained {
					t.Fatal("expired token remained in refresh pool")
				}
			}
		})
	}
}

func TestInvalidationAndCloseCannotResurrectInflightAllow(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		t.Run(fmt.Sprint(closeClient), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
				}
				fmt.Fprint(w, snapshotJSON("user", "orders:read"))
			})
			result := make(chan error, 1)
			go func() { _, err := c.Can(context.Background(), "user", "orders", "read"); result <- err }()
			<-entered
			want := ErrCacheInvalidated
			if closeClient {
				want = ErrClientClosed
				_ = c.Close()
			} else {
				c.cache.clear()
			}
			close(release)
			if err := <-result; !errors.Is(err, want) {
				t.Fatal("stale in-flight response accepted", err)
			}
			c.cache.mu.Lock()
			size := len(c.cache.entries)
			c.cache.mu.Unlock()
			if size != 0 {
				t.Fatal("invalidated result resurrected")
			}
			if closeClient {
				if _, err := c.Introspect(context.Background(), "token"); !errors.Is(err, ErrClientClosed) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPasswordCacheAndLogout(t *testing.T) {
	var calls atomic.Int64
	var loggedOut atomic.Bool
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/app/v1/password/logout" {
			loggedOut.Store(true)
			w.WriteHeader(204)
			return
		}
		calls.Add(1)
		if loggedOut.Load() {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":{"code":"login_required"}}`)
			return
		}
		_ = json.NewEncoder(w).Encode(PasswordSession{Subject: "user", ExpiresAt: time.Now().Add(time.Hour)})
	})
	input := PasswordTokenInput{Token: "opaque-token"}
	for i := 0; i < 5; i++ {
		if _, err := c.VerifyPasswordSession(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("password verification not cached")
	}
	if err := c.LogoutPasswordSession(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyPasswordSession(context.Background(), input); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("logout did not clear cache", err)
	}
}

func TestOnlineAndDisabledCacheModes(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprint(disabled), func(t *testing.T) {
			var calls atomic.Int64
			c := cachedTestClient(t, CacheConfig{Disabled: disabled}, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == "/access/v1/evaluation" {
					fmt.Fprint(w, `{"decision":true}`)
				} else {
					fmt.Fprint(w, snapshotJSON("user", "orders:read"))
				}
			})
			for i := 0; i < 3; i++ {
				var ok bool
				var err error
				if disabled {
					ok, err = c.Can(context.Background(), "user", "orders", "read")
				} else {
					ok, err = c.CanOnline(context.Background(), "user", "orders", "read")
				}
				if err != nil || !ok {
					t.Fatal(ok, err)
				}
			}
			if calls.Load() != 3 {
				t.Fatal("online check used a cache")
			}
			c.cache.mu.Lock()
			started := c.cache.started
			c.cache.mu.Unlock()
			if started {
				t.Fatal("online mode started a scheduler")
			}
		})
	}
}

func TestCacheConfigAndCapacity(t *testing.T) {
	for _, config := range []CacheConfig{{TTL: -1}, {TTL: 2 * time.Minute}, {RefreshInterval: time.Minute}, {MaxEntries: -1}, {RefreshConcurrency: -1}, {IdleTimeout: -1}} {
		if _, err := New(Config{BaseURL: "https://account.example", Cache: config}); err == nil {
			t.Fatal("invalid cache config accepted", config)
		}
	}
	c := cachedTestClient(t, CacheConfig{MaxEntries: 1}, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, snapshotJSON(strings.TrimPrefix(r.URL.Path, "/api/app/v1/access/users/"), "orders:read"))
	})
	for _, user := range []string{"one", "two"} {
		if _, err := c.ApplicationEntitlements(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	c.cache.mu.Lock()
	size := len(c.cache.entries)
	_, retained := c.cache.entries[cacheKey{"permissions", "two"}]
	c.cache.mu.Unlock()
	if size != 1 || !retained {
		t.Fatal("capacity not enforced")
	}
}

func TestCanceledWaiterDoesNotCancelSharedLookup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		close(entered)
		<-release
		fmt.Fprint(w, snapshotJSON("user", "orders:read"))
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := c.Can(ctx, "user", "orders", "read"); result <- err }()
	<-entered
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if ok, err := c.Can(context.Background(), "user", "orders", "read"); err != nil || !ok {
		t.Fatal("shared lookup canceled by a waiter", ok, err)
	}
	if calls.Load() != 1 {
		t.Fatal("canceled waiter caused duplicate lookup")
	}
}

func TestRefreshConcurrencyAndOverloadAreBounded(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	c := cachedTestClient(t, CacheConfig{MaxEntries: 2, RefreshConcurrency: 1}, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		fmt.Fprint(w, snapshotJSON(strings.TrimPrefix(r.URL.Path, "/api/app/v1/access/users/"), "orders:read"))
	})
	results := make(chan error, 2)
	go func() { _, err := c.ApplicationEntitlements(context.Background(), "one"); results <- err }()
	<-entered
	go func() { _, err := c.ApplicationEntitlements(context.Background(), "two"); results <- err }()
	eventually(t, func() bool { c.cache.mu.Lock(); defer c.cache.mu.Unlock(); return c.cache.inflight == 2 })
	if _, err := c.ApplicationEntitlements(context.Background(), "three"); !errors.Is(err, ErrCacheCapacity) {
		t.Fatal("unbounded lookup admission", err)
	}
	if len(c.cache.slots) != 1 {
		t.Fatal("network concurrency limit not enforced")
	}
	releaseOnce.Do(func() { close(release) })
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestDifferentClientsDoNotShareGrants(t *testing.T) {
	allow := testClient(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, snapshotJSON("user", "orders:read")) })
	deny := testClient(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, snapshotJSON("user", "")) })
	if ok, err := allow.Can(context.Background(), "user", "orders", "read"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := deny.Can(context.Background(), "user", "orders", "read"); err != nil || ok {
		t.Fatal("cross-client grant leak", ok, err)
	}
}

func TestExpiredSnapshotHelpersDeny(t *testing.T) {
	var snapshot AccessEntitlements
	_ = json.Unmarshal([]byte(snapshotJSON("user", "orders:read")), &snapshot)
	snapshot.ValidUntil = time.Now().Add(-time.Second)
	if snapshot.HasPermission("orders:read") || snapshot.HasRole("member") {
		t.Fatal("expired snapshot helper allowed access")
	}
}
