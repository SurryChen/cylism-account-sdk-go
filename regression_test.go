package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Exercise malformed wire responses while retaining the real OAuth/OIDC libraries.
type mutateJSONTransport struct {
	base   http.RoundTripper
	path   string
	mutate func(map[string]any)
}

func (t mutateJSONTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(r)
	if err != nil || r.URL.Path != t.path {
		return res, err
	}
	defer res.Body.Close()
	var body map[string]any
	if err = json.NewDecoder(res.Body).Decode(&body); err != nil {
		return nil, err
	}
	t.mutate(body)
	data, _ := json.Marshal(body)
	res.Body = io.NopCloser(strings.NewReader(string(data)))
	res.ContentLength = int64(len(data))
	res.Header.Del("Content-Length")
	return res, nil
}
func mutateResponses(path string, fn func(map[string]any)) func(*Config) {
	return func(cfg *Config) {
		cfg.HTTPClient = &http.Client{Transport: mutateJSONTransport{http.DefaultTransport, path, fn}}
	}
}
func TestPasswordEmailCodeWireContract(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"message": "若邮箱地址有效，请查收验证码", "expires_in": 600, "retry_after": 60})
	})
	result, err := c.SendPasswordEmailCode(context.Background(), EmailCodeInput{Email: "user@example.test", Purpose: "register"})
	if err != nil || result.Message != "若邮箱地址有效，请查收验证码" || result.ExpiresIn != 600 || result.RetryAfter != 60 {
		t.Fatalf("wrong application response: %+v %v", result, err)
	}
	var browser EmailCodeAccepted
	if err = json.Unmarshal([]byte("{\"ok\":true,\"expires_in\":600,\"retry_after\":60}"), &browser); err != nil || !browser.Ok {
		t.Fatal("browser contract changed", err)
	}
}
func TestOIDCRejectsMalformedAccessTokens(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing-expiry", func(m map[string]any) { delete(m, "expires_in") }},
		{"zero-expiry", func(m map[string]any) { m["expires_in"] = 0 }},
		{"expired", func(m map[string]any) { m["expires_in"] = -60 }},
		{"missing-token-type", func(m map[string]any) { delete(m, "token_type") }},
		{"wrong-token-type", func(m map[string]any) { m["token_type"] = "MAC" }},
		{"missing-access", func(m map[string]any) { delete(m, "access_token") }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newOIDCFixture(t, mutateResponses("/oauth/token", test.mutate))
			callback := f.begin(t)
			if _, err := f.o.CompleteLogin(context.Background(), callback, f.tx); err == nil {
				t.Fatal("invalid login response accepted")
			}
			old := &oauth2.Token{AccessToken: "old-access", TokenType: "Bearer", RefreshToken: "refresh-1", Expiry: time.Now().Add(-time.Hour)}
			if _, err := f.o.Refresh(context.Background(), old, "user-1"); err == nil {
				t.Fatal("invalid refresh accepted")
			}
			session := NewTokenSession(old, "user-1")
			saves := 0
			persist := func(context.Context, *oauth2.Token) error { saves++; return nil }
			if _, err := session.Token(context.Background(), f.o, persist); err == nil || saves != 0 {
				t.Fatal("invalid rotation persisted")
			}
			count := f.refreshes.Load()
			if _, err := session.Token(context.Background(), f.o, persist); !errors.Is(err, ErrUnauthenticated) || count != f.refreshes.Load() {
				t.Fatal("invalid session replayed refresh")
			}
		})
	}
}
func TestTokenSessionRejectsMalformedStoredToken(t *testing.T) {
	for _, kind := range []string{"missing-access", "missing-expiry", "wrong-type"} {
		t.Run(kind, func(t *testing.T) {
			token := &oauth2.Token{AccessToken: "a", TokenType: "Bearer", RefreshToken: "r", Expiry: time.Now().Add(time.Hour)}
			switch kind {
			case "missing-access":
				token.AccessToken = ""
			case "missing-expiry":
				token.Expiry = time.Time{}
			case "wrong-type":
				token.TokenType = "MAC"
			}
			if _, err := NewTokenSession(token, "u").Token(context.Background(), nil, nil); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal(err)
			}
		})
	}
}
func TestConfiguredResponseLimits(t *testing.T) {
	for _, knownLength := range []bool{true, false} {
		t.Run(fmt.Sprint(knownLength), func(t *testing.T) {
			body := "{\"status\":\"ok\",\"padding\":\"" + strings.Repeat("x", 200) + "\"}"
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if !knownLength {
					w.(http.Flusher).Flush()
				}
				io.WriteString(w, body)
			}))
			defer host.Close()
			for _, limit := range []int64{int64(len(body)) - 1, int64(len(body)), int64(len(body)) + 1} {
				c, err := New(Config{BaseURL: host.URL, ClientID: "app", ClientSecret: "secret", AllowInsecureLoopback: true, MaxResponseBytes: limit})
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.HealthLive(context.Background())
				if (err != nil) != (limit < int64(len(body))) {
					t.Fatalf("limit %d: %v", limit, err)
				}
				err = c.Revoke(context.Background(), "token")
				if (err != nil) != (limit < int64(len(body))) {
					t.Fatalf("OAuth form limit %d: %v", limit, err)
				}
			}
		})
	}
	if _, err := New(Config{BaseURL: "https://account.example", MaxResponseBytes: -1}); err == nil {
		t.Fatal("negative limit allowed")
	}
}
func TestOIDCResponseLimitsCoverDependencies(t *testing.T) {
	for _, path := range []string{"/oauth/token", "/oauth/jwks", "/oauth/userinfo"} {
		t.Run(path, func(t *testing.T) {
			f := newOIDCFixture(t, func(c *Config) { c.MaxResponseBytes = 16 << 10 }, mutateResponses(path, func(m map[string]any) { m["padding"] = strings.Repeat("x", 32<<10) }))
			callback := f.begin(t)
			result, err := f.o.CompleteLogin(context.Background(), callback, f.tx)
			if path != "/oauth/userinfo" {
				if err == nil {
					t.Fatal("oversized token/JWKS accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.o.UserInfo(context.Background(), result.Tokens.AccessToken, result.Profile.Subject); err == nil {
				t.Fatal("oversized userinfo accepted")
			}
		})
	}
	var host *httptest.Server
	host = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": host.URL, "authorization_endpoint": host.URL + "/oauth/authorize",
			"token_endpoint": host.URL + "/oauth/token", "jwks_uri": host.URL + "/oauth/jwks",
			"userinfo_endpoint": host.URL + "/oauth/userinfo", "padding": strings.Repeat("x", 1024),
		})
	}))
	defer host.Close()
	for _, limit := range []int64{128, 4096} {
		c, err := New(Config{BaseURL: host.URL, ClientID: "app", MaxResponseBytes: limit, AllowInsecureLoopback: true})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.DiscoverOIDC(context.Background(), "http://localhost/callback")
		if (err != nil) != (limit == 128) {
			t.Fatalf("discovery limit %d: %v", limit, err)
		}
	}
}
func TestDiscoveredOAuthEndpointsAndOverrides(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(fmt.Sprint(override), func(t *testing.T) {
			var host *httptest.Server
			wantIntro, wantRevoke := "/gateway/introspect", "/gateway/revoke"
			if override {
				wantIntro, wantRevoke = "/custom/introspect", "/custom/revoke"
			}
			calls := map[string]int{}
			host = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/.well-known/openid-configuration" {
					json.NewEncoder(w).Encode(map[string]any{"issuer": host.URL, "authorization_endpoint": host.URL + "/oauth/authorize", "token_endpoint": host.URL + "/oauth/token", "jwks_uri": host.URL + "/oauth/jwks", "userinfo_endpoint": host.URL + "/oauth/userinfo", "introspection_endpoint": host.URL + "/gateway/introspect", "revocation_endpoint": host.URL + "/gateway/revoke"})
					return
				}
				id, secret, ok := r.BasicAuth()
				if !ok || id != "app" || secret != "secret" || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" {
					t.Error("credentials or isolation wrong")
				}
				if r.Method != "POST" {
					t.Error("wrong HTTP method")
				}
				r.ParseForm()
				if r.Form.Get("token") != "access" {
					t.Error("missing token")
				}
				calls[r.URL.Path]++
				switch r.URL.Path {
				case wantIntro:
					json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "user-1", "client_id": "app", "exp": time.Now().Add(time.Hour).Unix()})
				case wantRevoke:
					io.WriteString(w, "{}")
				default:
					t.Error("wrong endpoint", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer host.Close()
			cfg := Config{BaseURL: host.URL, ClientID: "app", ClientSecret: "secret", AllowInsecureLoopback: true}
			if override {
				cfg.IntrospectionEndpoint = host.URL + wantIntro
				cfg.RevocationEndpoint = host.URL + wantRevoke
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.DiscoverOIDC(context.Background(), "http://localhost/callback"); err != nil {
				t.Fatal(err)
			}
			if _, err = c.Introspect(context.Background(), "access"); err != nil {
				t.Fatal(err)
			}
			if err = c.Revoke(context.Background(), "access"); err != nil {
				t.Fatal(err)
			}
			if calls[wantIntro] != 1 || calls[wantRevoke] != 1 {
				t.Fatal(calls)
			}
		})
	}
}
func TestOAuthEndpointValidation(t *testing.T) {
	for _, field := range []string{"introspection_endpoint", "revocation_endpoint"} {
		for _, raw := range []string{"https://evil.example/token", "http://account.example/token", "https://user@account.example/token", "https://account.example/token?x=1", "https://account.example/token#x", "/relative"} {
			t.Run(field+raw, func(t *testing.T) {
				cfg := Config{BaseURL: "https://account.example"}
				if field == "introspection_endpoint" {
					cfg.IntrospectionEndpoint = raw
				} else {
					cfg.RevocationEndpoint = raw
				}
				if _, err := New(cfg); err == nil {
					t.Fatal("unsafe override accepted")
				}
				f := newOIDCFixture(t)
				f.o.client.http.Transport = mutateJSONTransport{f.o.client.http.Transport, "/.well-known/openid-configuration", func(m map[string]any) { m[field] = raw }}
				if _, err := f.o.client.DiscoverOIDC(context.Background(), "http://localhost/callback"); err == nil {
					t.Fatal("unsafe discovered endpoint accepted")
				}
			})
		}
	}
}

func TestHTTPClientInjectionPreserved(t *testing.T) {
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	original := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	c, err := New(Config{BaseURL: "https://account.example", HTTPClient: original, MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if original.Transport != transport || original.Jar != nil || original.CheckRedirect != nil || original.Timeout != 12*time.Second {
		t.Fatal("caller HTTPClient mutated")
	}
	if c.http.Timeout != original.Timeout || c.http.Transport.(responseLimitTransport).base != transport {
		t.Fatal("transport or timeout lost")
	}
}
func TestOIDCBearerTypeCaseInsensitive(t *testing.T) {
	f := newOIDCFixture(t, mutateResponses("/oauth/token", func(m map[string]any) { m["token_type"] = "bEaReR" }))
	callback := f.begin(t)
	result, err := f.o.CompleteLogin(context.Background(), callback, f.tx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.o.Refresh(context.Background(), result.Tokens, result.Profile.Subject); err != nil {
		t.Fatal(err)
	}
}
