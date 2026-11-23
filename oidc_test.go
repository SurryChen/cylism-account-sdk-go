package account

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

type oidcFixture struct {
	o         *OIDC
	nonce     string
	subject   string
	issuer    string
	audience  string
	expiry    int64
	badHash   bool
	key       *rsa.PrivateKey
	requests  atomic.Int64
	refreshes atomic.Int64
	tx        LoginTransaction
}

func newOIDCFixture(t *testing.T, options ...func(*Config)) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &oidcFixture{key: key, subject: "user-1", audience: "app", expiry: time.Now().Add(time.Hour).Unix()}
	var host *httptest.Server
	host = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": host.URL, "authorization_endpoint": host.URL + "/oauth/authorize", "token_endpoint": host.URL + "/oauth/token", "jwks_uri": host.URL + "/oauth/jwks", "userinfo_endpoint": host.URL + "/oauth/userinfo", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/oauth/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key", Use: "sig", Algorithm: "RS256"}}})
		case "/oauth/token":
			f.requests.Add(1)
			_ = r.ParseForm()
			id, secret, basic := r.BasicAuth()
			if !basic || id != "app" || secret != "secret" {
				t.Error("token credentials wrong")
			}
			refresh := "refresh-1"
			if r.Form.Get("grant_type") == "refresh_token" {
				f.refreshes.Add(1)
				refresh = "refresh-2"
			} else if r.Form.Get("code_verifier") != f.tx.Verifier {
				t.Error("wrong PKCE verifier")
			}
			access := "access-token"
			sum := sha256.Sum256([]byte(access))
			hash := base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
			if f.badHash {
				hash = "wrong"
			}
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "key"))
			claims, _ := json.Marshal(map[string]any{"iss": f.issuer, "sub": f.subject, "aud": f.audience, "exp": f.expiry, "iat": time.Now().Unix(), "nonce": f.nonce, "at_hash": hash, "name": "SDK User"})
			signed, _ := signer.Sign(claims)
			raw, _ := signed.CompactSerialize()
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "token_type": "Bearer", "refresh_token": refresh, "expires_in": 300, "id_token": raw})
		case "/oauth/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": f.subject, "name": "SDK User"})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(host.Close)
	f.issuer = host.URL
	cfg := Config{BaseURL: host.URL, ClientID: "app", ClientSecret: "secret", AllowInsecureLoopback: true}
	for _, option := range options {
		option(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	f.o, err = c.DiscoverOIDC(context.Background(), "http://localhost:18099/callback", "openid", "profile", "offline_access")
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *oidcFixture) begin(t *testing.T) url.Values {
	t.Helper()
	login, tx, err := f.o.BeginLogin(LoginOptions{Provider: "google"})
	if err != nil {
		t.Fatal(err)
	}
	f.tx = tx
	f.nonce = tx.Nonce
	u, _ := url.Parse(login)
	q := u.Query()
	if q.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(tx.Verifier) || q.Get("code_challenge_method") != "S256" || q.Get("nonce") != tx.Nonce || q.Get("provider") != "google" {
		t.Fatal("PKCE/nonce/provider missing")
	}
	return url.Values{"state": {tx.State}, "code": {"single-use-code"}}
}
func TestOIDCLoginAndUserinfo(t *testing.T) {
	f := newOIDCFixture(t)
	callback := f.begin(t)
	result, err := f.o.CompleteLogin(context.Background(), callback, f.tx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Subject != "user-1" || result.Tokens.RefreshToken != "refresh-1" {
		t.Fatal("wrong login result")
	}
	profile, err := f.o.UserInfo(context.Background(), result.Tokens.AccessToken, result.Profile.Subject)
	if err != nil || profile.Name != "SDK User" {
		t.Fatal(profile, err)
	}
	if _, err = f.o.UserInfo(context.Background(), result.Tokens.AccessToken, "different-user"); err == nil {
		t.Fatal("userinfo subject mismatch allowed")
	}
}
func TestOIDCRejectsInvalidCallbackBeforeExchange(t *testing.T) {
	f := newOIDCFixture(t)
	for _, test := range []string{"wrong-state", "duplicate-state", "expired", "future", "denied", "missing-code"} {
		t.Run(test, func(t *testing.T) {
			callback := f.begin(t)
			tx := f.tx
			switch test {
			case "wrong-state":
				callback.Set("state", "wrong")
			case "duplicate-state":
				callback.Add("state", tx.State)
			case "expired":
				tx.CreatedAt = time.Now().Add(-11 * time.Minute)
			case "future":
				tx.CreatedAt = time.Now().Add(time.Hour)
			case "denied":
				callback.Set("error", "access_denied")
			case "missing-code":
				callback.Del("code")
			}
			if _, err := f.o.CompleteLogin(context.Background(), callback, tx); err == nil {
				t.Fatal("invalid callback accepted")
			}
		})
	}
	if f.requests.Load() != 0 {
		t.Fatal("exchanged before callback validation")
	}
}
func TestOIDCRejectsInvalidTokens(t *testing.T) {
	for _, test := range []string{"nonce", "audience", "issuer", "expired", "hash", "subject"} {
		t.Run(test, func(t *testing.T) {
			f := newOIDCFixture(t)
			callback := f.begin(t)
			switch test {
			case "nonce":
				f.nonce = "wrong"
			case "audience":
				f.audience = "other"
			case "issuer":
				f.issuer = "https://evil.invalid"
			case "expired":
				f.expiry = time.Now().Add(-time.Hour).Unix()
			case "hash":
				f.badHash = true
			case "subject":
				f.subject = ""
			}
			if _, err := f.o.CompleteLogin(context.Background(), callback, f.tx); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
}
func TestTokenSessionSerializesRefreshAndInvalidatesOnSaveFailure(t *testing.T) {
	f := newOIDCFixture(t)
	callback := f.begin(t)
	login, err := f.o.CompleteLogin(context.Background(), callback, f.tx)
	if err != nil {
		t.Fatal(err)
	}
	login.Tokens.Expiry = time.Now().Add(-time.Hour)
	session := NewTokenSession(login.Tokens, login.Profile.Subject)
	var wg sync.WaitGroup
	var saves atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, e := session.Token(context.Background(), f.o, func(context.Context, *oauth2.Token) error { saves.Add(1); return nil })
			if e != nil || token.RefreshToken != "refresh-2" {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if saves.Load() != 1 || f.refreshes.Load() != 1 {
		t.Fatal("refresh was not serialized")
	}
	broken := NewTokenSession(login.Tokens, login.Profile.Subject)
	_, err = broken.Token(context.Background(), f.o, func(context.Context, *oauth2.Token) error { return errors.New("store unavailable") })
	if err == nil {
		t.Fatal("save failure ignored")
	}
	previous := f.refreshes.Load()
	if _, err = broken.Token(context.Background(), f.o, func(context.Context, *oauth2.Token) error { return nil }); !errors.Is(err, ErrUnauthenticated) || previous != f.refreshes.Load() {
		t.Fatal("old refresh token replayed")
	}
}
func TestProviderValidation(t *testing.T) {
	f := newOIDCFixture(t)
	for _, provider := range []string{"https://evil.invalid", "../google", "", "Google"} {
		_, _, err := f.o.BeginLogin(LoginOptions{Provider: provider})
		if provider != "" && err == nil {
			t.Fatal("invalid provider accepted")
		}
	}
}

// Developers can use a registered loopback callback with an HTTPS Account
// issuer only when they explicitly opt into local development.
func TestHTTPSIssuerLoopbackCallback(t *testing.T) {
	var host *httptest.Server
	host = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": host.URL, "authorization_endpoint": host.URL + "/oauth/authorize", "token_endpoint": host.URL + "/oauth/token", "jwks_uri": host.URL + "/oauth/jwks", "userinfo_endpoint": host.URL + "/oauth/userinfo", "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	defer host.Close()
	for _, allow := range []bool{false, true} {
		c, err := New(Config{BaseURL: host.URL, ClientID: "app", ClientSecret: "secret", HTTPClient: host.Client(), AllowInsecureLoopback: allow})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.DiscoverOIDC(context.Background(), "http://127.0.0.1:18108/auth/callback")
		if (err == nil) != allow {
			t.Fatalf("loopback callback opt-in %v: %v", allow, err)
		}
		if _, err = c.DiscoverOIDC(context.Background(), "http://remote.example/callback"); err == nil {
			t.Fatal("insecure remote callback accepted")
		}
	}
}
