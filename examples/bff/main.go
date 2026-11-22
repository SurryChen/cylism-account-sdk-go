// A single-process local BFF example. Tokens never enter the browser. Replace
// the bounded in-memory store with transactional shared storage before scaling.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	account "github.com/SurryChen/cylism-account-sdk-go"
	"golang.org/x/oauth2"
)

type session struct {
	profile account.Profile
	tokens  *account.TokenSession
	csrf    string
	expires time.Time
}
type flow struct {
	transaction account.LoginTransaction
	expires     time.Time
}
type application struct {
	client   *account.Client
	oidc     *account.OIDC
	origin   string
	mu       sync.Mutex
	sessions map[string]*session
	flows    map[string]flow
}

func main() {
	issuer, id, secret := os.Getenv("ACCOUNT_ISSUER"), os.Getenv("ACCOUNT_CLIENT_ID"), os.Getenv("ACCOUNT_CLIENT_SECRET")
	if issuer == "" || id == "" || secret == "" {
		log.Fatal("Set ACCOUNT_ISSUER, ACCOUNT_CLIENT_ID and ACCOUNT_CLIENT_SECRET")
	}
	client, err := account.New(account.Config{BaseURL: issuer, ClientID: id, ClientSecret: secret, AllowInsecureLoopback: true})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	oidc, err := client.DiscoverOIDC(ctx, "http://127.0.0.1:18108/auth/callback", "openid", "profile", "email", "offline_access")
	cancel()
	if err != nil {
		log.Fatal(err)
	}
	app := &application{client: client, oidc: oidc, origin: "http://127.0.0.1:18108", sessions: map[string]*session{}, flows: map[string]flow{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", app.login)
	mux.HandleFunc("GET /auth/callback", app.callback)
	mux.HandleFunc("GET /api/me", app.me)
	mux.HandleFunc("POST /api/logout", app.logout)
	mux.Handle("GET /api/orders", app.authenticate(client.RequirePermission("orders:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"items": []string{"SDK demo order"}})
	}))))
	webDir := os.Getenv("SDK_WEB_DIR")
	if webDir == "" {
		webDir = "examples/vue/dist"
	}
	mux.Handle("/", http.FileServer(http.Dir(webDir)))
	listener, err := net.Listen("tcp", "127.0.0.1:18108")
	if err != nil {
		log.Fatal(err)
	}
	log.Print("SDK demo: http://127.0.0.1:18108 (single-process, local development)")
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Fatal(server.Serve(listener))
}
func random() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func (a *application) cleanup() { // Caller holds mu; all stores are bounded.
	now := time.Now()
	for k, v := range a.flows {
		if !v.expires.After(now) {
			delete(a.flows, k)
		}
	}
	for k, v := range a.sessions {
		if !v.expires.After(now) {
			delete(a.sessions, k)
		}
	}
}
func (a *application) login(w http.ResponseWriter, r *http.Request) {
	destination, tx, err := a.oidc.BeginLogin(account.LoginOptions{Provider: r.URL.Query().Get("provider")})
	if err != nil {
		respond(w, 400, map[string]string{"error": "invalid_login"})
		return
	}
	binding := random()
	a.mu.Lock()
	a.cleanup()
	if len(a.flows) >= 1000 {
		a.mu.Unlock()
		respond(w, 503, map[string]string{"error": "too_many_login_flows"})
		return
	}
	a.flows[binding] = flow{tx, time.Now().Add(10 * time.Minute)}
	a.mu.Unlock()
	cookie(w, "sdk_login", binding, 600)
	http.Redirect(w, r, destination, http.StatusFound)
}
func (a *application) callback(w http.ResponseWriter, r *http.Request) {
	bound, err := r.Cookie("sdk_login")
	if err != nil {
		respond(w, 400, map[string]string{"error": "login_expired"})
		return
	}
	a.mu.Lock()
	pending, ok := a.flows[bound.Value]
	delete(a.flows, bound.Value)
	a.cleanup()
	a.mu.Unlock()
	cookie(w, "sdk_login", "", -1)
	if !ok || !pending.expires.After(time.Now()) {
		respond(w, 400, map[string]string{"error": "login_expired"})
		return
	}
	result, err := a.oidc.CompleteLogin(r.Context(), r.URL.Query(), pending.transaction)
	if err != nil {
		respond(w, 401, map[string]string{"error": "login_failed"})
		return
	}
	token := random()
	s := &session{result.Profile, account.NewTokenSession(result.Tokens, result.Profile.Subject), random(), time.Now().Add(8 * time.Hour)}
	a.mu.Lock()
	a.cleanup()
	if len(a.sessions) >= 1000 {
		a.mu.Unlock()
		_ = a.client.Revoke(r.Context(), result.Tokens.AccessToken)
		respond(w, 503, map[string]string{"error": "session_limit"})
		return
	}
	if old, e := r.Cookie("sdk_session"); e == nil {
		delete(a.sessions, old.Value)
	}
	a.sessions[token] = s
	a.mu.Unlock()
	cookie(w, "sdk_session", token, 8*3600)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *application) current(r *http.Request) (string, *session) {
	c, err := r.Cookie("sdk_session")
	if err != nil {
		return "", nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanup()
	return c.Value, a.sessions[c.Value]
}
func (a *application) authenticated(r *http.Request) (*http.Request, error) {
	id, s := a.current(r)
	if s == nil {
		return r, account.ErrUnauthenticated
	}
	tokens, err := s.tokens.Token(r.Context(), a.oidc, func(context.Context, *oauth2.Token) error { return nil }) // TokenSession owns this example's in-memory token state.
	if err != nil {
		a.mu.Lock()
		delete(a.sessions, id)
		a.mu.Unlock()
		return r, err
	}
	introspection, err := a.client.Introspect(r.Context(), tokens.AccessToken)
	if err != nil {
		return r, err
	}
	if introspection.Subject != s.profile.Subject {
		return r, account.ErrUnauthenticated
	}
	return r.WithContext(account.WithPrincipal(r.Context(), account.Principal{Subject: introspection.Subject})), nil
}
func (a *application) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verified, err := a.authenticated(r)
		if err != nil {
			status := 503
			if errors.Is(err, account.ErrUnauthenticated) {
				status = 401
			}
			respond(w, status, map[string]string{"error": "authentication_failed"})
			return
		}
		next.ServeHTTP(w, verified)
	})
}
func (a *application) me(w http.ResponseWriter, r *http.Request) {
	a.authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, s := a.current(r)
		if s == nil {
			respond(w, 401, map[string]string{"error": "login_required"})
			return
		}
		entitlements, err := a.client.ApplicationEntitlements(r.Context(), s.profile.Subject)
		if err != nil {
			respond(w, 503, map[string]string{"error": "access_unavailable"})
			return
		}
		respond(w, 200, map[string]any{"profile": s.profile, "access": entitlements, "csrf_token": s.csrf})
	})).ServeHTTP(w, r)
}
func (a *application) logout(w http.ResponseWriter, r *http.Request) {
	id, s := a.current(r)
	if s == nil {
		cookie(w, "sdk_session", "", -1)
		w.WriteHeader(204)
		return
	}
	if r.Header.Get("Origin") != a.origin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrf)) != 1 {
		respond(w, 403, map[string]string{"error": "csrf_failed"})
		return
	}
	// Removing the local session always logs out this application, including when
	// Account is temporarily unreachable. Remote revocation remains best effort.
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
	cookie(w, "sdk_session", "", -1)
	tokens, err := s.tokens.Token(r.Context(), a.oidc, func(context.Context, *oauth2.Token) error { return nil })
	if err == nil {
		_ = a.client.Revoke(r.Context(), tokens.AccessToken)
		if tokens.RefreshToken != "" {
			_ = a.client.Revoke(r.Context(), tokens.RefreshToken)
		}
	}
	w.WriteHeader(204)
}
