package account

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type LoginOptions struct {
	Provider string
	Scopes   []string
}

// LoginTransaction is secret server state. Bind it to the initiating browser and
// atomically consume it once before CompleteLogin, including failed callbacks.
type LoginTransaction struct {
	State, Nonce, Verifier string
	CreatedAt              time.Time
}
type Profile struct {
	Subject       string `json:"sub"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
}
type LoginResult struct {
	Tokens  *oauth2.Token
	Profile Profile
	IDToken string
}
type OIDC struct {
	client   *Client
	provider *oidc.Provider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func (c *Client) DiscoverOIDC(ctx context.Context, redirectURI string, scopes ...string) (*OIDC, error) {
	if c.clientID == "" {
		return nil, errors.New("account: ClientID required")
	}
	callback, err := validateURL(redirectURI, c.allowInsecureLoopback)
	if err != nil || callback.RawQuery != "" {
		return nil, errors.New("account: invalid redirect URI")
	}
	ctx = oidc.ClientContext(ctx, c.http)
	provider, err := oidc.NewProvider(ctx, c.base.String())
	if err != nil {
		return nil, errors.New("account: OIDC discovery failed")
	}
	var metadata struct {
		JWKS          string `json:"jwks_uri"`
		Introspection string `json:"introspection_endpoint"`
		Revocation    string `json:"revocation_endpoint"`
		Userinfo      string `json:"userinfo_endpoint"`
	}
	if provider.Claims(&metadata) != nil {
		return nil, ErrInvalidResponse
	}
	endpoint := provider.Endpoint()
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL, metadata.JWKS, metadata.Userinfo} {
		u, e := validateURL(raw, c.base.Scheme == "http")
		if e != nil || u.Scheme != c.base.Scheme || u.Host != c.base.Host {
			return nil, errors.New("account: OIDC endpoints must use Account origin")
		}
	}
	introspection, err := sameOriginEndpoint(c.base, metadata.Introspection, "/oauth/introspect")
	if err != nil {
		return nil, err
	}
	revocation, err := sameOriginEndpoint(c.base, metadata.Revocation, "/oauth/revoke")
	if err != nil {
		return nil, err
	}
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	if c.clientSecret == "" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	if !contains(scopes, "openid") {
		return nil, errors.New("account: openid scope required")
	}
	c.mu.Lock()
	if !c.introspectionOverride {
		c.introspectionEndpoint = introspection
	}
	if !c.revocationOverride {
		c.revocationEndpoint = revocation
	}
	c.mu.Unlock()
	return &OIDC{client: c, provider: provider, oauth: oauth2.Config{ClientID: c.clientID, ClientSecret: c.clientSecret, RedirectURL: redirectURI, Scopes: append([]string{}, scopes...), Endpoint: endpoint}, verifier: provider.Verifier(&oidc.Config{ClientID: c.clientID, SupportedSigningAlgs: []string{"RS256"}})}, nil
}

var providerKey = regexp.MustCompile("^[a-z][a-z0-9-]{1,63}$")

func (o *OIDC) BeginLogin(options LoginOptions) (string, LoginTransaction, error) {
	if options.Provider != "" && !providerKey.MatchString(options.Provider) {
		return "", LoginTransaction{}, errors.New("account: invalid provider key")
	}
	tx := LoginTransaction{State: randomValue(), Nonce: randomValue(), Verifier: oauth2.GenerateVerifier(), CreatedAt: time.Now()}
	config := o.oauth
	if len(options.Scopes) > 0 {
		if !contains(options.Scopes, "openid") {
			return "", LoginTransaction{}, errors.New("account: openid scope required")
		}
		for _, s := range options.Scopes {
			if !contains(o.oauth.Scopes, s) {
				return "", LoginTransaction{}, errors.New("account: scope not configured")
			}
		}
		config.Scopes = append([]string{}, options.Scopes...)
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(tx.Nonce), oauth2.S256ChallengeOption(tx.Verifier)}
	if options.Provider != "" {
		opts = append(opts, oauth2.SetAuthURLParam("provider", options.Provider))
	}
	return config.AuthCodeURL(tx.State, opts...), tx, nil
}

// CompleteLogin validates state before exchanging the code. The caller must
// atomically consume a browser-bound transaction before invoking this method.
func (o *OIDC) CompleteLogin(ctx context.Context, callback url.Values, tx LoginTransaction) (*LoginResult, error) {
	if len(callback["state"]) != 1 || tx.State == "" || subtle.ConstantTimeCompare([]byte(callback.Get("state")), []byte(tx.State)) != 1 || tx.Nonce == "" || len(tx.Verifier) < 43 || tx.CreatedAt.IsZero() || time.Since(tx.CreatedAt) > 10*time.Minute || tx.CreatedAt.After(time.Now().Add(time.Minute)) {
		return nil, errors.New("account: invalid or expired login transaction")
	}
	if callback.Get("error") != "" {
		return nil, &APIError{StatusCode: 400, Code: "authorization_denied"}
	}
	if len(callback["code"]) != 1 || callback.Get("code") == "" {
		return nil, errors.New("account: authorization code required")
	}
	ctx = oidc.ClientContext(ctx, o.client.http)
	tokens, err := o.oauth.Exchange(ctx, callback.Get("code"), oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		return nil, safeOAuthError(err)
	}
	if err := validateAccessToken(tokens); err != nil {
		return nil, err
	}
	raw, _ := tokens.Extra("id_token").(string)
	profile, err := o.verifyID(ctx, raw, tokens.AccessToken, tx.Nonce, "")
	if err != nil {
		return nil, err
	}
	return &LoginResult{Tokens: tokens, Profile: profile, IDToken: raw}, nil
}
func (o *OIDC) verifyID(ctx context.Context, raw, access, nonce, subject string) (Profile, error) {
	var profile Profile
	if raw == "" {
		return profile, errors.New("account: missing ID token")
	}
	token, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return profile, errors.New("account: invalid ID token")
	}
	if token.Subject == "" || (nonce != "" && subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(nonce)) != 1) || (subject != "" && token.Subject != subject) {
		return profile, errors.New("account: token identity mismatch")
	}
	var extra struct {
		AuthorizedParty string `json:"azp"`
	}
	if token.Claims(&extra) != nil || (len(token.Audience) > 1 && extra.AuthorizedParty != o.client.clientID) || (extra.AuthorizedParty != "" && extra.AuthorizedParty != o.client.clientID) {
		return profile, errors.New("account: invalid authorized party")
	}
	if access == "" || (token.AccessTokenHash != "" && token.VerifyAccessToken(access) != nil) {
		return profile, errors.New("account: invalid access token hash")
	}
	if token.Claims(&profile) != nil {
		return profile, ErrInvalidResponse
	}
	return profile, nil
}

// Refresh must be serialized and persisted atomically per application session.
// Network and persistence failures require a new login: never replay the old token.
func (o *OIDC) Refresh(ctx context.Context, current *oauth2.Token, subject string) (*oauth2.Token, error) {
	if current == nil || current.RefreshToken == "" || subject == "" {
		return nil, errors.New("account: refresh token and verified subject required")
	}
	old := *current
	old.Expiry = time.Now().Add(-time.Hour)
	token, err := o.oauth.TokenSource(oidc.ClientContext(ctx, o.client.http), &old).Token()
	if err != nil {
		return nil, safeOAuthError(err)
	}
	if err := validateAccessToken(token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" || token.RefreshToken == "" || token.RefreshToken == current.RefreshToken {
		return nil, errors.New("account: refresh rotation missing")
	}
	if raw, ok := token.Extra("id_token").(string); ok && raw != "" {
		if _, err = o.verifyID(ctx, raw, token.AccessToken, "", subject); err != nil {
			return nil, err
		}
	}
	return token, nil
}

// TokenSession serializes refresh in one process. Distributed deployments must
// use a shared session store with a lock/transaction around refresh and persistence.
type TokenSession struct {
	mu      sync.Mutex
	token   *oauth2.Token
	subject string
	invalid bool
}

func NewTokenSession(token *oauth2.Token, subject string) *TokenSession {
	var copyToken *oauth2.Token
	if token != nil {
		v := *token
		copyToken = &v
	}
	return &TokenSession{token: copyToken, subject: subject}
}
func (s *TokenSession) Token(ctx context.Context, o *OIDC, persist func(context.Context, *oauth2.Token) error) (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invalid || s.token == nil || s.subject == "" {
		return nil, ErrUnauthenticated
	}
	if s.token.AccessToken == "" || !strings.EqualFold(s.token.TokenType, "Bearer") || s.token.Expiry.IsZero() {
		s.invalid = true
		return nil, ErrUnauthenticated
	}
	if time.Until(s.token.Expiry) < 30*time.Second {
		if persist == nil {
			return nil, errors.New("account: refresh persistence callback required")
		}
		next, err := o.Refresh(ctx, s.token, s.subject)
		if err != nil {
			s.invalid = true
			return nil, err
		}
		if err := validateAccessToken(next); err != nil {
			s.invalid = true
			return nil, err
		}
		if persist(ctx, next) != nil {
			s.invalid = true
			return nil, errors.New("account: rotated token persistence failed; re-login required")
		}
		s.token = next
	}
	if err := validateAccessToken(s.token); err != nil {
		s.invalid = true
		return nil, err
	}
	copyToken := *s.token
	return &copyToken, nil
}
func (o *OIDC) UserInfo(ctx context.Context, accessToken, subject string) (Profile, error) {
	var out Profile
	if accessToken == "" || subject == "" {
		return out, ErrUnauthenticated
	}
	info, err := o.provider.UserInfo(oidc.ClientContext(ctx, o.client.http), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken, TokenType: "Bearer"}))
	if err != nil {
		return out, errors.New("account: userinfo failed")
	}
	if info.Subject != subject {
		return out, errors.New("account: userinfo subject mismatch")
	}
	if info.Claims(&out) != nil {
		return out, ErrInvalidResponse
	}
	return out, nil
}

type Introspection struct {
	Active    bool            `json:"active"`
	Subject   string          `json:"sub"`
	ClientID  string          `json:"client_id"`
	Audience  json.RawMessage `json:"aud"`
	ExpiresAt int64           `json:"exp"`
	Scope     string          `json:"scope"`
	TokenType string          `json:"token_type"`
}

func (c *Client) Introspect(ctx context.Context, token string) (Introspection, error) {
	if token == "" {
		return Introspection{}, ErrUnauthenticated
	}
	value, err := c.cache.get(ctx, tokenCacheKey("oidc", token), func(ctx context.Context) (any, time.Time, error) {
		out, err := c.introspect(ctx, token)
		return out, time.Unix(out.ExpiresAt, 0), err
	})
	if err != nil {
		return Introspection{}, err
	}
	out := value.(Introspection)
	out.Audience = append(json.RawMessage(nil), out.Audience...)
	return out, nil
}

// IntrospectOnline bypasses cached authentication, including revocation checks.
func (c *Client) IntrospectOnline(ctx context.Context, token string) (Introspection, error) {
	c.cache.forget(tokenCacheKey("oidc", token))
	defer c.cache.forget(tokenCacheKey("oidc", token))
	return c.introspect(ctx, token)
}

func (c *Client) introspect(ctx context.Context, token string) (Introspection, error) {
	var out Introspection
	c.mu.RLock()
	endpoint := c.introspectionEndpoint
	c.mu.RUnlock()
	if err := c.oauthForm(ctx, endpoint, url.Values{"token": {token}}, &out); err != nil {
		return out, err
	}
	if !out.Active {
		return out, ErrUnauthenticated
	}
	var audience []string
	if json.Unmarshal(out.Audience, &audience) != nil {
		var one string
		if json.Unmarshal(out.Audience, &one) == nil {
			audience = []string{one}
		}
	}
	if out.Subject == "" || (len(out.Audience) > 0 && !contains(audience, c.clientID)) || out.ClientID != c.clientID || out.ExpiresAt <= time.Now().Unix() {
		return Introspection{}, ErrUnauthenticated
	}
	return out, nil
}
func (c *Client) Revoke(ctx context.Context, token string) error {
	c.mu.RLock()
	endpoint := c.revocationEndpoint
	c.mu.RUnlock()
	err := c.oauthForm(ctx, endpoint, url.Values{"token": {token}}, nil)
	if err == nil {
		c.cache.clear()
	}
	return err
}
func (c *Client) oauthForm(ctx context.Context, endpoint string, values url.Values, output any) error {
	if c.clientID == "" || c.clientSecret == "" {
		return errors.New("account: confidential credentials required")
	}
	if values.Get("token") == "" {
		return ErrUnauthenticated
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)
	h := *c.http
	h.Jar = nil
	res, err := h.Do(req)
	if err != nil {
		return errors.New("account: request failed")
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return ErrInvalidResponse
	}
	if res.StatusCode != 200 {
		return decodeError(res, data)
	}
	if output != nil && (string(data) == "null" || json.Unmarshal(data, output) != nil) {
		return ErrInvalidResponse
	}
	return nil
}
func safeOAuthError(err error) error {
	var remote *oauth2.RetrieveError
	if errors.As(err, &remote) {
		return &APIError{StatusCode: remote.Response.StatusCode, Code: remote.ErrorCode, Message: remote.ErrorDescription, RequestID: remote.Response.Header.Get("X-Request-ID")}
	}
	return errors.New("account: token request failed")
}
func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
func randomValue() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("account: secure random source unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Discovery and SigningKeys expose the standard read-only OIDC metadata for
// integrations that use another OIDC implementation instead of DiscoverOIDC.
func (c *Client) Discovery(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.request(ctx, "GET", "/.well-known/openid-configuration", nil, nil, &out, "public", []int{200})
	return out, err
}
func (c *Client) SigningKeys(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.request(ctx, "GET", "/oauth/jwks", nil, nil, &out, "public", []int{200})
	return out, err
}

// PlatformLoginURL is for Account's own UI. Business apps should call BeginLogin
// with Provider to retain OIDC state, nonce, PKCE and application consent.
func (c *Client) PlatformLoginURL(provider, authorization string) (string, error) {
	if !providerKey.MatchString(provider) {
		return "", errors.New("account: invalid provider key")
	}
	u := *c.base
	u.Path = "/auth/" + provider + "/start"
	if authorization != "" {
		u.RawQuery = url.Values{"authorization": {authorization}}.Encode()
	}
	return u.String(), nil
}

// oauth2.Token.Valid treats unknown expiry as non-expiring and does not enforce
// a token type. Account sessions require an explicit, current Bearer token.
func validateAccessToken(token *oauth2.Token) error {
	if token == nil || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || token.Expiry.IsZero() || !token.Expiry.After(time.Now()) {
		return errors.New("account: invalid or expired Bearer access token")
	}
	return nil
}
