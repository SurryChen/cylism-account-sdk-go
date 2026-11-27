package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxResponseBytes = 2 << 20

var (
	ErrInvalidResponse  = errors.New("account: invalid response")
	ErrUnauthenticated  = errors.New("account: authentication required")
	ErrForbidden        = errors.New("account: permission denied")
	ErrClientClosed     = errors.New("account: client closed")
	ErrCacheInvalidated = errors.New("account: cache invalidated during lookup; retry authentication")
	ErrCacheCapacity    = errors.New("account: authentication cache at capacity")
)

// Config describes a single application and/or a single browser user session.
// Never share a cookie Client between different people. Use separate clients for
// business services and administrator sessions. No environment is read implicitly.
type Config struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	// MaxResponseBytes bounds every response, including OIDC discovery, JWKS,
	// tokens and userinfo. Zero uses 2 MiB; negative values are invalid.
	MaxResponseBytes int64
	// Optional absolute URLs, restricted to the BaseURL origin. Explicit values
	// take precedence over discovery; absent metadata retains Account defaults.
	IntrospectionEndpoint string
	RevocationEndpoint    string
	// AllowInsecureLoopback allows HTTP only for localhost/loopback development.
	AllowInsecureLoopback bool
	// Cache defaults to local authentication/permission caching with background refresh.
	Cache CacheConfig
}

type Client struct {
	base                                      *url.URL
	http                                      *http.Client
	clientID, clientSecret                    string
	allowInsecureLoopback                     bool
	mu                                        sync.RWMutex
	csrf                                      map[string]string
	introspectionEndpoint, revocationEndpoint string
	introspectionOverride, revocationOverride bool
	cache                                     *accessCache
}

// APIError preserves machine-readable error and tracing metadata. Error() omits
// remote descriptions/bodies, which may contain confidential input.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	RetryAfter string
}

func (e *APIError) Error() string { return fmt.Sprintf("account: HTTP %d (%s)", e.StatusCode, e.Code) }
func (e *APIError) Is(target error) bool {
	return (target == ErrUnauthenticated && e.StatusCode == 401) || (target == ErrForbidden && e.StatusCode == 403)
}

func New(config Config) (*Client, error) {
	cacheConfig, err := normalizeCacheConfig(config.Cache)
	if err != nil {
		return nil, err
	}
	u, err := validateURL(config.BaseURL, config.AllowInsecureLoopback)
	if err != nil || (u != nil && u.Path != "" && u.Path != "/") {
		return nil, errors.New("account: BaseURL must be an HTTPS origin (explicit loopback HTTP allowed)")
	}
	if config.ClientSecret != "" && config.ClientID == "" {
		return nil, errors.New("account: ClientSecret requires ClientID")
	}
	if config.MaxResponseBytes < 0 {
		return nil, errors.New("account: MaxResponseBytes must not be negative")
	}
	limit := config.MaxResponseBytes
	if limit == 0 {
		limit = maxResponseBytes
	}
	introspection, err := sameOriginEndpoint(u, config.IntrospectionEndpoint, "/oauth/introspect")
	if err != nil {
		return nil, err
	}
	revocation, err := sameOriginEndpoint(u, config.RevocationEndpoint, "/oauth/revoke")
	if err != nil {
		return nil, err
	}
	h := http.Client{Timeout: 15 * time.Second}
	if config.HTTPClient != nil {
		h = *config.HTTPClient
		if h.Timeout == 0 {
			h.Timeout = 15 * time.Second
		}
	}
	transport := h.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	h.Transport = responseLimitTransport{base: transport, limit: limit}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// A private jar avoids inheriting another user's cookies from the supplied client.
	h.Jar, _ = cookiejar.New(nil)
	u.Path = ""
	return &Client{
		base: u, http: &h, clientID: config.ClientID, clientSecret: config.ClientSecret,
		csrf: map[string]string{}, allowInsecureLoopback: config.AllowInsecureLoopback,
		introspectionEndpoint: introspection, revocationEndpoint: revocation,
		introspectionOverride: config.IntrospectionEndpoint != "", revocationOverride: config.RevocationEndpoint != "",
		cache: newAccessCache(cacheConfig, h.Timeout),
	}, nil
}

func validateURL(raw string, allowLoopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("account: invalid URL")
	}
	local := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		local = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && allowLoopback && local) {
		return nil, errors.New("account: HTTPS required")
	}
	return u, nil
}

func escapeSegment(s string) string { return url.PathEscape(s) }

func queryValues(value any) url.Values {
	data, _ := json.Marshal(value)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	out := url.Values{}
	for k, v := range fields {
		var text string
		if json.Unmarshal(v, &text) == nil {
			out.Set(k, text)
		} else if string(v) != "null" {
			out.Set(k, string(v))
		}
	}
	return out
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, input, output any, auth string, statuses []int) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return errors.New("account: cannot encode request")
		}
		body = bytes.NewReader(data)
	}
	// Segment escaping must not permit ambiguous separators or dot traversal.
	for _, v := range strings.Split(path, "/")[1:] {
		segment, err := url.PathUnescape(v)
		if err != nil || segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "/\\%\x00\r\n") {
			return errors.New("account: invalid path segment")
		}
	}
	destination := c.base.String() + path
	if len(query) > 0 {
		destination += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, destination, body)
	if err != nil {
		return errors.New("account: invalid request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cylism-account-go/0.1.0")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth == "application" {
		if c.clientID == "" || c.clientSecret == "" {
			return errors.New("account: confidential application credentials required")
		}
		req.SetBasicAuth(c.clientID, c.clientSecret)
	} else if method != "GET" && method != "HEAD" {
		req.Header.Set("Origin", c.base.String())
		if auth == "user" || auth == "admin" || auth == "flow" {
			c.mu.RLock()
			token := c.csrf[auth]
			c.mu.RUnlock()
			if token == "" {
				return errors.New("account: read session/config before a cookie-authenticated write")
			}
			req.Header.Set("X-CSRF-Token", token)
		}
	}
	h := *c.http
	if auth == "application" {
		h.Jar = nil
	}
	response, err := h.Do(req)
	if err != nil {
		return fmt.Errorf("account: request failed: %w", safeNetworkError(err))
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("%w: read failed", ErrInvalidResponse)
	}
	accepted := false
	for _, code := range statuses {
		if code == response.StatusCode {
			accepted = true
			break
		}
	}
	if !accepted {
		return decodeError(response, data)
	}
	if output != nil {
		if len(data) == 0 || string(bytes.TrimSpace(data)) == "null" || json.Unmarshal(data, output) != nil {
			return fmt.Errorf("%w: invalid JSON", ErrInvalidResponse)
		}
	}
	if err := validateAccessResponse(path, input, output); err != nil {
		return err
	}
	c.captureCSRF(path, method, data)
	// Writes can revoke sessions or change grants. Verification is a read even
	// though its opaque token is carried in a POST body.
	if method != "GET" && method != "HEAD" && path != "/api/app/v1/password/verify" && path != "/api/app/v1/sessions/verify" && path != "/api/app/v1/users/search" && path != "/access/v1/evaluation" && path != "/access/v1/evaluations" {
		c.cache.clear()
	}
	return nil
}

// Avoid including request URLs (which can contain token-like query parameters).
func safeNetworkError(err error) error {
	var e *url.Error
	if errors.As(err, &e) {
		return e.Err
	}
	return err
}

func decodeError(response *http.Response, data []byte) error {
	out := &APIError{StatusCode: response.StatusCode, Code: "http_error", RequestID: response.Header.Get("X-Request-ID"), RetryAfter: response.Header.Get("Retry-After")}
	var envelope struct {
		Error       json.RawMessage `json:"error"`
		Description string          `json:"error_description"`
		RequestID   string          `json:"request_id"`
	}
	if json.Unmarshal(data, &envelope) == nil {
		var detail struct{ Code, Message string }
		if json.Unmarshal(envelope.Error, &detail) == nil && detail.Code != "" {
			out.Code = detail.Code
			out.Message = detail.Message
		} else {
			var code string
			if json.Unmarshal(envelope.Error, &code) == nil && code != "" {
				out.Code = code
				out.Message = envelope.Description
			}
		}
		if envelope.RequestID != "" {
			out.RequestID = envelope.RequestID
		}
	}
	return out
}

func (c *Client) captureCSRF(path, method string, data []byte) {
	var value struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(data, &value)
	scope := ""
	switch path {
	case "/auth/email/config":
		scope = "flow"
	case "/api/v1/me":
		scope = "user"
	case "/api/admin/v1/auth/me", "/api/admin/v1/auth/login", "/api/admin/v1/auth/mfa":
		scope = "admin"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if scope != "" && value.CSRFToken != "" {
		c.csrf[scope] = value.CSRFToken
	}
	if method == "POST" {
		if path == "/api/v1/me/logout" {
			delete(c.csrf, "user")
		}
		if path == "/api/admin/v1/auth/logout" {
			delete(c.csrf, "admin")
		}
		if path == "/auth/email/login" || path == "/auth/email/register" {
			delete(c.csrf, "user")
		}
	}
}

// Ptr constructs optional values in generated request/query types.
func Ptr[T any](value T) *T { return &value }

// RetryAfterDuration parses Retry-After without automatically replaying a write.
func (e *APIError) RetryAfterDuration(now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(e.RetryAfter); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(e.RetryAfter); err == nil && date.After(now) {
		return date.Sub(now)
	}
	return 0
}

// Bound the transport rather than individual decoders so dependency-owned OIDC
// requests and error bodies have the same ceiling. Never mutate the caller's client.
type responseLimitTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t responseLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.ContentLength > t.limit {
		res.Body.Close()
		return nil, fmt.Errorf("%w: response too large", ErrInvalidResponse)
	}
	res.Body = http.MaxBytesReader(nil, res.Body, t.limit)
	return res, nil
}
func sameOriginEndpoint(base *url.URL, raw, fallback string) (string, error) {
	if raw == "" {
		return base.Scheme + "://" + base.Host + fallback, nil
	}
	u, err := validateURL(raw, base.Scheme == "http")
	if err != nil || u.Scheme != base.Scheme || u.Host != base.Host {
		return "", errors.New("account: OAuth endpoint must use Account origin without query or fragment")
	}
	return u.String(), nil
}
