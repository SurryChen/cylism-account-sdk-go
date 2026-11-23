package account

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Can uses the trusted session subject, not user-supplied identity. Resource/action
// are fixed by the backend. Ownership/tenant checks remain the application's job.
func (c *Client) Can(ctx context.Context, subject, resource, action string) (bool, error) {
	return c.CanResource(ctx, subject, resource, "*", action)
}
func (c *Client) CanResource(ctx context.Context, subject, resource, id, action string) (bool, error) {
	if !validAccessText(subject, 128) || !validAccessText(resource, 64) || !validAccessText(id, 512) || !validAccessText(action, 64) || !permissionKey.MatchString(resource+":"+action) {
		return false, errors.New("account: invalid permission request")
	}
	if c.cache.config.Disabled {
		return c.CanResourceOnline(ctx, subject, resource, id, action)
	}
	permissions, err := c.ApplicationEntitlements(ctx, subject)
	if err != nil {
		var api *APIError
		if errors.As(err, &api) && api.StatusCode == 403 && api.Code == "application_access_denied" {
			return false, nil
		}
		return false, err
	}
	return permissions.HasPermission(resource + ":" + action), nil
}

var permissionKey = regexp.MustCompile(`^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_.-]*$`)

func validAccessText(s string, limit int) bool {
	return strings.TrimSpace(s) != "" && utf8.ValidString(s) && utf8.RuneCountInString(s) <= limit
}

// CanOnline bypasses the permission cache for operations needing immediate checks.
func (c *Client) CanOnline(ctx context.Context, subject, resource, action string) (bool, error) {
	return c.CanResourceOnline(ctx, subject, resource, "*", action)
}

func (c *Client) CanResourceOnline(ctx context.Context, subject, resource, id, action string) (bool, error) {
	c.cache.forget(cacheKey{"permissions", subject})
	defer c.cache.forget(cacheKey{"permissions", subject})
	result, err := c.EvaluateAccess(ctx, AuthZENEvaluation{Subject: AuthZENEntity{Type: "user", ID: subject}, Resource: AuthZENEntity{Type: resource, ID: id}, Action: AuthZENAction{Name: action}})
	if err != nil {
		return false, err
	}
	if result.Decision == nil {
		return false, ErrInvalidResponse
	}
	return *result.Decision, nil
}
func (e AccessEntitlements) HasRole(role string) bool {
	return e.Status == "active" && (e.ValidUntil.IsZero() || time.Now().Before(e.ValidUntil)) && contains(e.Roles, role)
}

// HasPermission checks a snapshot. Can enforces cache validity; CanOnline always
// asks Account. Do not retain a snapshot beyond its ValidUntil.
func (e AccessEntitlements) HasPermission(key string) bool {
	if e.Status != "active" || (!e.ValidUntil.IsZero() && !time.Now().Before(e.ValidUntil)) {
		return false
	}
	for _, p := range e.Permissions {
		if p.Key == key {
			return true
		}
	}
	return false
}

type principalKey struct{}
type Principal struct {
	Subject string
	Scope   []string
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok && p.Subject != ""
}

// WithPrincipal is for application-owned, already verified session middleware.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}
func (c *Client) AuthenticateBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			middlewareError(w, 401, "login_required")
			return
		}
		token, err := c.Introspect(r.Context(), fields[1])
		if err != nil {
			status := 503
			if errors.Is(err, ErrUnauthenticated) {
				status = 401
			}
			middlewareError(w, status, "authentication_failed")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), Principal{Subject: token.Subject, Scope: strings.Fields(token.Scope)})))
	})
}

// RequirePermission accepts resource:action. Run after trusted authentication.
func (c *Client) RequirePermission(permission string) func(http.Handler) http.Handler {
	resource, action, valid := strings.Cut(permission, ":")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok {
				middlewareError(w, 401, "login_required")
				return
			}
			if !valid || resource == "" || action == "" || strings.Contains(action, ":") {
				middlewareError(w, 500, "invalid_permission_configuration")
				return
			}
			allowed, err := c.Can(r.Context(), p.Subject, resource, action)
			if err != nil {
				middlewareError(w, 503, "authorization_unavailable")
				return
			}
			if !allowed {
				middlewareError(w, 403, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
func middlewareError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code}})
}

func validateAccessResponse(path string, input, output any) error {
	if path == "/access/v1/evaluation" {
		v, ok := output.(*AuthZENDecision)
		if !ok || v.Decision == nil {
			return ErrInvalidResponse
		}
	}
	if path != "/access/v1/evaluations" {
		return nil
	}
	// Preserve the protocol's default single-decision and short-circuit shapes.
	data, _ := json.Marshal(output)
	var wire struct {
		Decision    *bool
		Evaluations []struct{ Decision *bool }
	}
	if json.Unmarshal(data, &wire) != nil {
		return ErrInvalidResponse
	}
	request, ok := input.(AuthZENEvaluations)
	if !ok {
		return ErrInvalidResponse
	}
	count := len(request.Evaluations)
	if count == 0 {
		if wire.Decision == nil {
			return ErrInvalidResponse
		}
		return nil
	}
	if len(wire.Evaluations) == 0 || len(wire.Evaluations) > count {
		return ErrInvalidResponse
	}
	for _, v := range wire.Evaluations {
		if v.Decision == nil {
			return ErrInvalidResponse
		}
	}
	semantic := "execute_all"
	if request.Options != nil && request.Options.EvaluationsSemantic != nil {
		semantic = *request.Options.EvaluationsSemantic
	}
	if semantic == "" || semantic == "execute_all" {
		if len(wire.Evaluations) != count {
			return ErrInvalidResponse
		}
	} else if len(wire.Evaluations) < count {
		last := *wire.Evaluations[len(wire.Evaluations)-1].Decision
		if (semantic == "deny_on_first_deny" && last) || (semantic == "permit_on_first_permit" && !last) {
			return ErrInvalidResponse
		}
	}
	return nil
}
