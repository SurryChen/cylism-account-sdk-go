package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	host := httptest.NewServer(handler)
	t.Cleanup(host.Close)
	c, err := New(Config{BaseURL: host.URL, ClientID: "app", ClientSecret: "secret", AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func TestConfigRejectsUnsafeOrigins(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?q=secret", "https://example.com/#hash", "ftp://example.com"} {
		if _, err := New(Config{BaseURL: raw, AllowInsecureLoopback: true}); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, err := New(Config{BaseURL: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("HTTP allowed without development opt-in")
	}
}
func TestCredentialAndCookieBoundaries(t *testing.T) {
	var loginCount atomic.Int64
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/admin/v1/auth/login":
			if r.Header.Get("Authorization") != "" || r.Header.Get("Origin") == "" {
				t.Error("login credential/origin boundary")
			}
			loginCount.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "ca_admin", Value: "admin-cookie", Path: "/"})
			fmt.Fprint(w, "{\"csrf_token\":\"admin-csrf\",\"user\":{\"id\":\"admin\"},\"enrollment_required\":false}")
		case "/api/admin/v1/auth/verify":
			if cookie, err := r.Cookie("ca_admin"); err != nil || cookie.Value != "admin-cookie" {
				t.Error("missing admin cookie")
			}
			if r.Header.Get("X-CSRF-Token") != "admin-csrf" {
				t.Error("wrong admin CSRF")
			}
			fmt.Fprint(w, "{\"ok\":true}")
		case "/access/v1/evaluation":
			id, secret, ok := r.BasicAuth()
			if !ok || id != "app" || secret != "secret" || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" {
				t.Error("application auth leaked browser state")
			}
			fmt.Fprint(w, "{\"decision\":true}")
		case "/api/v1/me/logout":
			t.Error("user write without user CSRF sent")
		default:
			t.Error("unexpected path", r.URL.Path)
		}
	})
	ctx := context.Background()
	if _, err := c.AdminVerify(ctx, AdminVerifyInput{Password: "password"}); err == nil {
		t.Fatal("uninitialized CSRF accepted")
	}
	if _, err := c.AdminLogin(ctx, AdminLoginInput{Username: "admin", Password: "password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AdminVerify(ctx, AdminVerifyInput{Password: "password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UserLogout(ctx); err == nil {
		t.Fatal("admin CSRF reused for user")
	}
	allowed, err := c.CanOnline(ctx, "subject", "orders", "read")
	if err != nil || !allowed {
		t.Fatal(allowed, err)
	}
	if loginCount.Load() != 1 {
		t.Fatal("write repeated")
	}
}
func TestNoRedirectOrAutomaticRetry(t *testing.T) {
	var count atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
	defer destination.Close()
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(307)
	})
	if _, err := c.LoginPasswordUser(context.Background(), PasswordLoginInput{Email: "test@example.com", Password: "secret"}); err == nil {
		t.Fatal("redirect accepted")
	}
	if count.Load() != 1 {
		t.Fatal("unexpected retry")
	}
}
func TestErrorsAndInvalidDecisions(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		wantError  bool
		allowed    bool
	}{
		{"allow", "{\"decision\":true}", 200, false, true}, {"deny", "{\"decision\":false}", 200, false, false},
		{"missing", "{}", 200, true, false}, {"null", "null", 200, true, false}, {"null decision", "{\"decision\":null}", 200, true, false},
		{"wrong type", "{\"decision\":\"true\"}", 200, true, false}, {"invalid", "true", 200, true, false},
		{"server", "{\"decision\":true}", 503, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(test.status); fmt.Fprint(w, test.body) })
			allowed, err := c.CanOnline(context.Background(), "user", "orders", "read")
			if allowed != test.allowed || (err != nil) != test.wantError {
				t.Fatalf("allowed=%v err=%v", allowed, err)
			}
		})
	}
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(409)
		fmt.Fprint(w, "{\"error\":{\"code\":\"configuration_conflict\",\"message\":\"private-input\"},\"request_id\":\"trace-1\"}")
	})
	_, err := c.CanOnline(context.Background(), "user", "orders", "read")
	var api *APIError
	if !errors.As(err, &api) || api.Code != "configuration_conflict" || api.RequestID != "trace-1" || api.RetryAfterDuration(time.Now()) != time.Minute || strings.Contains(err.Error(), "private-input") {
		t.Fatal(err)
	}
}
func TestPathQueryAndCancellation(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "3" || r.URL.Query().Get("page_size") != "25" || r.URL.Query().Get("q") != "中文 & ?" {
			t.Error("query corrupted", r.URL.Query())
		}
		fmt.Fprint(w, "{\"items\":[],\"page\":3,\"page_size\":25,\"total\":0,\"total_pages\":0,\"has_next\":false,\"has_previous\":true}")
	})
	if _, err := c.ListUsers(context.Background(), ListUsersQuery{Page: Ptr(int64(3)), PageSize: Ptr(int64(25)), Q: Ptr("中文 & ?")}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"..", "a/b", "a%2fb", "", "a\\b"} {
		if _, err := c.GetUserDetail(context.Background(), id); err == nil {
			t.Error("unsafe segment accepted", id)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.HealthLive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestResponseLimits(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", maxResponseBytes+1)) })
	if _, err := c.HealthLive(context.Background()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal(err)
	}
}
func TestIntrospectionChecksApplicationAndRevocation(t *testing.T) {
	for _, test := range []struct {
		name, body string
		valid      bool
	}{
		{"valid without optional audience", fmt.Sprintf("{\"active\":true,\"sub\":\"subject\",\"client_id\":\"app\",\"exp\":%d}", time.Now().Add(time.Hour).Unix()), true},
		{"revoked", "{\"active\":false}", false},
		{"wrong app", fmt.Sprintf("{\"active\":true,\"sub\":\"subject\",\"client_id\":\"other\",\"exp\":%d}", time.Now().Add(time.Hour).Unix()), false},
		{"expired", "{\"active\":true,\"sub\":\"subject\",\"client_id\":\"app\",\"exp\":1}", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/oauth/introspect" {
					t.Error(r.URL.Path)
				}
				_ = r.ParseForm()
				if r.Form.Get("token") != "access" {
					t.Error("missing token")
				}
				fmt.Fprint(w, test.body)
			})
			_, err := c.Introspect(context.Background(), "access")
			if (err == nil) != test.valid {
				t.Fatal(err)
			}
		})
	}
}
func TestPermissionMiddlewareFailsClosed(t *testing.T) {
	for _, test := range []struct {
		body         string
		status, want int
	}{
		{snapshotJSON("trusted-user", "orders:read"), 200, 204}, {snapshotJSON("trusted-user", ""), 200, 403}, {"{}", 200, 503}, {"{}", 500, 503},
	} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(test.status); fmt.Fprint(w, test.body) })
		handler := c.RequirePermission("orders:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		req := httptest.NewRequest("GET", "/orders", nil)
		req = req.WithContext(WithPrincipal(req.Context(), Principal{Subject: "trusted-user"}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != test.want {
			t.Fatal(rec.Code, test.want)
		}
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/orders?subject=admin", nil))
		if rec.Code != 401 {
			t.Fatal("request identity trusted")
		}
	}
}

// Every generated method is exercised against its contract: method, path, query,
// body presence, status, and credential scope. Higher-level tests cover behavior.
func TestAllJSONOperationsHaveWorkingMethods(t *testing.T) {
	data, err := os.ReadFile("operations.json")
	if err != nil {
		t.Fatal(err)
	}
	var operations []struct {
		Name, Method, Path, Auth string
		Query                    bool
		Request, Response        json.RawMessage
		Statuses                 []int
	}
	if json.Unmarshal(data, &operations) != nil {
		t.Fatal("manifest invalid")
	}
	for _, op := range operations {
		t.Run(op.Name, func(t *testing.T) {
			path := op.Path
			for strings.Contains(path, "{") {
				start := strings.Index(path, "{")
				end := strings.Index(path[start:], "}") + start
				path = path[:start] + "test-value" + path[end+1:]
			}
			var called bool
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.Method != op.Method || r.URL.Path != path {
					t.Error("wrong operation", r.Method, r.URL.Path)
				}
				_, _, basic := r.BasicAuth()
				if basic != (op.Auth == "application") {
					t.Error("wrong credential scope")
				}
				if op.Auth == "application" && (r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "") {
					t.Error("cookie headers in application call")
				}
				if op.Method != "GET" && op.Auth != "application" && r.Header.Get("Origin") == "" {
					t.Error("missing Origin")
				}
				if op.Method != "GET" && contains([]string{"admin", "user", "flow"}, op.Auth) && r.Header.Get("X-CSRF-Token") != op.Auth+"-csrf" {
					t.Error("wrong CSRF scope")
				}
				body, _ := io.ReadAll(r.Body)
				if string(op.Request) != "null" && len(body) == 0 {
					t.Error("missing request body")
				}
				w.WriteHeader(op.Statuses[0])
				if op.Statuses[0] != 204 {
					if op.Name == "ApplicationEntitlements" {
						fmt.Fprint(w, snapshotJSON("test-value", "orders:read"))
					} else if op.Name == "VerifyApplicationSession" {
						_ = json.NewEncoder(w).Encode(ApplicationSessionIdentity{Subject: "test-value", ApplicationID: "app", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour), AbsoluteExpiresAt: time.Now().Add(2 * time.Hour), ValidUntil: time.Now().Add(time.Minute)})
					} else if op.Name == "VerifyPasswordSession" {
						_ = json.NewEncoder(w).Encode(PasswordSession{Subject: "test-value", ExpiresAt: time.Now().Add(time.Hour)})
					} else if strings.HasPrefix(path, "/access/v1/") {
						fmt.Fprint(w, "{\"decision\":false}")
					} else {
						fmt.Fprint(w, "{}")
					}
				}
			})
			c.csrf = map[string]string{"admin": "admin-csrf", "user": "user-csrf", "flow": "flow-csrf"}
			method := reflect.ValueOf(c).MethodByName(op.Name)
			if !method.IsValid() {
				t.Fatal("missing method")
			}
			args := []reflect.Value{reflect.ValueOf(context.Background())}
			for i := 1; i < method.Type().NumIn(); i++ {
				typ := method.Type().In(i)
				if typ.Kind() == reflect.String {
					args = append(args, reflect.ValueOf("test-value"))
				} else if op.Name == "VerifyApplicationSession" {
					args = append(args, reflect.ValueOf(VerifyApplicationSessionInput{Token: strings.Repeat("t", 43)}))
				} else if op.Name == "VerifyPasswordSession" {
					args = append(args, reflect.ValueOf(PasswordTokenInput{Token: "test-token"}))
				} else {
					args = append(args, reflect.Zero(typ))
				}
			}
			results := method.Call(args)
			last := results[len(results)-1]
			if !last.IsNil() {
				t.Fatal(last.Interface())
			}
			if !called {
				t.Fatal("not called")
			}
		})
	}
}
func TestBatchShapeValidation(t *testing.T) {
	var request AuthZENEvaluations
	if err := json.Unmarshal([]byte("{\"evaluations\":[{},{}]}"), &request); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		body      string
		wantError bool
	}{
		{"{\"evaluations\":[{\"decision\":true},{\"decision\":false}]}", false},
		{"{\"evaluations\":[{\"decision\":true}]}", true},
		{"{\"evaluations\":[{},{}]}", true},
		{"{\"decision\":true}", true},
	} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, test.body) })
		_, err := c.EvaluateAccessBatch(context.Background(), request)
		if (err != nil) != test.wantError {
			t.Fatal(err, test.body)
		}
	}
}
func TestSnapshotHelpersNoImplicitAdmin(t *testing.T) {
	e := AccessEntitlements{Status: "active", Roles: []string{"admin"}, Permissions: []EffectivePermission{{Key: "orders:read"}}}
	if !e.HasRole("admin") || !e.HasPermission("orders:read") || e.HasPermission("orders:delete") {
		t.Fatal(e)
	}
	e.Status = "disabled"
	if e.HasRole("admin") || e.HasPermission("orders:read") {
		t.Fatal("disabled member allowed")
	}
}
