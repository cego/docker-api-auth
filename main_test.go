package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cego/caddy-docker-api-auth/internal"
	"github.com/cego/caddy-docker-api-auth/internal/guards"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

var (
	testACL    = internal.NewACL("example/acl.yml")
	testLogger = zap.NewNop()
)

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	dockerApi, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	guard := guards.NewServicesEdit(context.Background(), testLogger, testACL, dockerApi)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	return authMiddleware(testLogger, testACL, guard, backend)
}

func TestAuthRejectsNoHeaders(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest("GET", "/_ping", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "X-Docker-Auth-Username or X-Docker-Auth-Password is empty or unspecified")
}

func TestAuthRejectsMissingPassword(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest("GET", "/_ping", nil)
	req.Header.Set("X-Docker-Auth-Username", "example")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthRejectsMissingUsername(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest("GET", "/_ping", nil)
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthRejectsWrongPassword(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest("GET", "/_ping", nil)
	req.Header.Set("X-Docker-Auth-Username", "example")
	req.Header.Set("X-Docker-Auth-Password", "wrongpassword")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Could not verify username/password")
}

func TestAuthRejectsWrongUsername(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest("GET", "/_ping", nil)
	req.Header.Set("X-Docker-Auth-Username", "nobody")
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthPassesValidCredentials(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest("GET", "/_ping", nil)
	req.Header.Set("X-Docker-Auth-Username", "example")
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestAuthPassesNonGuardedPath(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest("GET", "/containers/json", nil)
	req.Header.Set("X-Docker-Auth-Username", "example")
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestServicesCreateForbiddenPrefix(t *testing.T) {
	handler := newTestHandler(t)
	body := `{"Name":"forbidden_service","TaskTemplate":{"Networks":[]}}`
	req := httptest.NewRequest("POST", "/v1.41/services/create", strings.NewReader(body))
	req.Header.Set("X-Docker-Auth-Username", "example")
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "is not permitted to update or create")
}

func TestServicesCreateAllowedPrefix(t *testing.T) {
	handler := newTestHandler(t)
	body := `{"Name":"example_myservice","TaskTemplate":{"Networks":[]}}`
	req := httptest.NewRequest("POST", "/v1.41/services/create", strings.NewReader(body))
	req.Header.Set("X-Docker-Auth-Username", "example")
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServicesUpdateForbiddenPrefix(t *testing.T) {
	handler := newTestHandler(t)
	body := `{"Name":"other_service","TaskTemplate":{"Networks":[]}}`
	req := httptest.NewRequest("POST", "/v1.41/services/abc123/update", strings.NewReader(body))
	req.Header.Set("X-Docker-Auth-Username", "example")
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestServicesUpdateAllowedPrefix(t *testing.T) {
	handler := newTestHandler(t)
	body := `{"Name":"example_myservice","TaskTemplate":{"Networks":[]}}`
	req := httptest.NewRequest("POST", "/v1.41/services/abc123/update", strings.NewReader(body))
	req.Header.Set("X-Docker-Auth-Username", "example")
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServicesCreateInvalidJSON(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest("POST", "/v1.41/services/create", strings.NewReader("not json"))
	req.Header.Set("X-Docker-Auth-Username", "example")
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServicesCreateBodyPassedThrough(t *testing.T) {
	dockerApi, _ := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	guard := guards.NewServicesEdit(context.Background(), testLogger, testACL, dockerApi)

	var capturedBody string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		w.WriteHeader(http.StatusOK)
	})
	handler := authMiddleware(testLogger, testACL, guard, backend)

	body := `{"Name":"example_myservice","TaskTemplate":{"Networks":[]}}`
	req := httptest.NewRequest("POST", "/v1.41/services/create", strings.NewReader(body))
	req.Header.Set("X-Docker-Auth-Username", "example")
	req.Header.Set("X-Docker-Auth-Password", "see im a proper password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, body, capturedBody)
}

func TestProxyDirector(t *testing.T) {
	req := httptest.NewRequest("GET", "http://localhost:3004/v1.41/containers/json", nil)

	director := func(r *http.Request) {
		r.URL.Scheme = "http"
		r.URL.Host = "docker"
	}
	director(req)

	assert.Equal(t, "http", req.URL.Scheme)
	assert.Equal(t, "docker", req.URL.Host)
	assert.Equal(t, "/v1.41/containers/json", req.URL.Path)
}
