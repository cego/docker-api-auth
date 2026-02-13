package guards_test

import (
	"context"
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

func newTestGuard(t *testing.T) *guards.ServicesEdit {
	t.Helper()
	acl := internal.NewACL("../../example/acl.yml")
	dockerApi, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	return guards.NewServicesEdit(context.Background(), zap.NewNop(), acl, dockerApi)
}

func TestMatchesServiceCreate(t *testing.T) {
	guard := newTestGuard(t)

	assert.True(t, guard.Matches("/v1.41/services/create"))
	assert.True(t, guard.Matches("/v1.45/services/create"))
}

func TestMatchesServiceUpdate(t *testing.T) {
	guard := newTestGuard(t)

	assert.True(t, guard.Matches("/v1.41/services/abc123/update"))
	assert.True(t, guard.Matches("/v1.45/services/my-service/update"))
}

func TestDoesNotMatchOtherPaths(t *testing.T) {
	guard := newTestGuard(t)

	assert.False(t, guard.Matches("/v1.41/containers/json"))
	assert.False(t, guard.Matches("/_ping"))
	assert.False(t, guard.Matches("/v1.41/services/abc123"))
	assert.False(t, guard.Matches("/v1.41/services"))
	assert.False(t, guard.Matches("/version"))
}

func TestServeHTTPForbidsWrongPrefix(t *testing.T) {
	guard := newTestGuard(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	body := `{"Name":"forbidden_service","TaskTemplate":{"Networks":[]}}`
	req := httptest.NewRequest("POST", "/v1.41/services/create", strings.NewReader(body))
	w := httptest.NewRecorder()

	guard.ServeHTTP(w, req, next, "example")

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "is not permitted to update or create")
}

func TestServeHTTPAllowsCorrectPrefix(t *testing.T) {
	guard := newTestGuard(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	body := `{"Name":"example_myservice","TaskTemplate":{"Networks":[]}}`
	req := httptest.NewRequest("POST", "/v1.41/services/create", strings.NewReader(body))
	w := httptest.NewRecorder()

	guard.ServeHTTP(w, req, next, "example")

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServeHTTPRejectsInvalidJSON(t *testing.T) {
	guard := newTestGuard(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/v1.41/services/create", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	guard.ServeHTTP(w, req, next, "example")

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServeHTTPPreservesBodyForNext(t *testing.T) {
	guard := newTestGuard(t)

	var capturedBody string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1024)
		n, _ := r.Body.Read(b)
		capturedBody = string(b[:n])
		w.WriteHeader(http.StatusOK)
	})

	body := `{"Name":"example_myservice","TaskTemplate":{"Networks":[]}}`
	req := httptest.NewRequest("POST", "/v1.41/services/create", strings.NewReader(body))
	w := httptest.NewRecorder()

	guard.ServeHTTP(w, req, next, "example")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, body, capturedBody)
}
