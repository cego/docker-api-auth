package internal_test

import (
	"testing"

	"github.com/cego/caddy-docker-api-auth/internal"
	"github.com/stretchr/testify/assert"
)

func TestACL(t *testing.T) {
	acl := internal.NewACL("../example/acl.yml")

	validExampleUsername := "example"
	validExamplePassword := "see im a proper password"
	validExamplePrefix := "example_"

	t.Run("it matches by username, password and service name", func(t *testing.T) {
		found := acl.MatchServicePrefix(validExampleUsername, validExamplePassword, validExamplePrefix)
		assert.True(t, found)
	})
	t.Run("it matches by username, and service name, but not password", func(t *testing.T) {
		found := acl.MatchServicePrefix(validExampleUsername, "invalid password", validExamplePrefix)
		assert.False(t, found)
	})
	t.Run("it matches by username and password, but not service name", func(t *testing.T) {
		found := acl.MatchServicePrefix(validExampleUsername, validExamplePassword, "notexample_")
		assert.False(t, found)
	})
	t.Run("it matches by password and service name, but not username", func(t *testing.T) {
		found := acl.MatchServicePrefix("invalid-username", validExamplePassword, validExamplePrefix)
		assert.False(t, found)
	})
}
