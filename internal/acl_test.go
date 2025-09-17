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

	t.Run("it passes VerifyUser", func(t *testing.T) {
		found := acl.VerifyUser(validExampleUsername, validExamplePassword)
		assert.True(t, found)
	})

	t.Run("it fails VerifyUser with invalid password", func(t *testing.T) {
		found := acl.VerifyUser(validExampleUsername, "im not a proper password")
		assert.False(t, found)
	})

	t.Run("it fails VerifyUser with invalid username", func(t *testing.T) {
		found := acl.VerifyUser("notavalidusername", validExamplePassword)
		assert.False(t, found)
	})

	t.Run("it matches by username and service name", func(t *testing.T) {
		found := acl.MatchServicePrefix(validExampleUsername, validExamplePrefix)
		assert.True(t, found)
	})
	t.Run("it matches by username, but not service name", func(t *testing.T) {
		found := acl.MatchServicePrefix(validExampleUsername, "notexample_")
		assert.False(t, found)
	})
	t.Run("it matches by service name, but not username", func(t *testing.T) {
		found := acl.MatchServicePrefix("invalid-username", validExamplePrefix)
		assert.False(t, found)
	})
}
