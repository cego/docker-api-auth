package internal

import (
	"os"
	"regexp"

	"github.com/samber/lo"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type ACLDeployer struct {
	servicePrefixRegexp *regexp.Regexp

	Username           string   `yaml:"username"`
	PasswordHash       string   `yaml:"password_hash"`
	ServicePrefix      string   `yaml:"service_prefix"`
	NetworkAttachments []string `yaml:"network_attachments"`
}

type ACL struct {
	Deployers []*ACLDeployer `json:"deployers"`
}

func NewACL(aclFilePath string) *ACL {
	acl := &ACL{}

	out := MustReturn(os.ReadFile(aclFilePath))
	MustNotFail(yaml.Unmarshal(out, &acl))

	// Compile and assign regexp's
	for _, deployer := range acl.Deployers {
		deployer.servicePrefixRegexp = MustReturn(regexp.Compile("^" + deployer.ServicePrefix))
	}

	return acl
}

func verifyPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (a *ACL) MatchNetworkAttachment(username string, password string, networkName string) bool {
	matches := lo.Filter(a.Deployers, func(item *ACLDeployer, _ int) bool {
		if item.Username != username {
			return false
		}

		if !verifyPasswordHash(password, item.PasswordHash) {
			return false
		}

		networkMatches := lo.Filter(item.NetworkAttachments, func(item string, _ int) bool {
			return item == networkName
		})
		return len(networkMatches) > 0
	})
	return len(matches) > 0
}

func (a *ACL) MatchServicePrefix(username string, password string, serviceName string) bool {
	matches := lo.Filter(a.Deployers, func(item *ACLDeployer, _ int) bool {
		if item.Username != username {
			return false
		}

		if !verifyPasswordHash(password, item.PasswordHash) {
			return false
		}

		return item.servicePrefixRegexp.MatchString(serviceName)
	})
	return len(matches) > 0
}
