package guards

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/cego/caddy-docker-api-auth/internal"
)

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*ServicesEdit)(nil)
)

type ServicesEdit struct {
	acl     *internal.ACL
	regexps []*regexp.Regexp
}

type ServiceDefTaskTemplateNetwork struct {
	Target string
}

type ServiceDefTaskTemplate struct {
	Networks []*ServiceDefTaskTemplateNetwork
}

type ServiceDef struct {
	Name         string `json:"Name"`
	TaskTemplate *ServiceDefTaskTemplate
}

func NewServicesEdit(acl *internal.ACL) *ServicesEdit {
	regexps := []*regexp.Regexp{
		regexp.MustCompile("/.*?/services/.*?/update"),
		regexp.MustCompile("/.*?/services/create"),
	}
	return &ServicesEdit{acl, regexps}
}

func (n *ServicesEdit) Matches(path string) bool {
	for _, r := range n.regexps {
		if r.MatchString(path) {
			return true
		}
	}
	return false
}

func (n *ServicesEdit) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("%v\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}

	username := r.Header.Get("X-Docker-Auth-Username")
	password := r.Header.Get("X-Docker-Auth-Password")
	if username == "" || password == "" {
		fmt.Printf("X-Docker-Auth-Password or X-Docker-Auth-Username is empty or unspecified\n")
		http.Error(w, "X-Docker-Auth-Password or X-Docker-Auth-Username is empty or unspecified", http.StatusUnauthorized)
		return nil
	}

	rdr1 := io.NopCloser(bytes.NewBuffer(buf))
	rdr2 := io.NopCloser(bytes.NewBuffer(buf))

	service := new(ServiceDef)
	err = json.NewDecoder(rdr1).Decode(&service)
	if err != nil {
		fmt.Printf("%v\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}

	// Block service edit if service name doesn't have correct prefix according to the matched password
	if !n.acl.MatchServicePrefix(username, password, service.Name) {
		http.Error(w, "X-Docker-Auth-Password not permitted to change "+service.Name+", no service prefixes were matched", http.StatusForbidden)
		return nil
	}

	// Block service edit if network target isn't matched in network_attachments
	for _, network := range service.TaskTemplate.Networks {
		if !n.acl.MatchNetworkAttachment(username, password, network.Target) {
			http.Error(w, "X-Docker-Auth-Password not permitted to attach to network "+network.Target+", no network_attachments were matched", http.StatusForbidden)
			return nil
		}
	}

	r.Body = rdr2
	return next.ServeHTTP(w, r)
}
