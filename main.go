package docker_api_auth

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/cego/caddy-docker-api-auth/internal"
	"github.com/cego/caddy-docker-api-auth/internal/guards"
)

// Interface guards
var (
	_ caddy.Validator             = (*DockerApiAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*DockerApiAuth)(nil)
)

type DockerApiAuth struct {
	ACLFile string `json:"acl_file,omitempty"`

	acl *internal.ACL

	servicesEditGuard *guards.ServicesEdit
}

func init() {
	d := &DockerApiAuth{}
	caddy.RegisterModule(d)
	httpcaddyfile.RegisterHandlerDirective("docker_api_auth", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		for h.Next() {
			if !h.Args(&d.ACLFile) {
				return d, h.ArgErr()
			}
		}
		return d, nil
	})
}

func (*DockerApiAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.docker_api_auth",
		New: func() caddy.Module { return new(DockerApiAuth) },
	}
}

func (d *DockerApiAuth) Validate() error {
	if d.ACLFile == "" {
		return fmt.Errorf("docker_api_auth <acl_file> not specified")
	}
	return nil
}

func (d *DockerApiAuth) Provision(_ caddy.Context) error {
	// Read file and generate acl struct
	d.acl = internal.NewACL(d.ACLFile)
	d.servicesEditGuard = guards.NewServicesEdit(d.acl)

	return nil
}

func (d *DockerApiAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if d.servicesEditGuard.Matches(r.URL.Path) {
		return d.servicesEditGuard.ServeHTTP(w, r, next)
	}

	return next.ServeHTTP(w, r)
}
