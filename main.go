package docker_api_auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/cego/caddy-docker-api-auth/internal"
	"github.com/cego/caddy-docker-api-auth/internal/guards"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
)

// Interface guards
var (
	_ caddy.Validator             = (*DockerApiAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*DockerApiAuth)(nil)
)

type DockerApiAuth struct {
	ACLFile string `json:"acl_file,omitempty"`

	acl               *internal.ACL
	servicesEditGuard *guards.ServicesEdit
	logger            *zap.Logger
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

func (d *DockerApiAuth) RefershConfig(logger *zap.Logger) {
	logger.Debug("Refreshing acl config")
}

func (d *DockerApiAuth) Provision(c caddy.Context) error {
	dockerApi, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	d.logger = c.Logger(c.Module())
	d.acl = internal.NewACL(d.ACLFile)
	d.servicesEditGuard = guards.NewServicesEdit(c, d.logger, d.acl, dockerApi)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.RefershConfig(d.logger)
				return
			case <-c.Done():
				return
			}
		}
	}()

	return nil
}

func (d *DockerApiAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	logger := d.logger

	username := r.Header.Get("X-Docker-Auth-Username")
	password := r.Header.Get("X-Docker-Auth-Password")
	if username == "" || password == "" {
		msg := "X-Docker-Auth-Username or X-Docker-Auth-Password is empty or unspecified"
		logger.Error(msg)
		http.Error(w, msg, http.StatusUnauthorized)
		return nil
	}

	if !d.acl.VerifyUser(username, password) {
		msg := "Could not verify username/password"
		logger.Error(msg)
		http.Error(w, msg, http.StatusUnauthorized)
		return nil
	}

	if d.servicesEditGuard.Matches(r.URL.Path) {
		return d.servicesEditGuard.ServeHTTP(w, r, next, username)
	}

	return next.ServeHTTP(w, r)
}
