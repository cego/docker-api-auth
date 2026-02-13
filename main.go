package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"syscall"

	"github.com/cego/caddy-docker-api-auth/internal"
	"github.com/cego/caddy-docker-api-auth/internal/guards"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
)

func main() {
	aclFile := flag.String("acl", "", "path to ACL YAML file")
	listen := flag.String("listen", ":3004", "listen address")
	dockerSocket := flag.String("docker-socket", "/var/run/docker.sock", "path to Docker socket")
	flag.Parse()

	if *aclFile == "" {
		fmt.Fprintln(os.Stderr, "error: --acl flag is required")
		flag.Usage()
		os.Exit(1)
	}

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	acl := internal.NewACL(*aclFile)

	dockerApi, err := client.NewClientWithOpts(
		client.WithHost("unix://"+*dockerSocket),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		logger.Fatal("failed to create docker client", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	servicesEditGuard := guards.NewServicesEdit(ctx, logger, acl, dockerApi)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = "docker"
		},
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", *dockerSocket)
			},
		},
	}

	handler := authMiddleware(logger, acl, servicesEditGuard, proxy)

	server := &http.Server{
		Addr:    *listen,
		Handler: handler,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info("shutting down")
		server.Close()
	}()

	logger.Info("starting server", zap.String("listen", *listen), zap.String("docker-socket", *dockerSocket))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("server error", zap.Error(err))
	}
}

func authMiddleware(logger *zap.Logger, acl *internal.ACL, servicesEditGuard *guards.ServicesEdit, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.Header.Get("X-Docker-Auth-Username")
		password := r.Header.Get("X-Docker-Auth-Password")
		if username == "" || password == "" {
			msg := "X-Docker-Auth-Username or X-Docker-Auth-Password is empty or unspecified"
			logger.Error(msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		if !acl.VerifyUser(username, password) {
			msg := "Could not verify username/password for username '" + username + "'"
			logger.Error(msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		if servicesEditGuard.Matches(r.URL.Path) {
			servicesEditGuard.ServeHTTP(w, r, next, username)
			return
		}

		next.ServeHTTP(w, r)
	})
}
