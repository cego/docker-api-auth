package guards

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"

	"github.com/cego/caddy-docker-api-auth/internal"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
)

type ServicesEdit struct {
	ctx       context.Context
	logger    *zap.Logger
	acl       *internal.ACL
	dockerApi *client.Client
	regexps   []*regexp.Regexp
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

func NewServicesEdit(ctx context.Context, logger *zap.Logger, acl *internal.ACL, dockerApi *client.Client) *ServicesEdit {
	regexps := []*regexp.Regexp{
		regexp.MustCompile("/.*?/services/.*?/update"),
		regexp.MustCompile("/.*?/services/create"),
	}
	return &ServicesEdit{ctx, logger, acl, dockerApi, regexps}
}

func (n *ServicesEdit) Matches(path string) bool {
	for _, r := range n.regexps {
		if r.MatchString(path) {
			return true
		}
	}
	return false
}

func (n *ServicesEdit) findNetworkName(networkID string) string {
	inspect, err := n.dockerApi.NetworkInspect(n.ctx, networkID, client.NetworkInspectOptions{})
	if err != nil {
		n.logger.Warn("Could not find network name for '" + networkID + "'")
		return ""
	}
	return inspect.Name
}

func (n *ServicesEdit) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.Handler, username string) {
	logger := n.logger

	buf, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error("Failed to read request body", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rdr1 := io.NopCloser(bytes.NewBuffer(buf))
	rdr2 := io.NopCloser(bytes.NewBuffer(buf))
	r.Body = rdr2

	service := new(ServiceDef)
	err = json.NewDecoder(rdr1).Decode(&service)
	if err != nil {
		logger.Error("Failed to parse json", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !n.acl.MatchServicePrefix(username, service.Name) {
		msg := "'" + username + "' is not permitted to update or create '" + service.Name + "'"
		logger.Error(msg)
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	for _, network := range service.TaskTemplate.Networks {
		networkName := n.findNetworkName(network.Target)
		if !n.acl.MatchNetworkAttachment(username, networkName) {
			msg := "'" + username + "' is not permitted to attach to network '" + network.Target + "'"
			logger.Error(msg)
			http.Error(w, msg, http.StatusForbidden)
			return
		}
	}

	next.ServeHTTP(w, r)
}
