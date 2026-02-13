# docker-api-auth

Standalone reverse proxy for the Docker API with ACL-based authentication.

Uses Go's `httputil.ReverseProxy` to proxy requests to the Docker socket, with proper support for connection hijacking (`docker run`, `docker exec`).

## Usage

```bash
docker-api-auth --acl acl.yml --listen :3004 --docker-socket /var/run/docker.sock
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--acl` | (required) | Path to ACL YAML file |
| `--listen` | `:3004` | Listen address |
| `--docker-socket` | `/var/run/docker.sock` | Path to Docker socket |

## ACL configuration

See [example/acl.yml](example/acl.yml).

## Authentication

Requests must include `X-Docker-Auth-Username` and `X-Docker-Auth-Password` headers.
