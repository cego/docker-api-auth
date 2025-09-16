# Usage on machines with docker

```Caddyfile
{
        admin off
        auto_https off

}

:3004 {
        route * {
                docker_api_auth example/acl.yml
                reverse_proxy unix//var/run/docker.sock
        }
}
```
