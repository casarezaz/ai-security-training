#!/usr/bin/env bash
# Audit running Docker containers for security
echo "=============================================="
echo "  Docker Security Audit"
echo "=============================================="
echo ""

echo "=== Running Containers ==="
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
echo ""

echo "=== Container Security Settings ==="
for container in $(docker ps -q); do
    name=$(docker inspect --format '{{.Name}}' $container | tr -d '/')
    echo "--- $name ---"
    echo "  Privileged:        $(docker inspect --format '{{.HostConfig.Privileged}}' $container)"
    echo "  No New Privileges: $(docker inspect --format '{{.HostConfig.SecurityOpt}}' $container)"
    echo "  Capabilities Add:  $(docker inspect --format '{{.HostConfig.CapAdd}}' $container)"
    echo "  Capabilities Drop: $(docker inspect --format '{{.HostConfig.CapDrop}}' $container)"
    echo "  Network Mode:      $(docker inspect --format '{{.HostConfig.NetworkMode}}' $container)"
    echo "  Memory Limit:      $(docker inspect --format '{{.HostConfig.Memory}}' $container)"
    echo "  CPU Limit:         $(docker inspect --format '{{.HostConfig.NanoCpus}}' $container)"
    echo "  Read-only Root:    $(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $container)"
    echo "  User:              $(docker inspect --format '{{.Config.User}}' $container)"
    echo ""
done

echo "=== Exposed Ports ==="
docker ps --format "{{.Names}}: {{.Ports}}" | grep -v "^$"
echo ""

echo "=== Volumes Mounted ==="
for container in $(docker ps -q); do
    name=$(docker inspect --format '{{.Name}}' $container | tr -d '/')
    mounts=$(docker inspect --format '{{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Mode}}){{"\n"}}{{end}}' $container)
    if [ -n "$mounts" ]; then
        echo "--- $name ---"
        echo "$mounts"
    fi
done

echo ""
echo "=== Docker Daemon Settings ==="
echo "  Content Trust: ${DOCKER_CONTENT_TRUST:-not set}"
cat ~/.docker/daemon.json 2>/dev/null | python3 -m json.tool 2>/dev/null
