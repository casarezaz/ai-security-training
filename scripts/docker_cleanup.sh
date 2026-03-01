#!/usr/bin/env bash
# Clean up Docker resources to free disk space
echo "=== Removing stopped containers ==="
docker container prune -f
echo ""
echo "=== Removing unused images ==="
docker image prune -f
echo ""
echo "=== Removing unused volumes ==="
docker volume prune -f
echo ""
echo "=== Removing unused networks ==="
docker network prune -f
echo ""
echo "=== Disk usage ==="
docker system df
