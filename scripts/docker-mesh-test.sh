#!/usr/bin/env bash
# End-to-end test: build image, bring up N-node mesh, assert overlay ICMP, tear down.
# Connectivity: every node pings every other node's VIP (all ordered pairs, catches asymmetric paths).
#
# Virtual IPs match docker/mesh/generate_mesh.py: node i -> 10.200.1.$((10 + i))
#
# Usage:
#   ./scripts/docker-mesh-test.sh [--no-build] [--stun] [N]
#   MESH_WAIT_SECS=240 ./scripts/docker-mesh-test.sh   # extend wait for slow hosts
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${FUBUKI_MESH_IMAGE:-fubuki-mesh:test}"
DOCKERFILE="docker/mesh/Dockerfile"
OUT="docker/mesh/out"
COMPOSE="$OUT/docker-compose.yml"
MESH_WAIT_SECS="${MESH_WAIT_SECS:-180}"

die() {
  echo "error: $*" >&2
  exit 1
}

# Overlay IPv4 for node index 1..N (must stay in sync with generate_mesh.py).
virtual_ip() {
  local i="$1"
  echo "10.200.1.$((10 + i))"
}

container_name() {
  local i="$1"
  echo "fubuki-mesh-node-${i}"
}

cleanup() {
  local code=$?
  if [[ -f "$COMPOSE" ]]; then
    if [[ "$code" -ne 0 ]]; then
      echo ""
      echo "=== docker compose logs (tail) ==="
      docker compose -f "$COMPOSE" logs --tail=200 2>/dev/null || true
    fi
    echo ""
    echo "mesh-test: tearing down (docker compose down -v)"
    docker compose -f "$COMPOSE" down -v 2>/dev/null || true
  fi
  exit "$code"
}

trap cleanup EXIT

skip_build=false
use_stun=false
n=3
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) skip_build=true; shift ;;
    --stun) use_stun=true; shift ;;
    *)
      if [[ "$1" =~ ^[0-9]+$ ]]; then
        n="$1"
        shift
      else
        die "unknown argument: $1 (usage: $0 [--no-build] [--stun] [N])"
      fi
      ;;
  esac
done

[[ "$n" -ge 2 ]] || die "need N >= 2 nodes"

command -v docker >/dev/null || die "docker not found"
command -v python3 >/dev/null || die "python3 not found"

if $skip_build; then
  if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "image $IMAGE missing; building (--no-build ignored)"
    docker build -f "$DOCKERFILE" -t "$IMAGE" .
  else
    echo "mesh-test: skip docker build"
  fi
else
  echo "mesh-test: docker build"
  docker build -f "$DOCKERFILE" -t "$IMAGE" .
fi

if $use_stun; then
  echo "mesh-test: generate compose ($n nodes, STUN on)"
  python3 docker/mesh/generate_mesh.py -n "$n" -o "$OUT" --image "$IMAGE" --stun
else
  echo "mesh-test: generate compose ($n nodes)"
  python3 docker/mesh/generate_mesh.py -n "$n" -o "$OUT" --image "$IMAGE"
fi

echo "mesh-test: compose up"
docker compose -f "$COMPOSE" up -d --force-recreate

echo "mesh-test: waiting for $n containers running"
deadline=$(( $(date +%s) + 90 ))
while (( $(date +%s) < deadline )); do
  running=$(docker compose -f "$COMPOSE" ps -q --status running 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$running" -eq "$n" ]]; then
    break
  fi
  sleep 2
done

running=$(docker compose -f "$COMPOSE" ps -q --status running 2>/dev/null | wc -l | tr -d ' ')
[[ "$running" -eq "$n" ]] || die "expected $n running containers, got $running"

c1=$(container_name 1)
echo "mesh-test: waiting for overlay (node1 -> node2), up to ${MESH_WAIT_SECS}s"
deadline=$(( $(date +%s) + MESH_WAIT_SECS ))
vip2=$(virtual_ip 2)
while (( $(date +%s) < deadline )); do
  if docker exec "$c1" ping -c 1 -W 2 "$vip2" &>/dev/null; then
    echo "mesh-test: first ping ok $c1 -> $vip2"
    break
  fi
  sleep 3
done

if ! docker exec "$c1" ping -c 1 -W 2 "$vip2" &>/dev/null; then
  die "timeout: no overlay ping from node1 to $vip2 within ${MESH_WAIT_SECS}s"
fi

echo "mesh-test: pairwise overlay ICMP ($((n * (n - 1))) directed paths)"
for ((i = 1; i <= n; i++)); do
  ci=$(container_name "$i")
  for ((j = 1; j <= n; j++)); do
    [[ "$i" -eq "$j" ]] && continue
    vip=$(virtual_ip "$j")
    echo "  ping node${i} -> node${j} ($ci -> $vip)"
    docker exec "$ci" ping -c 3 -W 3 "$vip" >/dev/null \
      || die "ping failed node${i} -> node${j} ($ci -> $vip)"
  done
done

echo ""
echo "mesh-test: all checks passed ($n nodes)"
