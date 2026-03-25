#!/usr/bin/env bash
# Multi-node Fubuki mesh on a single host (Docker Compose).
# Usage:
#   ./scripts/docker-mesh.sh build          # build image fubuki-mesh:test
#   ./scripts/docker-mesh.sh gen [N]        # write docker/mesh/out/ (default N=3)
#   ./scripts/docker-mesh.sh up [--no-build] [N]   # docker build + gen + compose up -d
#       --no-build / FUBUKI_MESH_SKIP_BUILD=1: skip image rebuild (configs-only iteration)
#       After a real build, compose uses --force-recreate so containers pick up the new image.
#   ./scripts/docker-mesh.sh down           # compose down
#   ./scripts/docker-mesh.sh logs           # compose logs -f
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${FUBUKI_MESH_IMAGE:-fubuki-mesh:test}"
DOCKERFILE="docker/mesh/Dockerfile"
OUT="docker/mesh/out"
COMPOSE="$OUT/docker-compose.yml"

die() {
  echo "error: $*" >&2
  exit 1
}

cmd="${1:-}"
shift || true

case "$cmd" in
  build)
    docker build -f "$DOCKERFILE" -t "$IMAGE" .
    ;;
  gen)
    n="${1:-3}"
    python3 docker/mesh/generate_mesh.py -n "$n" -o "$OUT" --image "$IMAGE"
    ;;
  up)
    skip_build=false
    case "${FUBUKI_MESH_SKIP_BUILD:-}" in
      1 | true | TRUE | yes | YES | on | ON) skip_build=true ;;
    esac
    n=3
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --no-build) skip_build=true; shift ;;
        *)
          if [[ "$1" =~ ^[0-9]+$ ]]; then
            n="$1"
            shift
          else
            die "unknown argument to up: $1 (try: $0 up [--no-build] [N])"
          fi
          ;;
      esac
    done
    ran_build=false
    if ! $skip_build; then
      docker build -f "$DOCKERFILE" -t "$IMAGE" .
      ran_build=true
    elif ! docker image inspect "$IMAGE" &>/dev/null; then
      echo "image $IMAGE not found; building (--no-build ignored)..."
      docker build -f "$DOCKERFILE" -t "$IMAGE" .
      ran_build=true
    else
      echo "skipping docker build (--no-build or FUBUKI_MESH_SKIP_BUILD)"
    fi
    python3 docker/mesh/generate_mesh.py -n "$n" -o "$OUT" --image "$IMAGE"
    if $ran_build; then
      docker compose -f "$COMPOSE" up -d --force-recreate
    else
      docker compose -f "$COMPOSE" up -d
    fi
    echo "Mesh up. Example: docker exec -it fubuki-mesh-node-1 ping -c 2 10.200.1.12"
    ;;
  down)
    [[ -f "$COMPOSE" ]] || die "no $COMPOSE — run '$0 gen' or '$0 up' first"
    docker compose -f "$COMPOSE" down
    ;;
  logs)
    [[ -f "$COMPOSE" ]] || die "no $COMPOSE — run '$0 up' first"
    docker compose -f "$COMPOSE" logs -f
    ;;
  *)
    die "usage: $0 build | gen [N] | up [--no-build] [N] | down | logs"
    ;;
esac
