# Docker mesh (integration test)

Multi-node Fubuki on one host: each container has `NET_ADMIN`, `/dev/net/tun`, and a generated `dc.json`. Topology is **single seed** (`node1` has empty `bootstrap`; others only bootstrap to `node1`). See `generate_mesh.py`.

## Prerequisites

- Docker Engine + Compose v2
- Python 3 (for `generate_mesh.py`)

## Manual bring-up

From the repository root:

```bash
./scripts/docker-mesh.sh up          # build, generate 3-node compose, start
docker exec -it fubuki-mesh-node-1 ping -c 3 10.200.1.12
./scripts/docker-mesh.sh down
```

## Automated test (recommended)

Builds the image, starts `N` nodes (default 3), waits for the overlay, runs ICMP between nodes, then `docker compose down -v`.

```bash
./scripts/docker-mesh-test.sh              # full cycle
./scripts/docker-mesh-test.sh --no-build   # reuse existing image
./scripts/docker-mesh-test.sh --no-build 4 # four nodes
./scripts/docker-mesh-test.sh --stun        # enable STUN (DNS + binding; see generate_mesh.py)
MESH_WAIT_SECS=300 ./scripts/docker-mesh-test.sh   # slow CI or laptop
```

CI runs the script twice: default mesh, then `--no-build --stun` to cover the STUN path without rebuilding the image.

Equivalent:

```bash
./scripts/docker-mesh.sh test
./scripts/docker-mesh.sh test --no-build 4
```

Exit code `0` means all pings succeeded; non-zero prints compose log tail and tears down volumes.

## CI

Workflow [`.github/workflows/docker-mesh.yml`](../../.github/workflows/docker-mesh.yml) runs mesh E2E without STUN, then again with `--stun`, on `pull_request` and `push`.
