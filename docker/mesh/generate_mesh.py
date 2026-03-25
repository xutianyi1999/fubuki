#!/usr/bin/env python3
"""Generate docker-compose.yml and dc.json files for a local multi-node Fubuki mesh."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "-n",
        "--nodes",
        type=int,
        default=3,
        metavar="N",
        help="number of peers (default: 3)",
    )
    p.add_argument(
        "-o",
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "out",
        help="output directory",
    )
    p.add_argument(
        "--image",
        default="fubuki-mesh:test",
        help="Docker image tag for all nodes",
    )
    args = p.parse_args()

    if args.nodes < 2:
        print("error: need at least 2 nodes", file=sys.stderr)
        sys.exit(1)
    if args.nodes > 200:
        print("error: subnet 172.30.0.0/24 limits practical node count", file=sys.stderr)
        sys.exit(1)

    out: Path = args.out
    cfg_dir = out / "configs"
    cfg_dir.mkdir(parents=True, exist_ok=True)

    network_id = "550e8400-e29b-41d4-a716-446655440000"
    psk = "docker-mesh-test-psk"

    # Underlay: Docker bridge 172.30.0.x ; overlay VPN: 10.200.1.x
    compose_lines: list[str] = [
        "services:",
    ]
    volumes_block: list[str] = ["volumes:"]

    for i in range(1, args.nodes + 1):
        listen_udp = 22400 + i
        virtual_host = 10 + i
        virtual_net = f"10.200.1.{virtual_host}/24"
        display_name = f"node{i}"
        bootstrap: list[str] = []
        for j in range(1, args.nodes + 1):
            if j == i:
                continue
            bootstrap.append(f"node{j}:{22400 + j}")

        cfg = {
            "network_id": network_id,
            "psk": psk,
            "virtual_net": virtual_net,
            "listen_udp": listen_udp,
            "display_name": display_name,
            "bootstrap": bootstrap,
            "stun_servers": [],
            "node_id_path": "/var/lib/fubuki/node.id",
        }
        cfg_path = cfg_dir / f"node-{i}.json"
        cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")

        vol_name = f"fubuki-node-{i}-state"
        volumes_block.append(f"  {vol_name}:")

        compose_lines.extend(
            [
                f"  node{i}:",
                f"    image: {args.image}",
                f"    container_name: fubuki-mesh-node-{i}",
                "    cap_add:",
                "      - NET_ADMIN",
                "    devices:",
                "      - /dev/net/tun",
                "    environment:",
                "      FUBUKI_DC_STATE_DIR: /var/lib/fubuki",
                "    volumes:",
                f"      - ./configs/node-{i}.json:/etc/fubuki/dc.json:ro",
                f"      - {vol_name}:/var/lib/fubuki",
                "    networks:",
                "      mesh:",
                f"        ipv4_address: 172.30.0.{virtual_host}",
                "",
            ]
        )

    header = [
        "networks:",
        "  mesh:",
        "    driver: bridge",
        "    ipam:",
        "      config:",
        "        - subnet: 172.30.0.0/24",
        "",
    ]
    footer = volumes_block + [""]
    compose_path = out / "docker-compose.yml"
    compose_path.write_text(
        "\n".join(header + compose_lines + footer),
        encoding="utf-8",
    )
    print(f"Wrote {compose_path} and {args.nodes} configs under {cfg_dir}")


if __name__ == "__main__":
    main()
