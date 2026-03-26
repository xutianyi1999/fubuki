[中文](README.zh-CN.md) | English

### Decentralized (`dc.json`)

See [`doc/decentralized-architecture.md`](../doc/decentralized-architecture.md) (§14) for configuration fields.

- **`dc-alice.json` / `dc-bob.json`** — two peers on the same `network_id` and `psk`; adjust `bootstrap` to the other host’s **LAN IP** and UDP port. For a quick loopback test on one machine, the sample uses `127.0.0.1` and different `listen_udp` values.

Run (elevated / root):

```bash
fubuki daemon -c cfg-example/dc-alice.json
```
