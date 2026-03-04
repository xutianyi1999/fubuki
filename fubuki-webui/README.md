# Fubuki Web UI

Web dashboard for [Fubuki](https://github.com/nic-horse/fubuki) node and server. Shows groups, nodes, virtual IPs, latency, and packet loss.

## Stack

- **React 18** + **TypeScript**
- **Vite** (build & dev server)
- **Tailwind CSS**
- **React Router**

## Development

```bash
npm install
npm run dev
```

Open http://localhost:5173 (or the port Vite prints). The dev server proxies `/info` and `/type` to `http://127.0.0.1:3030`, so run a Fubuki node (or server) with API on that address to load live data.

To use another API host, edit `server.proxy` in `vite.config.ts`.

## Build

```bash
npm run build
```

Output is written to `dist/fubuki-webui/`. The Fubuki binary embeds this directory when built with the `web` feature:

```bash
cd fubuki-webui && npm install && npm run build && cd ..
cargo build --release --features web
```

With `--features web`, the node/server serves the Web UI at the API root (e.g. http://127.0.0.1:3030 for node, http://127.0.0.1:3031 for server).

## Preview

```bash
npm run preview
```

Serves the built output locally. Configure proxy or API base if you need to hit a real backend.
