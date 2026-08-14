# Zebra node for zutreexo

A pinned, canonical `zfnd/zebra` mainnet node in Docker. It exists to serve two
roles the project depends on:

* **The Phase 0 baseline** — `scripts/measure_baseline.sh` reads its JSON-RPC to
  answer what today's node actually costs (CLAUDE.md Phase 0).
* **The oracle** — Zebra's `z_gettreestate` is the second of the two oracles in
  the Phase 2 differential harness, the one that catches parsing bugs the naive
  model cannot (CLAUDE.md Phase 2, standing rule 2).

Because it is an oracle, the image tag is **pinned** in `.env`, not `:latest`.
Bumping it invalidates every number measured against it.

## Quick start

```bash
cp docker/.env.example docker/.env   # then edit paths/ports
scripts/zebra-node.sh up
scripts/zebra-node.sh status
scripts/zebra-node.sh logs -f
```

Initial sync from genesis is many hours and lands at roughly 260–300 GB.

## Driving it

| Command | What it does |
|---|---|
| `zebra-node.sh up` / `down` / `restart` | Lifecycle. `down` allows 5 min for a clean RocksDB flush. |
| `zebra-node.sh status` | Height, estimated tip, blocks behind, peers, disk, RSS, value pools. |
| `zebra-node.sh rpc METHOD [PARAMS_JSON]` | One JSON-RPC call, `.result` only, errors surfaced. |
| `zebra-node.sh wait-sync [--timeout S]` | Blocks until `/ready`. Use before a measurement run. |
| `zebra-node.sh watch --out FILE` | Samples height/RSS/disk to CSV — this is what produces the IBD wall-clock and peak-RSS figures Phase 0 asks for. |
| `zebra-node.sh state-dir` | Prints the host path, for `measure_baseline.sh --state-dir`. |
| `zebra-node.sh nuke` | Deletes chain state. Requires typing `resync`. |

```bash
scripts/zebra-node.sh rpc getblockchaininfo
scripts/zebra-node.sh rpc z_gettreestate '["3428143"]'   # Ironwood activation
```

## Recording the Phase 0 baseline

Item 3 of Phase 0 is Zebra's IBD wall-clock and peak RSS, which can only be
captured while the sync is happening. Start the sampler alongside the node:

```bash
scripts/zebra-node.sh up
scripts/zebra-node.sh watch --interval 60 --out docs/ibd-baseline.csv
```

Then, once synced, take the state measurements:

```bash
scripts/zebra-node.sh wait-sync
scripts/measure_baseline.sh --state-dir "$(scripts/zebra-node.sh state-dir)"
```

`measure_baseline.sh` finds the RSS figure by `pgrep -x zebrad` on the host. That
works with this setup — a container process is still visible in the host's
`/proc` — so no change is needed there.

## Configuration

Three layers, highest precedence first:

1. `ZEBRA_SECTION__KEY` environment variables (double underscore for nesting),
   set in `docker-compose.yml`.
2. `docker/zebrad.toml`, mounted read-only and pointed at by `CONFIG_FILE_PATH`.
3. zebrad's built-in defaults. Print the full annotated skeleton with:
   `docker run --rm --entrypoint zebrad zfnd/zebra:6.3.0 generate`.

`state.cache_dir` and `rpc.cookie_dir` are set as env vars rather than in the
TOML, because the image entrypoint reads those same variables to decide which
directories to create and chown. Keeping them in one place avoids a second
source of truth that env would silently win against.

### Why the state mounts at `/state`

The image's `$HOME` (`/home/zebra`) is mode `0700` owned by the image's own uid
10001. The container runs as the host user so the state dir stays measurable
from the host without sudo, and that user cannot traverse into `/home/zebra`.
Mounting at `/state` and setting `ZEBRA_STATE__CACHE_DIR` sidesteps it.

Relatedly, `user:` is set explicitly rather than relying on the entrypoint's
privilege drop: that path uses `setpriv --init-groups`, which needs the target
uid to exist in the container's `/etc/passwd`, and the image only knows uid
10001.

## Security

The RPC has **cookie auth disabled** and is published to `127.0.0.1` only. That
combination is deliberate and the two halves are load-bearing together — an
unauthenticated Zcash RPC on a routable address is a wide-open door.

Note that Docker's published ports are DNAT'd ahead of the `INPUT` chain, so
`ufw`/`iptables` rules do **not** protect a `0.0.0.0`-published port. The
explicit `127.0.0.1:` prefix in `docker-compose.yml` is the actual control. If
you ever need the RPC reachable off-box, set `enable_cookie_auth = true` in
`zebrad.toml` and mount the cookie from the state dir.

Other containers on the same Docker bridge network can still reach the RPC.

## Ports

| Purpose | Container | Host default | Notes |
|---|---|---|---|
| JSON-RPC | 8232 | `127.0.0.1:8232` | Set by `ZEBRA_RPC_PORT`. |
| Health | 8080 | `127.0.0.1:8080` | `/healthy`, `/ready`. |
| P2P | 8233 | `0.0.0.0:8234` | Set by `ZEBRA_P2P_PORT`; see below. |

**This host already runs another Zcash node** (the `zakura` container) holding
8233, so `docker/.env` maps P2P to 8234. Zebra dials out from an ephemeral port
regardless, so this only affects inbound peers — sync works either way. If 8233
frees up, set `ZEBRA_P2P_PORT=8233` and restart to accept inbound connections on
the standard port.

## Phase 4

When the bridge node needs Zaino, uncomment `indexer_listen_addr` in
`zebrad.toml` and publish that port. Zaino reads Zebra's state over that socket
rather than over JSON-RPC.
