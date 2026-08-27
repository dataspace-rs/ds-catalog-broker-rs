> **Historical / retired.** This harness targeted `POST /dsp/catalog/request`,
> `GET /dsp/catalog/datasets/{id}`, and `GET /.well-known/dspace-version` -
> a DSP catalog-*serving* surface this product no longer has, per
> `docs/gap-analysis-2026-08-27.md` §1 (this product is a DSP Consumer /
> Catalog Broker, and must never answer `CatalogRequestMessage` as a
> Provider). `docker-compose.yml` and `tck.properties` have been moved to
> `historical/` unmodified, and are kept as a record of the real,
> `dsp-tck`-verified run described below - they are not expected to run
> against this codebase again, and should not be re-run against a rebuilt
> DSP-serving endpoint; there won't be one. The baseline log
> (`baseline-run-2026-08-27.log`) is untouched. Everything below this note
> describes the harness as it existed at the time it was run.

# DSP TCK compliance environment

A minimal harness for running the official
[Dataspace Protocol Technology Compatibility Kit](https://github.com/eclipse-dataspacetck/dsp-tck)
(`dsp-tck`) against this project's `http-api`, per
[the `dataspace` study repo's TCK spike](https://labs.deepthought-solutions.net/Deepthought-Solutions/dataspace/src/branch/main/docs/spikes/2026-08-27-dataspacetck-compliance-suites.md).

## Layout

- `docker-compose.yml` — runs the published `eclipsedataspacetck/dsp-tck-runtime`
  image. It does **not** run `http-api` itself: the TCK talks to the CUT
  (connector under test) over plain HTTP, so `http-api` runs directly on
  the host and the container reaches it via `host.docker.internal`
  (`extra_hosts: host-gateway`), matching the TCK's own documented
  pattern for this exact scenario.
- `tck.properties` — CUT connection config, mounted into the container at
  `/etc/tck/config.properties`. Trimmed from `dsp-tck`'s own
  `sample.tck.properties` to what a first baseline run needs.

## Running it

```bash
# 1. Build and run http-api on the host, bound to all interfaces so the
#    dsp-tck container can reach it (127.0.0.1 alone is not reachable
#    from inside the container).
cargo build --release -p http-api
HTTP_API_ADDR=0.0.0.0:18080 ./target/release/http-api &

# 2. Run the TCK against it.
cd compliance
docker compose up --abort-on-container-exit
```

(Port 18080, not 8080: some environments already have something bound to
8080 — adjust both `HTTP_API_ADDR` and `tck.properties`' URLs together if
you change it.)

## Result of the first baseline run (2026-08-27)

**0 / 65 tests passed.** Every test failed with a 404 or a JSON-decode
error on an empty body — expected and correct: `http-api` currently
exposes a small Management-API-style stub (`GET /health`,
`GET /catalog?node_id=...`), not the actual DSP wire protocol. This run
exists to prove the harness works and to get the exact gap list, not to
pass anything yet.

| Group | Failed | What it needs that doesn't exist yet |
|---|---:|---|
| `MET` | 1/1 | `GET /.well-known/dspace-version` — the metadata/version-exposure endpoint |
| `CAT` | 3/3 | `POST /dsp/catalog/request`, `GET /dsp/catalog/datasets/{id}` — the real DSP catalog protocol, distinct from the current `GET /catalog?node_id=` stub |
| `CN` (provider) | 15/15 | `POST /dsp/negotiations/request` and the rest of the contract-negotiation state machine |
| `CN_C` (consumer) | 16/16 | An endpoint at the `dataspacetck.dsp.connector.negotiation.initiate.url` this project controls, so the TCK (acting as provider) can tell the CUT to start a negotiation |
| `TP` (provider) | 15/15 | `POST /dsp/transfers/request` and the transfer-process state machine |
| `TP_C` (consumer) | 15/15 | An endpoint at `dataspacetck.dsp.connector.transfer.initiate.url`, same shape as `CN_C` above |

Full raw log: [`baseline-run-2026-08-27.log`](baseline-run-2026-08-27.log).

## What this means for the roadmap

`MET` and `CAT` are the two groups actually in scope for a Federated
Catalog crawler/cache (per the TCK spike's own read) — `CN`/`CN_C`/`TP`/`TP_C`
are a full connector's concern (contract negotiation, transfer process),
not this project's. Once `http-api` grows a real DSP-facing catalog
endpoint (needed anyway, so the eventual crawler has something
standards-shaped to crawl), re-running this harness against just those
two groups is the concrete "did we get the wire format right" check —
cheaper and more authoritative than hand-testing against the JSON-LD
shape read out of `vendor/eclipse-edc-connector`'s Java source.
