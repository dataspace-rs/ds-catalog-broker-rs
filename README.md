# Semantic Catalog Broker

*(repo/product: `ds-catalog-broker-rs`)*

A from-scratch Rust rewrite of [Eclipse EDC](https://projects.eclipse.org/projects/technology.edc)'s
**Federated Catalog** module, implementing what the [Dataspace Protocol (DSP) spec](https://raw.githubusercontent.com/eclipse-dataspace-protocol-base/DataspaceProtocol/main/catalog/catalog.protocol.md)
calls a **Catalog Broker**:

> "A Catalog Broker is a Consumer that has trusted access to 1..N
> upstream Catalog Services and advertises their respective Catalogs as
> a single Catalog Service. The Catalog Broker SHOULD honor upstream
> access control requirements (Policies)."
> — [`catalog.protocol.md`, "Catalog Brokers"](https://raw.githubusercontent.com/eclipse-dataspace-protocol-base/DataspaceProtocol/main/catalog/catalog.protocol.md)

It periodically **harvests** DSP catalogs from 1..N configured
participants as a DSP **Consumer**, decomposes them into a **semantic
cache** (an Oxigraph-backed RDF triple store), and serves that cache
through a small non-DSP HTTP API. It never answers an incoming DSP
`CatalogRequestMessage` — that's a dataspace participant's *other*
connector components' job, the ones this product crawls.

## Role and serving surfaces

A Catalog Broker is a DSP **Consumer**, nothing more on the wire — it
issues `CatalogRequestMessage`s to upstream Catalog Services and manages
the results, but never becomes a Catalog Service itself. `crawl_once`
issues one separate `POST .../catalog/request` per participant; DSP has
no combined "give me everyone's catalog" request.

Three serving surfaces, all non-DSP:

- **`GET /catalog?node_id=`** — dataset list per participant.
- **`GET`/`POST /sparql`** — SPARQL 1.1 Protocol over the whole cache
  (all named graphs by default), read-only. See
  `rdf_store::oxigraph_backend::OxigraphCatalogCache::sparql_query_json`'s
  doc comment for the full contract.
- **`POST /api/management/v4/catalogs/request`** — wire-compatible with
  real EDC Federated Catalog UI tooling
  (`edc-federated-catalog-client`'s `list_offers`/`get_offer_by_dataset_id`):
  a `QuerySpec`-shaped request, a `Vec<FederatedCatalogOffer>` response.
  `hasPolicy` carries a crawled dataset's real ODRL policies (atomic
  constraints only, see "Known gaps");
  `title`/`description`/`version`/`creator`/`thumbnail`/`keywords` are
  populated whenever a crawled dataset carries them.

All three can be gated behind an **OAuth2 Bearer** resource-server check
(JWT + JWKS) — opt-in via `OAUTH2_JWKS_URI`, unauthenticated by default,
independent of DCP (which stays scoped to the crawler's holder role
below). See
[`docs/oauth2-bearer-gating-2026-08-28.md`](docs/oauth2-bearer-gating-2026-08-28.md).

![This product implements the DSP spec's own Catalog Broker role: a Consumer with trusted access to 1..N Catalog Services, harvesting them into a semantic cache, served only via a dataset list, SPARQL, and a management API - never a DSP catalog-serving endpoint](docs/diagrams/harvester-deployment.svg)

## Crates

Rust crates rather than Java SPI modules, echoing EDC's `crawler-spi` /
`federated-catalog-spi` split:

- `catalog-core` — domain types: participant/node id, crawl work item,
  `Catalog`/`Dataset`/`DataService`, and a real ODRL `Policy`/`Rule`/
  `Constraint` model (atomic constraints only).
- `rdf-store` — the semantic cache: `CatalogCache` trait, in-memory and
  Oxigraph-backed implementations. See ["The RDF backend"](#the-rdf-backend-semantic-cache).
- `dcp-core` — DCP JWS sign/verify and `did:web` primitives, used by
  `crawler`'s **holder** role to present this participant's own
  credential to a gated Catalog Service.
- `crawler` — participant registry, scheduled crawl loop
  (`spawn_scheduler`/`crawl_once`), a DSP-response parser tolerant of
  real EDC's JSON-LD shape, and per-participant credential presentation:
  **DCP** or **OID4VP** (single-shot `vp_token`/`presentation_submission`,
  reusing `dcp-core`'s JWS/`did:web` primitives). See
  [`docs/oid4vp-holder-2026-08-28.md`](docs/oid4vp-holder-2026-08-28.md).
- `ds-catalog-broker-rs` — the HTTP surface: `/catalog`, `/sparql`, the
  management API, and the DCP holder routes.

![Outbound credential presentation when crawling a gated participant: crawl_one reads each participant's configured credential protocol - a fixed placeholder header when none is required, a directly-attached self-issued DCP token, or an OID4VP vp_token/presentation_submission exchange that returns a short-lived access token - all converging on the same Authorization: Bearer header attached to the same catalog request](docs/diagrams/harvester-credential-protocols.svg)

Reference implementation (starting point v0.18.0): [eclipse-edc/Connector](https://github.com/eclipse-edc/Connector).
Study and research behind this rewrite lives in the
[`dataspace`](https://labs.deepthought-solutions.net/Deepthought-Solutions/dataspace)
repo (`docs/spikes/`, `docs/adr/`).

## The RDF backend ("semantic cache")

`rdf-store`'s `CatalogCache` trait is backend-agnostic; `oxigraph_backend::OxigraphCatalogCache`
implements it on [Oxigraph](https://crates.io/crates/oxigraph) (via
`contreforts-kg`, an internal wrapper), chosen because a federated
catalog is naturally a set of named graphs and because SPARQL requires a
real triple store. In-memory only, matching EDC's own federated-catalog
cache — crawled data is repopulated on every restart, not durably
stored. `ds-catalog-broker-rs` falls back to a plain `InMemoryCatalogCache`
(a bare `HashMap`) when no harvester is configured.

**Real DCAT triples, not a JSON-blob bridge.** Each crawled `Catalog` is
decomposed into `dcat:Catalog`/`dcat:Dataset`/`dcat:Distribution`/
`dcat:DataService`/`dct:format` triples per named graph, plus real
`odrl:hasPolicy`/`odrl:permission`/`odrl:prohibition`/`odrl:obligation`/
`odrl:constraint` triples for each dataset's harvested policies — see
`rdf_store::oxigraph_backend`'s module doc for the exact mapping.

`Dataset.properties: BTreeMap<String, String>` round-trips transparently
as one `fcns:property/<key>` triple per entry, with no schema change
needed for a new field. `crawler::collect_datasets_and_services` uses
this to carry `title`/`description`/`version`/`creatorName`/`thumbnail`/
`keywords` through to the management API. That mapping's own test only
covers `InMemoryCatalogCache`; the live demo stack
(`ds-labs-org/ds-dev-deployment`) exercises the real Oxigraph path and
was checked manually, but no automated test yet proves the round trip
end to end (see the "Known limitation" note in the module doc).

![Internal architecture of the semantic cache: crawler parses a crawled catalog into a domain value plus a generic properties bag, upserts both through the CatalogCache trait, OxigraphCatalogCache stores one named graph per origin node as real DCAT triples plus one triple per property, and the two serving surfaces (catalog cache API, management API) read the triples and the decoded properties back out via SPARQL](docs/diagrams/semantic-cache-architecture.svg)

## Known gaps

ODRL policies are preserved and propagated end to end — crawl, semantic
cache, management API — but only *atomic* constraints
(`leftOperand`/`operator`/`rightOperand`); nested logical-constraint
groups (`odrl:and`/`odrl:or`/`odrl:xone`) aren't modeled, and a crawled
constraint shaped that way is skipped rather than guessed at. Whether the
broker should also *filter* what it re-serves based on policy (e.g. hide
a dataset a given caller isn't entitled to) is a genuinely open design
question this product does not currently answer — nothing filters on
policy content today. See
[`docs/gap-analysis-2026-08-27.md`](docs/gap-analysis-2026-08-27.md) §3.4
for history and the full punch list.

## Vendored dependencies

`contreforts-kg` and its own dependencies (`contreforts-core`,
`contreforts-config`) are git submodules under `vendor/`, and real
members of this workspace — this repo's root `Cargo.toml` decides their
shared dependency versions and feature defaults. See
[`vendor/README.md`](vendor/README.md) for details and a known metadata
caveat.

**No RocksDB.** Oxigraph's default build pulls in `oxrocksdb-sys`
(from-source C++/cmake) for on-disk persistence this product never uses
— see `crates/rdf-store/Cargo.toml`'s comment on the `contreforts-kg`
dependency line for how that got removed.

## Benchmarks

[`compliance/harvest-benchmark-2026-08-27.md`](compliance/harvest-benchmark-2026-08-27.md)
benchmarks the harvester against Eclipse EDC's own federated-catalog
crawler; the `ds-dev-deployment` demo stack reuses its exact
participant/dataset scale (2 participants, 10 datasets).

## Layout

```
crates/
  catalog-core/           domain types
  rdf-store/               CatalogCache trait + in-memory/Oxigraph implementations
  dcp-core/                DCP JWS/did:web primitives (crawler's holder role)
  crawler/                 crawl engine
  ds-catalog-broker-rs/    HTTP surface: /catalog, /sparql, management API, DCP holder routes
docs/
  diagrams/                    architecture SVGs referenced from this README
  gap-analysis-2026-08-27.md   how this product's scope was settled
vendor/
  contreforts-kg/          Oxigraph wrapper - rdf-store's real backend
  contreforts-core/        contreforts-kg's dependency
  contreforts-config/      contreforts-kg's dependency (a second Oxigraph store)
compliance/
  harvest-benchmark-2026-08-27.md   harvester-vs-EDC benchmark report
  crawler-edc-fixture/                real EDC 0.18.0 participant fixtures
  harvest-bench/                      benchmark driver
```

## Building and testing

```bash
cargo build -p catalog-core -p rdf-store -p ds-catalog-broker-rs -p dcp-core -p crawler
cargo test  -p catalog-core -p rdf-store -p ds-catalog-broker-rs -p dcp-core -p crawler
```

Not `--workspace`: `vendor/contreforts-kg` is a real workspace member,
and `--workspace` would activate its own default `rocksdb` feature (a
capability its own tests need, not a bug). Scoping to these five crates
— exactly what `.github/workflows/ci.yml`'s `PRODUCT_CRATES` builds —
keeps a real build of this product free of that dependency.

## License

Apache-2.0, matching upstream Eclipse EDC. See [LICENSE](LICENSE).
