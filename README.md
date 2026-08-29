# Semantic Catalog Broker

*(repo name: `ds-catalog-broker-rs`; product binary/crate: `ds-catalog-broker-rs`, `crates/http-api` before this project's rebrand)*

An iterative, from-scratch Rust rewrite of [Eclipse EDC](https://projects.eclipse.org/projects/technology.edc)'s
**Federated Catalog** module, built around what the [Dataspace Protocol (DSP) specification](https://raw.githubusercontent.com/eclipse-dataspace-protocol-base/DataspaceProtocol/main/catalog/catalog.protocol.md)
itself calls a **Catalog Broker**:

> "A Dataspace MAY include Catalog Brokers. A Catalog Broker is a
> Consumer that has trusted access to 1..N upstream Catalog Services
> and advertises their respective Catalogs as a single Catalog Service.
> The Catalog Broker SHOULD honor upstream access control requirements
> (Policies)."
> — [`catalog.protocol.md`, "Catalog Brokers"](https://raw.githubusercontent.com/eclipse-dataspace-protocol-base/DataspaceProtocol/main/catalog/catalog.protocol.md)

Concretely: this product periodically **harvests** (crawls) DSP catalogs
from 1..N configured participants as a DSP **Consumer**, maintains the
result in a unified **semantic cache** (an RDF/Oxigraph-backed triple
store — see ["The RDF backend"](#the-rdf-backend-semantic-cache) below),
and serves that cache locally as (a) a dataset list per participant and
(b) a SPARQL endpoint for searching across everything harvested. See
["Role: a DSP Catalog Broker"](#role-a-dsp-catalog-broker) below for what
that does and does not include.

## What this is (and isn't)

This is a rewrite, not a port. The goal is a Federated Catalog that
behaves like EDC's — a crawler periodically pulls catalogs from known
dataspace participants and makes the aggregate queryable — designed from
scratch in Rust, taking the *shape* of the problem from EDC's Java
implementation without transliterating its classes, package layout, or
internal abstractions.

**It is not a general-purpose DSP connector.** It does not, and should
not, answer incoming DSP `CatalogRequestMessage`s, negotiate contracts,
or transfer data. Those are the job of a dataspace participant's *other*
connector components — the ones this product addresses when it crawls
them. Conflating the two was an early mistake in this project (this
product's own `ds-catalog-broker-rs` crate (then named `http-api`) used to
expose a `POST /dsp/catalog/request`
provider endpoint) — see
[`docs/gap-analysis-2026-08-27.md`](docs/gap-analysis-2026-08-27.md) for
the corrective work that follows from fixing it.

The rewrite proceeds crate by crate, iteration by iteration: each crate
starts as a minimal skeleton that compiles and passes its own tests, and
gets built out once the next layer needs more from it. Nothing here is
meant to be feature-complete on first commit.

## Role: a DSP Catalog Broker

A Catalog Broker is a DSP **Consumer**, nothing more on the wire: it
issues `CatalogRequestMessage`s to upstream Catalog Services and manages
the results — it never becomes a Catalog Service itself just because it
aggregates. The spec is explicit that federation has no dedicated
request/response pair of its own:

> "The Catalog Protocol is designed to be used by federated services
> without the need for a replication protocol. Each Consumer is
> responsible for issuing requests to 1..N Catalog Services, and managing
> the results."
> — [`catalog.protocol.md`, "Replication Protocol"](https://raw.githubusercontent.com/eclipse-dataspace-protocol-base/DataspaceProtocol/main/catalog/catalog.protocol.md)

So `crawl_once` issues one separate `POST .../catalog/request` per
configured participant — never a combined "give me everyone's catalog"
request, because there is no such request in DSP.

**This product's only three serving surfaces are non-DSP:**

- A **dataset list per participant**: `GET /catalog?node_id=`, an
  internal Management-API-style endpoint. The gap analysis (§3.1)
  weighed redesigning this path (e.g. `GET /participants/{id}/datasets`)
  now that it's a first-class serving surface rather than a
  pre-crawler-era stub, and decided to keep it as-is — see that section
  for the reasoning.
- A **SPARQL endpoint**, `GET`/`POST /sparql`, over the whole semantic
  cache (all named graphs, by default), for ad hoc search across
  everything harvested — following the SPARQL 1.1 Protocol closely
  enough for standard tooling (`query` via GET query string or POST
  form-encoded body, `Accept`-negotiated `application/sparql-results+json`,
  read-only by construction), and only available when this connector is
  running the Oxigraph-backed cache. See the gap analysis §3.3 and
  `rdf_store::oxigraph_backend::OxigraphCatalogCache::sparql_query_json`'s
  doc comment for the full contract.
- A **federated-catalog management API**, `POST /api/management/v4/catalogs/request`
  — the exact wire shape real EDC Federated Catalog UI tooling
  (`edc-federated-catalog-client`'s `list_offers`/`get_offer_by_dataset_id`)
  already expects: a `QuerySpec`-shaped request body (optionally filtering
  on `datasets.id`), a `Vec<FederatedCatalogOffer>` response in the real
  DCAT/ODRL JSON-LD shape that crate deserializes, one offer per cached
  catalog. `hasPolicy` is always present but empty per dataset (still the
  same open ODRL gap, §3.4 below) — everything else (`title`,
  `description`, `version`, `creator`, `thumbnail`, `keywords`) is
  genuinely populated when a crawled dataset carries that data in its own
  `properties` bag. This is what lets an existing, unmodified
  federated-catalog UI component point at this broker instead of a full
  EDC connector's Management API for the catalog view specifically.

All three surfaces can be gated behind a real **OAuth2 Bearer**
resource-server check (a JWT access token, verified against a configured
JWKS) — opt-in via `OAUTH2_JWKS_URI`, off (unauthenticated, unchanged) by
default. This is deliberately *not* a revival of the removed
`DspAuthMode` gating system above, nor DCP (which stays scoped to the
crawler's own holder role, see below) — a standard OAuth2
resource-server check for a machine-to-machine API, independent of
either. See
[`docs/oauth2-bearer-gating-2026-08-28.md`](docs/oauth2-bearer-gating-2026-08-28.md)
for the full design and wire shapes.

**It deliberately does not implement a DSP catalog-serving endpoint at
all.** Answering `CatalogRequestMessage` — including presenting *this*
participant's own catalog to other participants — is the job of that
participant's other connector components, not this product. This also
settles where the harvested aggregate belongs: never re-served as if it
were one participant's own DSP catalog (the DSP `Catalog` schema's own
nested-catalog example has no `participantId` on nested entries and
represents a fetchable sub-catalog reference, not another party's
inlined content — inlining foreign participants under it would misuse
the field).

The spec also says a broker "SHOULD honor upstream access control
requirements (Policies)" — i.e., a harvested dataset's own usage
policy/access restrictions should be preserved and respected when this
broker re-serves it, not silently dropped. `catalog-core`'s `Dataset`
has no real ODRL policy model yet, so this is currently **not** honored
— tracked as a real gap, not an oversight (see the gap analysis).

![This product implements the DSP spec's own Catalog Broker role: a Consumer with trusted access to 1..N Catalog Services, harvesting them into a semantic cache, served only via a dataset list and SPARQL - never a DSP catalog-serving endpoint](docs/diagrams/harvester-deployment.svg)

## Relationship to Eclipse EDC Federated Catalog

Eclipse EDC's Federated Catalog crawls a directory of known target nodes,
fetches their Dataspace Protocol (DSP) catalogs, and caches the result so
it can be queried locally without crawling on every request. The
reference implementation (Java, Gradle, OSGi-style extension model) lives
upstream at [eclipse-edc/Connector](https://github.com/eclipse-edc/Connector);
this repo's starting point is v0.18.0 of that project.

The crate boundaries here echo the module boundaries EDC draws between
its `crawler-spi` (generic, protocol-agnostic crawling contracts) and
`federated-catalog-spi` (the catalog-specific cache and query layer on
top), but as separate Rust crates rather than Java SPI modules:

- `catalog-core` — domain types, loosely modeled on EDC's
  `federated-catalog-spi` / `catalog-spi`: a participant/node identifier,
  a crawl work item, and the `Catalog` / `Dataset` / `DataService` model.
  No ODRL policy model yet (see "Role" above).
- `rdf-store` — the semantic cache: a storage-agnostic `CatalogCache`
  trait, an in-memory implementation, and an Oxigraph-backed
  implementation. See ["The RDF backend"](#the-rdf-backend-semantic-cache).
- `dcp-core` — shared Decentralized Claims Protocol (DCP) JWS sign/verify
  and `did:web` resolution primitives, used by `crawler`'s **holder**
  role: presenting *this* participant's own credential when a remote
  Catalog Service it's crawling requires one, a legitimate Consumer-side
  concern this product keeps (the DCP *verifier* role that used to live
  here gated the now-removed DSP-serving endpoint and was removed with
  it — see the gap analysis §1.2).
- `crawler` — the crawl engine: a local-config participant registry, a
  scheduled crawl loop (`spawn_scheduler`/`crawl_once`), a lenient
  DSP-response parser tolerant of real Eclipse EDC's JSON-LD shape (not
  just this project's own), and, per participant, a choice of credential
  protocol to present when one is required: **DCP** (above) or
  **OID4VP** (OpenID for Verifiable Presentations) — a single-shot
  `vp_token`/`presentation_submission` exchange reusing `dcp-core`'s same
  JWS/`did:web` primitives rather than a second crypto stack. See
  [`docs/oid4vp-holder-2026-08-28.md`](docs/oid4vp-holder-2026-08-28.md)
  for why OID4VP exists alongside DCP here, what's simplified in this
  first pass, and the exact wire shapes.
- `ds-catalog-broker-rs` — this product's own HTTP surface (crate/binary
  name; `crates/http-api` until this project's rebrand): `GET /catalog`
  (dataset list per participant), `GET`/`POST /sparql` (the SPARQL
  endpoint), `POST /api/management/v4/catalogs/request` (the
  federated-catalog management API), and the DCP holder routes. The DSP
  catalog-serving endpoint that used to live here has been removed per
  the gap analysis §1.

![Outbound credential presentation when crawling a gated participant: crawl_one reads each participant's configured credential protocol - a fixed placeholder header when none is required, a directly-attached self-issued DCP token, or an OID4VP vp_token/presentation_submission exchange that returns a short-lived access token - all converging on the same Authorization: Bearer header attached to the same catalog request](docs/diagrams/harvester-credential-protocols.svg)

## Relationship to the `dataspace` study repo

This project originates from prior research done in the
[`dataspace`](https://labs.deepthought-solutions.net/Deepthought-Solutions/dataspace)
repository — a study of what's needed to deploy an EDC connector able to
host multiple participants. That repo's `docs/spikes/` directory holds
time-boxed, non-binding research spikes on the surrounding ecosystem
(other EDC-based connectors, integration points, framework comparisons),
and its `docs/adr/` directory records the architecture decisions that came
out of that research. The crawler architecture, cache semantics, and
query API described above were reconstructed there by reading EDC's
source directly (vendored as a submodule in that repo) before any Rust
code was written here.

## The RDF backend ("semantic cache")

`rdf-store` defines the cache trait as backend-agnostic on purpose. EDC
itself supports multiple `FederatedCatalogCache` backends (in-memory,
Postgres via a JSON column) behind one SPI; this project has landed on an
actual RDF store — since a federated catalog is naturally a set of named
graphs, and because a real triple store is what makes the SPARQL surface
in "Role" above possible at all. A research spike in the `dataspace`
repo's `docs/spikes/` surveyed the Rust RDF/quad-store ecosystem and
recommended [Oxigraph](https://crates.io/crates/oxigraph) as the target
backend, and `rdf-store`'s `oxigraph_backend::OxigraphCatalogCache`
implements `CatalogCache` on top of it — via `contreforts-kg`, an
existing internal Oxigraph wrapper from a separate private repo, rather
than the bare `oxigraph` crate directly.

`ds-catalog-broker-rs` uses this backend whenever a harvester config is supplied
(`CRAWLER_CONFIG_PATH` set) — in-memory Oxigraph only, matching EDC's own
federated-catalog cache, which has no on-disk persistence option either;
crawled data is expected to be repopulated on every restart, not durably
stored. With no harvester configured, `ds-catalog-broker-rs` falls back to a plain
`InMemoryCatalogCache` (a bare `HashMap`, not RDF-backed at all).

**A real triple store, not a JSON-blob bridge.** Past the original
"first cut" (one opaque `catalogJson` literal per named graph),
`OxigraphCatalogCache` now decomposes each crawled `Catalog` into real
DCAT-based triples (`dcat:Catalog`/`dcat:Dataset`/`dcat:Distribution`/
`dcat:DataService`, `dct:format`, ...) per named graph, so dataset
properties, formats, and distribution/service links are genuinely
SPARQL-queryable — see `rdf_store::oxigraph_backend`'s own module doc for
the exact mapping (gap analysis §3.2). No ODRL `Offer`/`Policy` triples
are emitted yet, since `catalog-core::Dataset` has no such field to
derive them from (gap analysis §3.4, still open).

`catalog-core::Dataset` also carries a generic `properties: BTreeMap<String, String>`
bag, and `OxigraphCatalogCache` round-trips it transparently — one
`fcns:property/<key>` triple per entry on write, decoded back into the
same map on read — with no schema change needed for a new field.
`crawler::collect_datasets_and_services` uses exactly this to carry each
crawled dataset's `title`/`description`/`version`/`creatorName`/
`thumbnail`/`keywords` (when the source DSP catalog provides them)
straight through to the `POST /api/management/v4/catalogs/request`
surface's `edc-federated-catalog-client`-compatible response. That
mapping's own wire-shape test only exercises it against the plain
`InMemoryCatalogCache`, not a real `OxigraphCatalogCache`; the live demo
stack (`ds-labs-org/ds-dev-deployment`) does exercise the full chain and
was checked manually, but no automated test yet proves these fields
survive a real Oxigraph round-trip end to end (see the "Known
limitation" note in `rdf_store::oxigraph_backend`'s module doc).

![Internal architecture of the semantic cache: crawler parses a crawled catalog into a domain value plus a generic properties bag, upserts both through the CatalogCache trait, OxigraphCatalogCache stores one named graph per origin node as real DCAT triples plus one triple per property, and the two serving surfaces (catalog cache API, management API) read the triples and the decoded properties back out via SPARQL](docs/diagrams/semantic-cache-architecture.svg)

## Current status vs. target scope

The sections above describe the **corrected target scope** (Catalog
Broker role, semantic cache, dataset-list + SPARQL serving). The
codebase does not fully match it yet. The DSP catalog-*serving* surface
this README used to describe as scope creep (`POST /dsp/catalog/request`,
`GET /dsp/catalog/datasets/{id}`, `.well-known/dspace-version`, the
`DspAuthMode`/`DspAuthConfig` gating system, and the DCP *verifier* role
that protected it) has since been removed, per
**[`docs/gap-analysis-2026-08-27.md`](docs/gap-analysis-2026-08-27.md)**
§1 — `ds-catalog-broker-rs` no longer answers `CatalogRequestMessage`s at
all. Real RDF decomposition of the semantic cache (§3.2) and the SPARQL
endpoint (§3.3) have since landed too, and §3.1 (the dataset-list
endpoint's shape) has been settled (kept as-is). What's still genuinely
missing: honoring upstream ODRL policies (§3.4) — see that same
document's §3 for the concrete punch list, and §2 for what was already
correctly scoped and untouched (the crawl engine and the DCP *holder*
role).

## Vendored dependencies

`contreforts-kg` and its own two hard dependencies (`contreforts-core`,
`contreforts-config`) are vendored as git submodules under `vendor/` and
are real members of this workspace - not a separate, excluded one - so
this repo's own root `Cargo.toml` decides their shared dependency
versions and feature defaults. See [`vendor/README.md`](vendor/README.md)
for what's vendored, why, and a known metadata caveat (inherited
`license`/`edition` on those crates doesn't match their own upstream
`Cargo.toml`).

**No RocksDB.** Oxigraph's own default build pulls in `oxrocksdb-sys` (a
from-source C++/cmake build) for on-disk persistence this product never
uses (see "The RDF backend" above: in-memory only, by design). It cost
real build time for nothing - `crates/rdf-store/Cargo.toml`'s own comment
on its `contreforts-kg` dependency line has the full story of where that
dependency was actually coming from and how it was removed, entirely
without shipping a persistence feature this product doesn't need.

## Compliance and benchmarks (historical — being re-scoped)

[`compliance/`](compliance/) holds the record of this project's DSP-facing
work to date, including the `dsp-tck` compliance harness
(`MET:01-01`/`CAT:01-01/02/03` passing) and three benchmark reports
comparing `http-api`'s former DSP catalog-serving endpoint and this
product's harvester against Eclipse EDC 0.18.0. **These targeted the
DSP-serving surface the gap analysis above retires** — kept as an
honest historical record of real, verified work (each report documents
its own methodology and real captured evidence), not as an ongoing
compliance target for this product going forward:

- [`benchmark-2026-08-27.md`](compliance/benchmark-2026-08-27.md) — DSP
  catalog-request throughput/memory and a full wire-format fidelity
  comparison against the now-retired endpoint.
- [`benchmark-dcp-2026-08-27.md`](compliance/benchmark-dcp-2026-08-27.md) —
  real DCP auth overhead vs. a no-auth baseline and EDC's stub auth
  (the DCP *verifier* role this exercised is also being retired with the
  endpoint it gated; the DCP *holder* role it also covers stays in scope).
- [`harvest-benchmark-2026-08-27.md`](compliance/harvest-benchmark-2026-08-27.md) —
  the harvester itself (still correctly scoped) vs. EDC's own federated-
  catalog crawler, though it currently reads results back via the
  soon-to-be-retired DSP endpoint as a stand-in for the dataset-list
  surface — see the gap analysis for the planned replacement.

## Layout

```
crates/
  catalog-core/   domain types (Catalog, Dataset, DataService, TargetNode, CrawlWorkItem)
  rdf-store/      CatalogCache trait + in-memory and Oxigraph-backed ("semantic cache") implementations
  dcp-core/       shared DCP JWS/did:web primitives (verifier + holder roles)
  crawler/        the crawl engine: participant registry, scheduled crawl loop, DSP response parser
  ds-catalog-broker-rs/  this product's HTTP surface - being corrected, see docs/gap-analysis-2026-08-27.md
docs/
  diagrams/                   architecture SVGs referenced from this README
  gap-analysis-2026-08-27.md  what to remove/keep/build to match the Catalog Broker scope
vendor/
  contreforts-kg/      Oxigraph wrapper (GraphStore, QueryEngine) - rdf-store's real backend
  contreforts-core/    contreforts-kg's own dependency (shared error/connector types)
  contreforts-config/  contreforts-kg's own dependency (a second, separate Oxigraph store)
compliance/
  README.md                  dsp-tck compliance harness (historical - see gap analysis)
  benchmark-*.md              three benchmark reports (historical - see gap analysis)
  crawler-edc-fixture/        real EDC 0.18.0 participant fixtures, built from Maven Central
  harvest-bench/              end-to-end harvester-vs-EDC benchmark driver
```

## Building and testing

```bash
cargo build -p catalog-core -p rdf-store -p ds-catalog-broker-rs -p dcp-core -p crawler
cargo test  -p catalog-core -p rdf-store -p ds-catalog-broker-rs -p dcp-core -p crawler
```

Not `--workspace`: `vendor/contreforts-kg` is a real workspace member
(see "Vendored dependencies" above), and `--workspace` selects it
directly too - which activates its *own* default `rocksdb` feature (a
real capability that crate's own test suite genuinely needs, not a bug
on its part) regardless of what this product's own crates request on
their dependency edge to it. Scoping to these five crates - exactly
what `.github/workflows/ci.yml`'s `PRODUCT_CRATES` also builds - is what
keeps a real build of this product itself free of that dependency; see
the RocksDB note above.

## License

Apache-2.0, matching upstream Eclipse EDC. See [LICENSE](LICENSE).
