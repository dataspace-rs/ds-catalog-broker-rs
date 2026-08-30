# Gap analysis: realigning to the Catalog Broker scope

**Date:** 2026-08-27
**Status:** analysis only — nothing in this document has been implemented yet. It exists
to lead a later, separate corrective implementation pass.

## Why this document exists

This project's scope was corrected (project-owner directive, 2026-08-27, informed by
reading the actual [Dataspace Protocol specification](https://raw.githubusercontent.com/eclipse-dataspace-protocol-base/DataspaceProtocol/main/catalog/catalog.protocol.md),
not just its JSON schemas): this product is a DSP **Catalog Broker** — a Consumer that
harvests 1..N upstream Catalog Services into one semantic cache and serves that cache
locally (dataset list + SPARQL). It is **not** a general-purpose DSP connector, and it
must **not** answer incoming `CatalogRequestMessage`s — that is the job of the
participant's *other* connector components, i.e. the very components this product
addresses when it crawls them.

The codebase currently does not match that scope: `http-api` grew a real,
`dsp-tck`-verified DSP catalog-*serving* endpoint (built and hardened across several
earlier rounds of this project, including a real bug-fix pass and a benchmark
comparison against Eclipse EDC). That work was real, verified, and not wasted — but it
answers a question this product should never have been asked in the first place. This
document is the punch list to correct that, cleanly, without losing the parts that are
already correctly scoped.

See also: `README.md`'s ["Role: a DSP Catalog Broker"](../README.md#role-a-dsp-catalog-broker)
section, which this document backs up with the concrete file/route/type inventory.

## 1. What must be REMOVED

All of the following exist only to answer `CatalogRequestMessage` as a Provider, or to
gate that endpoint — both out of scope once this product stops serving DSP at all.

### 1.1 `crates/http-api/src/lib.rs`

| Item | Why it goes |
|---|---|
| `POST /dsp/catalog/request` route + `catalog_request()` handler | The DSP catalog-serving endpoint itself. |
| `GET /dsp/catalog/datasets/{id}` route + `get_dsp_dataset()` handler | Same surface, by-id lookup variant. |
| `GET /.well-known/dspace-version` route + `dspace_version()` handler | DSP metadata discovery — only meaningful for a DSP-serving connector. |
| `GET /dsp/did.json` route + `own_did_document_route()` | The DCP *verifier* role's own DID document — exists only to let a caller resolve the key that gates the catalog-request endpoint above. Goes with it. |
| `DspAuthConfig`, `DspAuthMode` (`Disabled`/`Bearer`/`Dcp`), `authorize()`, `visible_datasets()`, `unauthorized_response()` | The whole per-caller catalog-filtering/gating system built specifically to protect the endpoint above. |
| `DspCatalog`, `DspDataset`, `DspOffer`, `DspDistribution`, `DspDataService`, `DspCatalogError`, `placeholder_offer()`, `new_urn_uuid()` (if unused elsewhere), `flatten_cache()`, `flatten_catalogs()`, `DSP_CONTEXT_URL`, `CONNECTOR_PARTICIPANT_ID` | The DSP JSON-LD wire-format types and helpers that only exist to build the catalog-request response body. |
| All `#[cfg(test)]` coverage for the above (`dsp_catalog_request_*`, `dsp_dataset_lookup_*`, `catalog_endpoint_serves_seeded_sample_catalog`'s DSP-shape assertions, the nested-catalog RED/GREEN tests from the previous correction round) | Tests for code that no longer exists. |

**Keep**: `AppState.holder: Option<Arc<HolderIdentity>>`, `GET /dsp/holder/did.json`,
`POST /dsp/holder/presentations/query`, and their handlers — see §2.

### 1.2 `crates/http-api/src/dcp.rs`

The whole module is the DCP **verifier** role (`DcpConfig`, `verify_dcp_bearer_token`) —
it exists only to check an *incoming* caller's credential before answering a DSP
catalog request. With no DSP catalog request to answer, there is no incoming caller to
check. Remove the module and its `dcp-core` re-exports that exist only to support it
(confirm none of `DcpKeyPair`'s shared primitives it also happens to use are otherwise
needed by the holder role in `dcp-core` before deleting wholesale — they shouldn't be,
since `HolderIdentity` already depends on `dcp-core` directly, not on this module).

### 1.3 `crates/http-api/src/main.rs`

- `load_dsp_auth()` and its env vars (`DSP_AUTH_MODE`, `DSP_CATALOG_ACCESS`,
  `DSP_DCP_OWN_DID_HOST`, `DSP_DCP_INSECURE_HTTP`, `DSP_DCP_REQUIRED_SCOPE`) — configures
  the gating system being removed.
- The `.with_dsp_auth(dsp_auth)` call and the `dsp_auth.mode == DspAuthMode::Bearer`/`Dcp`
  log lines.

**Keep**: `load_crawler_config()`, `build_holder()`, the `CRAWLER_CONFIG_PATH` branch that
picks `OxigraphCatalogCache` vs `InMemoryCatalogCache`, `seed_sample_catalog` (though see
§3.3 on whether it still makes sense once there's no DSP endpoint to demo it through).

### 1.4 `compliance/`

- `compliance/docker-compose.yml`, `compliance/tck.properties` — the `dsp-tck` harness.
  Retire (don't delete outright without saying so — see the standing project rule about
  not silently discarding another round's work; move under a clearly-labeled
  `compliance/historical/` or annotate `compliance/README.md` as historical, whichever
  the implementer judges cleaner) since there is no DSP endpoint left to certify.
- `compliance/benchmark-2026-08-27.md`, `compliance/benchmark-dcp-2026-08-27.md` — mark
  historical (README.md already does this). Do not re-run them against a rebuilt
  DSP-serving endpoint; there won't be one.
- `compliance/harvest-benchmark-2026-08-27.md` and `compliance/harvest-bench/` — the
  *crawling* half of this stays relevant (harvesting real EDC participants is exactly
  this product's job), but its Rust-side correctness check currently reads results back
  via `POST /dsp/catalog/request` (see `compliance/harvest-bench/check_catalog.py`) —
  needs to be repointed at whatever replaces it (§3.1) once that exists.

## 2. What is ALREADY correctly scoped — do not remove

- **`crates/crawler`** in full: `ParticipantsConfig`/`ParticipantEntry`, `crawl_once`,
  `spawn_scheduler`, the lenient DSP-response *parser* (`parse_catalog_response`,
  `collect_datasets_and_services`, including its "federation of federations" nested-`catalog[]`
  flattening). This is the Consumer-role crawl engine — exactly this product's job.
- **The DCP *holder* role**: `dcp_core::HolderIdentity` (`mint_self_issued_token`,
  `answer_presentation_query`, `own_did_document`), and in `http-api`:
  `GET /dsp/holder/did.json`, `POST /dsp/holder/presentations/query`, and
  `AppState.holder`. This is *this participant's own* credential-presentation capability
  for crawling a DCP-gated remote participant — a legitimate Consumer-side concern, not
  DSP catalog-serving. `dcp-core`'s shared JWS/`did:web` primitives stay in full, since
  the holder role depends on them directly.
- **`rdf-store`**: the `CatalogCache` trait and both implementations. Backend-agnostic
  design was correct; only the Oxigraph backend's internal representation needs work
  (§3.2), not the trait or the choice of Oxigraph itself.
- **`GET /catalog?node_id=`**: the dataset-list-per-participant surface. Already
  non-DSP, already roughly the right shape — see §3.1 for whether its exact response
  shape should change.

## 3. What is MISSING — real work, not just deletion

### 3.1 Confirm/redesign the dataset-list endpoint's final shape

`GET /catalog?node_id=` already returns `{ catalogs: Vec<Catalog> }` via the domain
type, which already matches "a list of datasets per participant." Decide: keep this
path/shape as the product's one dataset-list surface, or redesign it now that it's a
first-class, only-serving-surface (e.g. a path like `GET /participants/{id}/datasets`)
rather than a leftover "stub" from before the crawler existed. Either way, this is what
`compliance/harvest-bench/check_catalog.py` and the harvest benchmark's own correctness
checks should be repointed at once `POST /dsp/catalog/request` is gone.

### 3.2 Real RDF decomposition (the actual "unified triple store")

Today's `OxigraphCatalogCache` stores one opaque JSON-literal triple per named graph
(see `rdf-store`'s own module docs, and `docs/diagrams/semantic-cache-architecture.svg`).
That is not queryable by SPARQL in any meaningful way — you can find out that a graph
exists, not search by dataset format, policy, or any other property. This is the
single largest piece of real engineering work this gap analysis identifies:

- Choose and document a triple mapping for `Catalog`/`Dataset`/`Distribution`/
  `DataService` — reuse DCAT/ODRL vocabulary terms where they fit, matching what DSP
  itself does ("The Catalog Protocol reuses properties from the DCAT and ODRL
  vocabularies" — `catalog.protocol.md`, "Introduction"), rather than inventing a new
  one. This is a real design decision worth writing up on its own (an ADR-equivalent
  record, per this project's own conventions for consequential decisions), not a
  drive-by refactor.
  This also directly enables §3.4 (propagating ODRL policy/access-control information),
  since without real `Offer`/`Policy` triples there is nothing to propagate.
- Update `OxigraphCatalogCache::upsert`/`query` to write/read real triples per named
  graph instead of one JSON blob, without changing the `CatalogCache` trait's own
  signature (the trait itself is correctly scoped — see §2).
- Re-verify `crawler`'s own tests (`crates/crawler/tests/*`) and `rdf-store`'s own tests
  against the new representation — round-tripping through real triples must still
  reproduce the same domain `Catalog` value the JSON-blob version did.

### 3.3 The SPARQL endpoint

Does not exist at all today. Needs, once §3.2 lands:

- An HTTP surface following the [SPARQL 1.1 Protocol](https://www.w3.org/TR/sparql11-protocol/)
  closely enough to be usable by standard SPARQL tooling — `query` parameter over
  `GET`/`POST`, `Accept`-negotiated response format (at minimum
  `application/sparql-results+json`).
  wired to Oxigraph's own query evaluation (via whatever `contreforts_kg::GraphStore`
  exposes for direct SPARQL execution — confirm the exact API surface before assuming
  it's already there).
- A decision on whether this is read-only (near-certainly yes — this product never
  originates data, only harvests it) and whether/how to scope a query to one named
  graph vs. the whole store (both are legitimate use cases: "search everything I've
  harvested" and "search just participant X").
- Tests exercising real SPARQL queries against real harvested data, not just that the
  endpoint returns 200.

### 3.4 Honor upstream access control (ODRL policies)

The Catalog Broker section is explicit: "The Catalog Broker SHOULD honor upstream
access control requirements (Policies)." `catalog-core`'s `Dataset` currently has no
real ODRL policy model (its `hasPolicy`/`Offer` representation in the now-removed
`http-api` DSP layer was a hardcoded placeholder, not derived from anything a crawled
participant actually said — see the historical `compliance/benchmark-2026-08-27.md`'s
fidelity section, point 9). Once real triples exist (§3.2), decide what "honoring" a
harvested policy actually means for a read-only broker with no negotiation capability
of its own — at minimum, this likely means: preserve a harvested dataset's actual
policy/constraint data faithfully in the semantic cache (don't drop it), and make it
available to whatever queries the SPARQL endpoint or dataset-list surface, rather than
inventing a placeholder. Whether this product should also *filter* what it re-serves
based on policy (e.g. not listing a dataset a given internal caller isn't entitled to)
is a genuinely open design question, not answered by this document — flag it for a
real decision, don't guess at one here.

**Status: implemented (preservation half only).** `catalog-core` now has a real
`Policy`/`Rule`/`Constraint` model (`Dataset.policies: Vec<Policy>`); `crawler` parses
it from a crawled participant's `odrl:hasPolicy` triples; `rdf-store` preserves it as
real `odrl:` triples in the Oxigraph-backed semantic cache (write and read paths); the
management API's `hasPolicy` field is populated from that preserved data instead of
always being an empty array. Only *atomic* ODRL constraints (`leftOperand`/`operator`/
`rightOperand`) are modeled — nested logical-constraint groups (`odrl:and`/`odrl:or`/
`odrl:xone`) are a deliberate, known scope cut; a crawled constraint shaped as one of
those is skipped (with a `tracing::warn!`), not silently dropped along with the rest of
its policy, and not a crash. The *filtering* question this section raised — whether the
broker should hide a dataset from a caller not entitled under its policy — remains
open and unimplemented; nothing filters on policy content today.

### 3.5 Test-fixture impact: the DCP-gated crawl test

`crates/crawler/tests/multi_participant_crawl.rs`'s "gated participant" (Instance P)
currently simulates a DCP-gated remote Catalog Service using `http-api`'s own
`DspAuthMode::Dcp` + `POST /dsp/catalog/request` — both being removed per §1. This test
needs a replacement simulated gated provider once that machinery is gone: either a
small test-only mock server built just for this test file (not part of the product's
own `http-api`), or some other minimal stand-in that still exercises `crawler`'s real
outbound DCP token-minting path end to end. Decide and implement before removing the
routes this test currently depends on, so the harvester's own DCP-holder correctness
coverage isn't silently lost in the same change that removes the DSP-serving surface.

### 3.6 `crates/crawler/tests/crawl_real_edc.rs` and the EDC fixture

Unaffected by §1's removals (it crawls real EDC's own DSP endpoint, not this product's)
— no action needed here beyond what §3.1 requires for `compliance/harvest-bench/`.

## Suggested order (non-binding)

1. §3.5 first — build the replacement DCP-gated test fixture *before* deleting the
   routes it currently depends on, so there's no window where that coverage is gone.
2. §1 — remove the DSP-serving surface, its types, its gating system, and the
   `dsp-tck` harness (retired, not silently deleted — see §1.4).
3. §3.1 — settle the dataset-list endpoint's final shape.
4. §3.2 — real RDF decomposition (the biggest single piece; write the vocabulary
   decision up properly, it deserves the same rigor this project gives other
   consequential choices).
5. §3.3 — the SPARQL endpoint, now that there's something real to query.
6. §3.4 — decide and implement policy propagation, now that real `Offer`/policy
   triples exist to propagate.
7. Update `compliance/harvest-bench/check_catalog.py` and re-run
   `compliance/harvest-benchmark-2026-08-27.md` one more time against the corrected
   surfaces, so that report's own claims match what the product actually does.
