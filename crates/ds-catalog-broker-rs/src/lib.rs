//! Axum HTTP server skeleton for the federated catalog rewrite.
//!
//! Exposes a health check and a `GET /catalog` endpoint backed by
//! `rdf-store`'s `CatalogCache` trait. The catalog endpoint is
//! intentionally thin - it exists to prove the wiring between
//! `ds-catalog-broker-rs`, `catalog-core` types, and the `rdf-store` cache trait works
//! end to end, not to be a finished Management API. Query parameters,
//! pagination shape, and response JSON-LD framing (EDC's Management API
//! returns `dspace:`/`edc:` JSON-LD) are all deferred to a later
//! iteration.

mod dcp;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
    routing::{get, post},
};
use catalog_core::{Catalog, DataService, Dataset, Distribution, NodeId};
pub use dcp::DcpConfig;
pub use dcp_core::HolderIdentity;
use rdf_store::{CatalogCache, CatalogQuery, StoreResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Config for gating the DSP catalog endpoints (`POST
/// /dsp/catalog/request`, `GET /dsp/catalog/datasets/{id}`) behind a
/// bearer token, and filtering the catalog per caller once gated.
///
/// This is deliberately **not** real DCP (the Decentralized Claims
/// Protocol EDC's `DcpIdentityService` implements: DID resolution, a
/// Secure Token Service, a Credential Service round trip, and Verifiable
/// Presentation validation - see
/// `docs/spikes/2026-08-27-dataspacetck-compliance-suites.md` and
/// `compliance/benchmark-2026-08-27.md` in the `dataspace` study repo for
/// how that comparison came up). There's no signature verification and no
/// DID resolution here - the bearer token is used as an opaque,
/// unverified lookup key, closer to a shared-secret API key than a
/// verified identity. The goal is only to close the *structural* gap the
/// benchmark found (EDC's DSP endpoint requires some bearer token even
/// under its own TCK's `NoopIdentityService`; this project's required
/// none at all) and to demonstrate per-caller catalog filtering, without
/// taking on a multi-week real-DCP implementation.
///
/// If real DCP support is built later, this project only ever needs the
/// *verification* side (validate an incoming self-issued token/Verifiable
/// Presentation from a caller who already has real DID/Credential-Service
/// infrastructure) - a planned future test drives this connector with a
/// real EDC instance acting as the credentialed caller, so token
/// issuance, DID hosting, and the Credential Service itself don't need
/// implementing here. Candidate crates for that verification path,
/// surveyed but not adopted here: `ssi` (spruceid; DIDs, JWT/LD-proof VCs
/// and VPs) plus its `did-web`/`did-jwk` method crates, or a narrower
/// `jsonwebtoken`-based JWT check if only the self-issued-token layer
/// (not full VP/credential validation) turns out to be needed. That work
/// would replace what `authorize` does with the token here, rather than
/// needing a new trait or abstraction layer over these functions.
#[derive(Debug, Clone, Default)]
pub struct DspAuthConfig {
    pub mode: DspAuthMode,
    /// Bearer token -> the set of dataset ids that token's caller may
    /// see. A presented token with no entry here sees an empty catalog,
    /// not an error - once auth is enabled, unrecognized callers are
    /// denied by default rather than falling back to the full catalog.
    /// Only consulted in `DspAuthMode::Bearer`.
    pub catalog_access: HashMap<String, HashSet<String>>,
    /// Required (and only meaningful) when `mode` is `DspAuthMode::Dcp`.
    /// `main` guarantees the two stay consistent when loading config
    /// from the environment - see `load_dsp_auth` in `main.rs`.
    pub dcp: Option<DcpConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DspAuthMode {
    /// No auth check, no filtering: every caller sees the full catalog.
    /// This is the pre-existing behavior and the default, so anything
    /// that doesn't opt in via `DSP_AUTH_MODE` is unaffected.
    #[default]
    Disabled,
    /// The DSP catalog endpoints require an `Authorization: Bearer
    /// <token>` header (presence only - not cryptographically verified)
    /// and filter the catalog to what `catalog_access` grants that
    /// token.
    Bearer,
    /// The DSP catalog endpoints require a real Decentralized Claims
    /// Protocol self-issued token: this connector resolves the caller's
    /// `did:web`, verifies the token's signature, re-packages its
    /// nested presentation-access-token with this connector's own key
    /// (DCP's proof-of-original-possession step), queries the caller's
    /// Presentation API, and verifies the returned Verifiable
    /// Presentation and its embedded Verifiable Credential(s) - see
    /// `dcp::verify_dcp_bearer_token` and
    /// `compliance/dcp-test-env/README.md` for the full flow and what
    /// this was validated against.
    Dcp,
}

/// Shared application state: the cache, behind a trait object so the
/// concrete backend (in-memory today, RDF-backed later) is an
/// implementation detail of `main`, not of the router; plus DSP auth
/// config (disabled unless `main` opts it in from `DSP_AUTH_MODE`).
#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<dyn CatalogCache>,
    pub dsp_auth: DspAuthConfig,
    /// Shared HTTP client for `DspAuthMode::Dcp`'s outbound calls (DID
    /// resolution, presentation queries) - `reqwest::Client` is cheap to
    /// clone (internally `Arc`-backed) and reuses connection pooling, so
    /// one instance lives on `AppState` rather than being constructed
    /// per request.
    pub http: reqwest::Client,
    /// This connector's own DCP *holder* identity - set only when a
    /// crawler config with a `[holder]` section was loaded (see `main.rs`).
    /// `None` means this connector presents no credential of its own and
    /// the two `/dsp/holder/*` routes below 404, matching how
    /// `dsp_auth.dcp: None` gates `/dsp/did.json`.
    pub holder: Option<Arc<HolderIdentity>>,
}

impl AppState {
    pub fn new(cache: Arc<dyn CatalogCache>) -> Self {
        Self {
            cache,
            dsp_auth: DspAuthConfig::default(),
            http: reqwest::Client::new(),
            holder: None,
        }
    }

    /// Builder-style setter for DSP auth config. Kept as a plain setter
    /// rather than a `new()` parameter so existing callers (tests, and
    /// any future consumer that doesn't care about auth) don't need to
    /// change.
    pub fn with_dsp_auth(mut self, dsp_auth: DspAuthConfig) -> Self {
        self.dsp_auth = dsp_auth;
        self
    }

    /// Builder-style setter for this connector's own DCP holder identity.
    /// See the `holder` field's doc comment.
    pub fn with_holder(mut self, holder: Option<Arc<HolderIdentity>>) -> Self {
        self.holder = holder;
        self
    }
}

/// Seed `cache` with one sample catalog, so a freshly started server (or a
/// test) has something real to serve from `GET /catalog` before any
/// crawler exists to populate it.
///
/// This stands in for the not-yet-built crawler: it upserts exactly the
/// same way a real crawl result would, through the public `CatalogCache`
/// trait, so it exercises the same end-to-end path as production code
/// rather than poking the cache's internals.
///
/// Dataset ids (`CAT0101`, `CAT0102`) are deliberately aligned with
/// `vendor/eclipse-edc-connector`'s own DSP-TCK seed data
/// (`system-tests/tck/tck-extension/.../DataSeed.java`), specifically the
/// `CAT0xxx`-prefixed subset it reserves for the catalog-protocol test
/// group (as opposed to its `ACN0xxx`/`ATP0xxx` ids, used by the
/// contract-negotiation/transfer-process groups this project doesn't
/// implement). This gives the Rust and EDC catalog-request responses the
/// same dataset *count and ids* to compare against
/// (`compliance/benchmark-2026-08-27.md`), even though the two
/// implementations still diverge on everything else about how those
/// datasets are represented on the wire (see that report's fidelity
/// section).
pub async fn seed_sample_catalog(cache: &dyn CatalogCache) -> StoreResult<()> {
    let node = NodeId::new("sample-participant");
    let mut catalog = Catalog::new("sample-catalog", node);
    catalog.participant_id = Some("did:example:sample-participant".to_string());
    for dataset_id in ["CAT0101", "CAT0102"] {
        catalog.datasets.push(Dataset {
            id: dataset_id.to_string(),
            properties: Default::default(),
            distributions: vec![Distribution {
                format: "application/json".to_string(),
                access_service: "sample-data-service".to_string(),
            }],
        });
    }
    catalog.data_services.push(DataService {
        id: "sample-data-service".to_string(),
        endpoint_url: "https://sample.example.org/dsp".to_string(),
        endpoint_description: Some("dataspace-protocol-http:1.0".to_string()),
    });

    cache.upsert(catalog).await
}

/// Build the router. Kept separate from `main` so tests (and, later,
/// alternative binaries) can exercise it without binding a real socket.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/catalog", get(get_catalog))
        .route("/.well-known/dspace-version", get(dspace_version))
        .route("/dsp/catalog/request", post(catalog_request))
        .route("/dsp/catalog/datasets/{id}", get(get_dsp_dataset))
        // Only meaningful under DspAuthMode::Dcp (see dcp.rs's module
        // doc comment) - hosts this connector's own did:web document so
        // a holder's Presentation API can verify the re-packaged token
        // this connector sends it. Harmless to expose otherwise (404s
        // via an empty catalog access if `dsp_auth.dcp` is unset - see
        // `own_did_document_route`).
        .route("/dsp/did.json", get(own_did_document_route))
        // This connector's own DCP *holder* identity (see `AppState::holder`'s
        // doc comment) - the mirror of the two routes above, for when this
        // connector is the one presenting a credential rather than
        // verifying someone else's. Both 404 when no holder is
        // configured, the same gating pattern as `/dsp/did.json` above.
        .route("/dsp/holder/did.json", get(holder_did_document_route))
        .route("/dsp/holder/presentations/query", post(holder_presentation_query_route))
        .with_state(state)
}

async fn own_did_document_route(State(state): State<AppState>) -> impl IntoResponse {
    match &state.dsp_auth.dcp {
        Some(dcp_config) => (StatusCode::OK, Json(dcp_config.own_did_document())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `GET /dsp/holder/did.json` - this connector's own holder `did:web`
/// document, so a remote relying party this connector queried (via
/// `HolderIdentity::mint_self_issued_token`) can resolve the key that
/// signs the `VerifiablePresentation` `holder_presentation_query_route`
/// returns.
async fn holder_did_document_route(State(state): State<AppState>) -> impl IntoResponse {
    match &state.holder {
        Some(holder) => (StatusCode::OK, Json(holder.own_did_document())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `POST /dsp/holder/presentations/query` - this connector's Presentation
/// API, called back by a relying party this connector previously queried
/// as a DCP holder (see `HolderIdentity::answer_presentation_query`'s doc
/// comment for the full flow this is the receiving half of).
///
/// No holder configured: 404 (same gating as `holder_did_document_route`).
/// Missing/malformed `Authorization` header, or a token that fails
/// verification: 401. Otherwise: 200 with a `PresentationResponseMessage`
/// body wrapping this connector's own stored credential.
async fn holder_presentation_query_route(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(holder) = &state.holder else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    match holder.answer_presentation_query(token, &state.http).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::warn!(error = %err, "holder presentation query failed");
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Optional filter for `GET /catalog`: `?node_id=...` narrows to the
/// catalog crawled from a single origin node.
#[derive(Debug, Deserialize)]
struct CatalogParams {
    node_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CatalogListResponse {
    catalogs: Vec<Catalog>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

async fn get_catalog(
    State(state): State<AppState>,
    Query(params): Query<CatalogParams>,
) -> impl IntoResponse {
    let query = match params.node_id {
        Some(node_id) => CatalogQuery::for_node(NodeId::new(node_id)),
        None => CatalogQuery::all(),
    };

    match state.cache.query(query).await {
        Ok(catalogs) => Json(CatalogListResponse { catalogs }).into_response(),
        Err(err) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: err.to_string(),
            }),
        )
            .into_response(),
    }
}

// --- Dataspace Protocol (DSP) v2025-1 endpoints -----------------------
//
// The routes below implement just enough of the real DSP wire protocol
// (as opposed to the Management-API-style `/catalog` stub above) to pass
// the `eclipse-dataspacetck/dsp-tck` suite's MET:01-01 and CAT:01-01/02/03
// tests: connector metadata discovery, and the catalog protocol's
// "request the whole catalog" / "look up one dataset" operations.
// Contract negotiation and transfer process are out of scope and are
// expected to keep failing the rest of that suite.

const DSP_CONTEXT_URL: &str = "https://w3id.org/dspace/2025/1/context.jsonld";

/// This connector's own participant id, as advertised in DSP catalog
/// responses. Matches `dataspacetck.dsp.connector.agent.id` in
/// `compliance/tck.properties` - both name the same connector.
const CONNECTOR_PARTICIPANT_ID: &str = "urn:connector:federated-catalog-rs";

fn new_urn_uuid() -> String {
    format!("urn:uuid:{}", Uuid::new_v4())
}

#[derive(Debug, Serialize)]
struct ProtocolVersionEntry {
    version: String,
    path: String,
    binding: String,
}

#[derive(Debug, Serialize)]
struct DspaceVersionResponse {
    #[serde(rename = "protocolVersions")]
    protocol_versions: Vec<ProtocolVersionEntry>,
}

/// `GET /.well-known/dspace-version` - plain JSON, no JSON-LD framing (the
/// TCK's `MetadataClient` does a plain Jackson deserialize of this one).
/// Lives at the HTTP root, not under `/dsp`. This alone is MET:01-01.
async fn dspace_version() -> Json<DspaceVersionResponse> {
    Json(DspaceVersionResponse {
        protocol_versions: vec![ProtocolVersionEntry {
            version: "2025-1".to_string(),
            path: "/dsp".to_string(),
            binding: "HTTPS".to_string(),
        }],
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct DspPermission {
    #[serde(rename = "@type")]
    ld_type: String,
    action: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DspOffer {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    ld_type: String,
    permission: Vec<DspPermission>,
}

/// Synthesize a single default "use" Offer for a dataset.
///
/// Placeholder: `catalog-core`'s `Dataset` has no real ODRL policy model
/// yet (see its doc comment), so every dataset gets exactly one
/// synthesized default-permission Offer here just so DSP's
/// `hasPolicy` (required, non-empty per the TCK's schema) is populated.
/// Real per-dataset policy modeling is future work, not built here.
fn placeholder_offer() -> DspOffer {
    DspOffer {
        id: new_urn_uuid(),
        ld_type: "Offer".to_string(),
        permission: vec![DspPermission {
            ld_type: "Permission".to_string(),
            action: "http://www.w3.org/ns/odrl/2/use".to_string(),
        }],
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DspDistribution {
    #[serde(rename = "@type")]
    ld_type: String,
    format: String,
    #[serde(rename = "accessService")]
    access_service: String,
}

impl From<Distribution> for DspDistribution {
    fn from(d: Distribution) -> Self {
        Self {
            ld_type: "Distribution".to_string(),
            format: d.format,
            access_service: d.access_service,
        }
    }
}

/// A DSP `Dataset` document. `context` is only present when this struct is
/// serialized as its own top-level document (`GET
/// /dsp/catalog/datasets/{id}`); when nested inside a `Catalog`'s
/// `dataset` array it is omitted, since JSON-LD framing is only needed at
/// the document root.
#[derive(Debug, Serialize, Deserialize)]
struct DspDataset {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    context: Option<Vec<String>>,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    ld_type: String,
    #[serde(rename = "hasPolicy")]
    has_policy: Vec<DspOffer>,
    distribution: Vec<DspDistribution>,
}

impl From<Dataset> for DspDataset {
    fn from(dataset: Dataset) -> Self {
        Self {
            context: None,
            id: dataset.id,
            ld_type: "Dataset".to_string(),
            has_policy: vec![placeholder_offer()],
            distribution: dataset.distributions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DspDataService {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    ld_type: String,
    #[serde(rename = "endpointURL")]
    endpoint_url: String,
}

impl From<DataService> for DspDataService {
    fn from(service: DataService) -> Self {
        Self {
            id: service.id,
            ld_type: "DataService".to_string(),
            endpoint_url: service.endpoint_url,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DspCatalog {
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    ld_type: String,
    #[serde(rename = "participantId")]
    participant_id: String,
    dataset: Vec<DspDataset>,
    service: Vec<DspDataService>,
    /// DSP's own `catalog` field (JSON-LD `dspace:catalog`) for
    /// representing a federation of catalogs - one nested `Catalog` per
    /// crawled participant. Confirmed against `dsp-tck`'s own
    /// `catalog-schema.json` (`Catalog.catalog`: `array`, `minItems: 1`,
    /// items `$ref` back to `Catalog` itself - the same optional-but-
    /// nonempty-when-present shape as `dataset` and `service` on that same
    /// schema node, not required at all).
    ///
    /// Empty (and omitted from the JSON entirely via
    /// `skip_serializing_if`, satisfying `minItems: 1` by never emitting a
    /// present-but-empty array) whenever the cache holds 0 or 1 origin
    /// nodes - the pre-existing flat shape, byte-identical to before this
    /// field existed. When the cache holds 2+ origin nodes, this carries
    /// one entry per node (that node's own `participantId`, and only its
    /// own, already auth-filtered `dataset`/`service` entries) and the
    /// outer document's own `dataset`/`service` are left empty - see
    /// `catalog_request`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    catalog: Vec<DspCatalog>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DspCatalogError {
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    ld_type: String,
    code: String,
}

impl DspCatalogError {
    fn not_found() -> Self {
        Self {
            context: vec![DSP_CONTEXT_URL.to_string()],
            id: new_urn_uuid(),
            ld_type: "CatalogError".to_string(),
            code: "NOT_FOUND".to_string(),
        }
    }

    fn unauthorized() -> Self {
        Self {
            context: vec![DSP_CONTEXT_URL.to_string()],
            id: new_urn_uuid(),
            ld_type: "CatalogError".to_string(),
            code: "UNAUTHORIZED".to_string(),
        }
    }
}

/// Gate a DSP request per `auth`, returning the caller's bearer token (if
/// any) on success, already resolved to the set of dataset ids that
/// caller may see. `Ok(None)` means auth is disabled - callers should
/// treat that the same as "no filtering, full catalog". `Err(response)`
/// is a fully-formed 401 response to return immediately.
///
/// Bearer mode: the token is a presence check, not a verified identity -
/// see `DspAuthConfig`'s doc comment for why. Dcp mode: real signature
/// verification and DID resolution via `dcp::verify_dcp_bearer_token` -
/// see that module's doc comment for the full flow.
async fn authorize(
    auth: &DspAuthConfig,
    headers: &HeaderMap,
    http: &reqwest::Client,
) -> Result<Option<HashSet<String>>, Box<axum::response::Response>> {
    if auth.mode == DspAuthMode::Disabled {
        return Ok(None);
    }

    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        return Err(unauthorized_response());
    };

    match auth.mode {
        DspAuthMode::Disabled => unreachable!("handled above"),
        // An unrecognized token sees nothing (empty set), not an error:
        // once auth is enabled, unrecognized callers are denied by
        // default rather than falling back to the unfiltered catalog.
        DspAuthMode::Bearer => Ok(Some(auth.catalog_access.get(token).cloned().unwrap_or_default())),
        DspAuthMode::Dcp => {
            let dcp_config = auth
                .dcp
                .as_ref()
                .expect("DspAuthMode::Dcp always carries a DcpConfig - see load_dsp_auth in main.rs");
            match dcp::verify_dcp_bearer_token(token, dcp_config, http).await {
                Ok(verified) => {
                    tracing::info!(holder = %verified.holder_did, granted = verified.catalog_access.len(), "DCP token verified");
                    Ok(Some(verified.catalog_access))
                }
                Err(err) => {
                    tracing::warn!(error = %err, "DCP token verification failed");
                    Err(unauthorized_response())
                }
            }
        }
    }
}

fn unauthorized_response() -> Box<axum::response::Response> {
    Box::new((StatusCode::UNAUTHORIZED, Json(DspCatalogError::unauthorized())).into_response())
}

/// Filter `datasets` down to `allowed` (already-resolved dataset ids, see
/// `authorize`). `allowed: None` means auth is disabled - return
/// everything, matching this endpoint's pre-existing behavior. An empty
/// result is a valid response here, not an error -
/// `catalog_request`'s doc comment already establishes that for the
/// "cache is empty" case, and it applies equally to "cache is non-empty
/// but nothing in it is visible to this caller".
fn visible_datasets(allowed: Option<&HashSet<String>>, datasets: Vec<Dataset>) -> Vec<Dataset> {
    match allowed {
        None => datasets,
        Some(allowed_ids) => datasets.into_iter().filter(|dataset| allowed_ids.contains(&dataset.id)).collect(),
    }
}

/// Flatten every dataset (with its origin catalog's data services) out of
/// `catalogs`, discarding which origin node each came from.
///
/// NOTE: an earlier version of this comment claimed this was "conceptually
/// the same flattening EDC's own federated catalog does over its crawled
/// catalogs" - that was wrong, and is now known to be wrong (see
/// `compliance/harvest-benchmark-2026-08-27.md`): EDC's federated-catalog
/// Management API never merges crawled participants together, it returns
/// one `Catalog` object per crawled participant. Flattening across origin
/// nodes is only ever correct here when there's at most one origin node to
/// begin with, in which case there's nothing to lose by discarding origin
/// identity. `catalog_request` uses this for exactly that single-node (or
/// empty-cache) case, and separately for `get_dsp_dataset`'s by-id lookup,
/// which doesn't care about origin either way. For 2+ origin nodes,
/// `catalog_request` does NOT call this - it nests one `DspCatalog` per
/// node in the outer document's own `catalog` field instead, matching
/// EDC's own per-participant grouping.
fn flatten_catalogs(catalogs: Vec<Catalog>) -> (Vec<Dataset>, Vec<DataService>) {
    let mut datasets = Vec::new();
    let mut services = Vec::new();
    for catalog in catalogs {
        datasets.extend(catalog.datasets);
        services.extend(catalog.data_services);
    }
    (datasets, services)
}

/// `flatten_catalogs` over the cache's full contents - see that function's
/// doc comment for what "flatten" means and does not mean here.
async fn flatten_cache(cache: &dyn CatalogCache) -> StoreResult<(Vec<Dataset>, Vec<DataService>)> {
    let catalogs = cache.query(CatalogQuery::all()).await?;
    Ok(flatten_catalogs(catalogs))
}

/// `POST /dsp/catalog/request` - the DSP catalog protocol's "give me the
/// catalog" operation. The request body (a `CatalogRequestMessage`, which
/// may carry filters in a real implementation) is intentionally ignored
/// for now: filtering is per-caller (via `DspAuthConfig`), not per-request.
///
/// When `state.dsp_auth.mode` is `Disabled` (the default), auth doesn't
/// filter anything. When it's `Bearer`, a missing/malformed `Authorization`
/// header 401s (see `authorize`), and the returned dataset(s) are filtered
/// to what that caller's token grants (see `visible_datasets`).
///
/// The response shape itself depends on how many distinct origin nodes
/// (crawled participants) the cache currently holds:
///
/// - **0 or 1**: byte-identical to this endpoint's original, pre-federation
///   behavior - a flat top-level `dataset`/`service`, and `catalog: []`
///   (omitted from the JSON, see `DspCatalog::catalog`'s doc comment).
/// - **2+**: the outer document becomes a pure federation wrapper - its own
///   `dataset`/`service` are left empty, and one nested `DspCatalog` per
///   origin node is emitted in the outer document's `catalog` field, each
///   carrying only that node's own (auth-filtered) datasets/services and
///   its own `participantId`. A node with zero datasets visible to this
///   caller after filtering is omitted from `catalog` entirely, not
///   included as an empty entry - the same "don't leak existence to a
///   caller who can't see it" principle `get_dsp_dataset` already applies
///   per-dataset.
///
/// Must never return 404, even when the cache is empty or nothing is
/// visible to this caller - the TCK's HTTP client treats any 404 on this
/// path as a hard failure. An empty `dataset: []` (or an empty/absent
/// `catalog`) is a perfectly valid response either way.
async fn catalog_request(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let allowed = match authorize(&state.dsp_auth, &headers, &state.http).await {
        Ok(allowed) => allowed,
        Err(response) => return *response,
    };

    let catalogs = match state.cache.query(CatalogQuery::all()).await {
        Ok(catalogs) => catalogs,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: err.to_string(),
                }),
            )
                .into_response();
        }
    };

    let body = if catalogs.len() <= 1 {
        // 0 or 1 origin node: nothing to preserve structurally, keep the
        // pre-existing flat shape exactly.
        let (datasets, services) = flatten_catalogs(catalogs);
        let datasets = visible_datasets(allowed.as_ref(), datasets);
        DspCatalog {
            context: vec![DSP_CONTEXT_URL.to_string()],
            id: new_urn_uuid(),
            ld_type: "Catalog".to_string(),
            participant_id: CONNECTOR_PARTICIPANT_ID.to_string(),
            dataset: datasets.into_iter().map(Into::into).collect(),
            service: services.into_iter().map(Into::into).collect(),
            catalog: Vec::new(),
        }
    } else {
        // 2+ origin nodes: nest one DspCatalog per node, filtered per-node
        // (not once globally after flattening), and drop any node left
        // with zero visible datasets rather than leak its existence.
        let nested: Vec<DspCatalog> = catalogs
            .into_iter()
            .filter_map(|catalog| {
                let participant_id = catalog.participant_id.clone().unwrap_or_else(|| catalog.origin_node.to_string());
                let datasets = visible_datasets(allowed.as_ref(), catalog.datasets);
                if datasets.is_empty() {
                    return None;
                }
                Some(DspCatalog {
                    context: vec![DSP_CONTEXT_URL.to_string()],
                    id: new_urn_uuid(),
                    ld_type: "Catalog".to_string(),
                    participant_id,
                    dataset: datasets.into_iter().map(Into::into).collect(),
                    service: catalog.data_services.into_iter().map(Into::into).collect(),
                    catalog: Vec::new(),
                })
            })
            .collect();
        DspCatalog {
            context: vec![DSP_CONTEXT_URL.to_string()],
            id: new_urn_uuid(),
            ld_type: "Catalog".to_string(),
            participant_id: CONNECTOR_PARTICIPANT_ID.to_string(),
            dataset: Vec::new(),
            service: Vec::new(),
            catalog: nested,
        }
    };

    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /dsp/catalog/datasets/{id}` - look up one dataset by id, flattened
/// across every origin node in the cache regardless of how many there are
/// (unlike `catalog_request`, which nests per origin node once there are
/// 2+ - by-id lookup doesn't care which participant a dataset came from,
/// so there's nothing to preserve by keeping them separate here).
/// Found (and visible to this caller): 200 with a `Dataset` JSON-LD
/// document. Not found, *or* it exists but this caller's token doesn't
/// grant it: 404 with a `CatalogError` document - deliberately the same
/// response either way, so this endpoint doesn't leak which datasets
/// exist to a caller who can't see them.
async fn get_dsp_dataset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let allowed = match authorize(&state.dsp_auth, &headers, &state.http).await {
        Ok(allowed) => allowed,
        Err(response) => return *response,
    };

    let (datasets, _services) = match flatten_cache(&*state.cache).await {
        Ok(flattened) => flattened,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: err.to_string(),
                }),
            )
                .into_response();
        }
    };
    let datasets = visible_datasets(allowed.as_ref(), datasets);

    match datasets.into_iter().find(|dataset| dataset.id == id) {
        Some(dataset) => {
            let mut body: DspDataset = dataset.into();
            body.context = Some(vec![DSP_CONTEXT_URL.to_string()]);
            (StatusCode::OK, Json(body)).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(DspCatalogError::not_found())).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use rdf_store::memory::InMemoryCatalogCache;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState::new(Arc::new(InMemoryCatalogCache::new()))
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.status, "ok");
    }

    #[tokio::test]
    async fn catalog_endpoint_returns_empty_list_when_cache_is_empty() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/catalog")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
        assert!(parsed.catalogs.is_empty());
    }

    #[tokio::test]
    async fn catalog_endpoint_returns_upserted_catalog() {
        let state = test_state();
        let node = NodeId::new("node-1");
        state
            .cache
            .upsert(Catalog::new("cat-1", node.clone()))
            .await
            .unwrap();

        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/catalog?node_id=node-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.catalogs.len(), 1);
        assert_eq!(parsed.catalogs[0].id, "cat-1");
    }

    #[tokio::test]
    async fn catalog_endpoint_serves_seeded_sample_catalog() {
        let state = test_state();
        seed_sample_catalog(&*state.cache).await.unwrap();

        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/catalog?node_id=sample-participant")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.catalogs.len(), 1);
        let catalog = &parsed.catalogs[0];
        assert_eq!(catalog.id, "sample-catalog");
        assert_eq!(catalog.origin_node, NodeId::new("sample-participant"));
        assert_eq!(catalog.datasets.len(), 2);
        let dataset_ids: Vec<&str> = catalog.datasets.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(dataset_ids, vec!["CAT0101", "CAT0102"]);
        assert_eq!(catalog.data_services.len(), 1);
    }

    /// Proves `AppState.cache: Arc<dyn CatalogCache>` genuinely works with
    /// the real Oxigraph-backed implementation, not just
    /// `InMemoryCatalogCache` - the backend `main.rs` switches to when
    /// `CRAWLER_CONFIG_PATH` is set (see that function's doc comment).
    /// Exercises the real DSP catalog-request endpoint end to end, not
    /// just the cache trait directly.
    #[tokio::test]
    async fn dsp_catalog_request_serves_data_from_the_oxigraph_backend() {
        let cache: Arc<dyn CatalogCache> = Arc::new(rdf_store::oxigraph_backend::OxigraphCatalogCache::in_memory().unwrap());
        seed_sample_catalog(&*cache).await.unwrap();
        let state = AppState::new(cache);

        let app = build_router(state);
        let response = post_catalog_request(app, None).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: DspCatalog = serde_json::from_slice(&body).unwrap();
        let mut ids: Vec<&str> = parsed.dataset.iter().map(|d| d.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["CAT0101", "CAT0102"]);
    }

    #[tokio::test]
    async fn catalog_endpoint_filters_by_unknown_node_id() {
        let state = test_state();
        state
            .cache
            .upsert(Catalog::new("cat-1", NodeId::new("node-1")))
            .await
            .unwrap();

        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/catalog?node_id=does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
        assert!(parsed.catalogs.is_empty());
    }

    // --- DSP catalog endpoint auth/filtering (`DspAuthConfig`) ---------

    async fn seeded_dsp_state(dsp_auth: DspAuthConfig) -> AppState {
        let state = AppState::new(Arc::new(InMemoryCatalogCache::new())).with_dsp_auth(dsp_auth);
        seed_sample_catalog(&*state.cache).await.unwrap();
        state
    }

    fn bearer_auth(access: &[(&str, &[&str])]) -> DspAuthConfig {
        DspAuthConfig {
            mode: DspAuthMode::Bearer,
            catalog_access: access
                .iter()
                .map(|(token, ids)| {
                    (
                        token.to_string(),
                        ids.iter().map(|id| id.to_string()).collect::<HashSet<_>>(),
                    )
                })
                .collect(),
            dcp: None,
        }
    }

    async fn post_catalog_request(app: Router, bearer_token: Option<&str>) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/dsp/catalog/request")
            .header("content-type", "application/json");
        if let Some(token) = bearer_token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        app.oneshot(builder.body(Body::from("{}")).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn dsp_catalog_request_disabled_mode_ignores_missing_auth_header() {
        // The pre-existing, default behavior: DspAuthMode::Disabled means
        // no gate at all, regardless of what's seeded or configured.
        let state = seeded_dsp_state(DspAuthConfig::default()).await;
        let app = build_router(state);
        let response = post_catalog_request(app, None).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: DspCatalog = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.dataset.len(), 2);
    }

    #[tokio::test]
    async fn dsp_catalog_request_bearer_mode_requires_auth_header() {
        let state = seeded_dsp_state(bearer_auth(&[])).await;
        let app = build_router(state);
        let response = post_catalog_request(app, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: DspCatalogError = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.code, "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn dsp_catalog_request_bearer_mode_denies_unknown_caller_by_default() {
        let state = seeded_dsp_state(bearer_auth(&[])).await;
        let app = build_router(state);
        // A syntactically valid bearer token, but not in catalog_access.
        let response = post_catalog_request(app, Some("nobody-configured")).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: DspCatalog = serde_json::from_slice(&body).unwrap();
        assert!(parsed.dataset.is_empty());
    }

    #[tokio::test]
    async fn dsp_catalog_request_bearer_mode_filters_per_caller() {
        let auth = bearer_auth(&[
            ("consumer-a-token", &["CAT0101"]),
            ("consumer-b-token", &["CAT0101", "CAT0102"]),
        ]);
        let state = seeded_dsp_state(auth).await;
        let app = build_router(state);

        let response_a = post_catalog_request(app.clone(), Some("consumer-a-token")).await;
        assert_eq!(response_a.status(), StatusCode::OK);
        let body_a = response_a.into_body().collect().await.unwrap().to_bytes();
        let parsed_a: DspCatalog = serde_json::from_slice(&body_a).unwrap();
        assert_eq!(
            parsed_a.dataset.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            vec!["CAT0101"]
        );

        let response_b = post_catalog_request(app, Some("consumer-b-token")).await;
        assert_eq!(response_b.status(), StatusCode::OK);
        let body_b = response_b.into_body().collect().await.unwrap().to_bytes();
        let parsed_b: DspCatalog = serde_json::from_slice(&body_b).unwrap();
        let mut ids_b: Vec<&str> = parsed_b.dataset.iter().map(|d| d.id.as_str()).collect();
        ids_b.sort_unstable();
        assert_eq!(ids_b, vec!["CAT0101", "CAT0102"]);
    }

    #[tokio::test]
    async fn dsp_dataset_lookup_404s_for_a_dataset_that_exists_but_isnt_visible_to_caller() {
        let auth = bearer_auth(&[("consumer-a-token", &["CAT0101"])]);
        let state = seeded_dsp_state(auth).await;
        let app = build_router(state);

        // CAT0101 is granted to this caller: visible.
        let visible = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/dsp/catalog/datasets/CAT0101")
                    .header("authorization", "Bearer consumer-a-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(visible.status(), StatusCode::OK);

        // CAT0102 exists (it's in the seeded catalog) but isn't granted to
        // this caller: same 404 as a genuinely nonexistent id, not a 403 -
        // this endpoint shouldn't leak existence to callers who can't see it.
        let not_granted = app
            .oneshot(
                Request::builder()
                    .uri("/dsp/catalog/datasets/CAT0102")
                    .header("authorization", "Bearer consumer-a-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_granted.status(), StatusCode::NOT_FOUND);
    }

    // --- Per-origin-node nesting in `catalog_request` (bug: today's
    // `flatten_cache` always merges every cached node's datasets into one
    // flat top-level `dataset` array, discarding which participant each
    // dataset came from - see the report this fixes,
    // `compliance/harvest-benchmark-2026-08-27.md`, and ADR-eligible
    // follow-up work tracked there). These tests assert the CORRECT,
    // not-yet-implemented behavior and are expected to fail (RED) against
    // today's `catalog_request`/`flatten_cache`. They deserialize the
    // response as `serde_json::Value` rather than the typed `DspCatalog`
    // struct, since `DspCatalog` has no `catalog` field yet and adding the
    // real nesting logic is explicitly out of scope for this change - see
    // the task note on why option (a) (untyped JSON assertions) was
    // chosen over scaffolding an unused field.

    /// Seed two distinct origin nodes - mirrors the real harvest-bench
    /// scenario's shape (multiple genuinely different crawled
    /// participants, not the single hardcoded `seed_sample_catalog` node
    /// every other test in this file uses). Node "node-a" gets 3 datasets
    /// (`A1..A3`), node "node-b" gets 7 (`B1..B7`) - distinct id
    /// namespaces per node so cross-contamination between nested entries
    /// is trivially detectable. Each node also gets its own
    /// `participant_id` and its own `DataService`, matching what
    /// `crates/crawler`'s response parser actually populates for a real
    /// crawled participant.
    async fn seed_two_node_catalog(cache: &dyn CatalogCache) {
        let mut node_a = Catalog::new("catalog-a", NodeId::new("node-a"));
        node_a.participant_id = Some("did:example:node-a".to_string());
        for id in ["A1", "A2", "A3"] {
            node_a.datasets.push(Dataset {
                id: id.to_string(),
                properties: Default::default(),
                distributions: vec![Distribution {
                    format: "application/json".to_string(),
                    access_service: "node-a-data-service".to_string(),
                }],
            });
        }
        node_a.data_services.push(DataService {
            id: "node-a-data-service".to_string(),
            endpoint_url: "https://node-a.example.org/dsp".to_string(),
            endpoint_description: None,
        });
        cache.upsert(node_a).await.unwrap();

        let mut node_b = Catalog::new("catalog-b", NodeId::new("node-b"));
        node_b.participant_id = Some("did:example:node-b".to_string());
        for id in ["B1", "B2", "B3", "B4", "B5", "B6", "B7"] {
            node_b.datasets.push(Dataset {
                id: id.to_string(),
                properties: Default::default(),
                distributions: vec![Distribution {
                    format: "application/json".to_string(),
                    access_service: "node-b-data-service".to_string(),
                }],
            });
        }
        node_b.data_services.push(DataService {
            id: "node-b-data-service".to_string(),
            endpoint_url: "https://node-b.example.org/dsp".to_string(),
            endpoint_description: None,
        });
        cache.upsert(node_b).await.unwrap();
    }

    #[tokio::test]
    async fn dsp_catalog_request_nests_per_origin_node_when_multiple_nodes_are_cached() {
        let state = AppState::new(Arc::new(InMemoryCatalogCache::new()));
        seed_two_node_catalog(&*state.cache).await;

        let app = build_router(state);
        let response = post_catalog_request(app, None).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Outer document is a pure federation wrapper once 2+ origin nodes
        // are cached: both top-level dataset and service arrays are empty,
        // all real content lives in the nested `catalog[]` entries.
        let top_level_datasets = parsed["dataset"]
            .as_array()
            .expect("top-level `dataset` field present (even if empty)");
        assert!(
            top_level_datasets.is_empty(),
            "top-level `dataset` must be empty when 2+ origin nodes are cached, got: {top_level_datasets:?}"
        );
        let top_level_services = parsed["service"]
            .as_array()
            .expect("top-level `service` field present (even if empty)");
        assert!(
            top_level_services.is_empty(),
            "top-level `service` must be empty when 2+ origin nodes are cached, got: {top_level_services:?}"
        );

        let nested_catalogs = parsed["catalog"]
            .as_array()
            .expect("`catalog` array present when 2+ origin nodes are cached");
        assert_eq!(
            nested_catalogs.len(),
            2,
            "expected one nested catalog entry per origin node, got: {nested_catalogs:?}"
        );

        // Index by participantId rather than assuming array order, since
        // nesting order isn't specified.
        let mut by_participant: HashMap<String, Vec<String>> = HashMap::new();
        for entry in nested_catalogs {
            let participant_id = entry["participantId"]
                .as_str()
                .expect("each nested entry carries its own node's participantId")
                .to_string();
            let ids: Vec<String> = entry["dataset"]
                .as_array()
                .expect("each nested entry has its own `dataset` array")
                .iter()
                .map(|d| d["@id"].as_str().unwrap().to_string())
                .collect();
            by_participant.insert(participant_id, ids);
        }

        let mut node_a_ids = by_participant
            .get("did:example:node-a")
            .expect("node-a's nested entry present, keyed by its own participantId")
            .clone();
        node_a_ids.sort();
        assert_eq!(node_a_ids, vec!["A1", "A2", "A3"]);

        let mut node_b_ids = by_participant
            .get("did:example:node-b")
            .expect("node-b's nested entry present, keyed by its own participantId")
            .clone();
        node_b_ids.sort();
        assert_eq!(node_b_ids, vec!["B1", "B2", "B3", "B4", "B5", "B6", "B7"]);

        // No cross-contamination: exactly 10 dataset ids total, none
        // duplicated across the two nested entries.
        let mut all_ids: Vec<String> = by_participant.values().flatten().cloned().collect();
        all_ids.sort();
        all_ids.dedup();
        assert_eq!(all_ids.len(), 10, "expected 10 distinct dataset ids total across both nested entries");
    }

    #[tokio::test]
    async fn dsp_catalog_request_bearer_mode_filters_nested_catalogs_per_node() {
        // Token grants only node-a's "A1" and nothing from node-b.
        let auth = bearer_auth(&[("consumer-a-token", &["A1"])]);
        let state = AppState::new(Arc::new(InMemoryCatalogCache::new())).with_dsp_auth(auth);
        seed_two_node_catalog(&*state.cache).await;

        let app = build_router(state);
        let response = post_catalog_request(app, Some("consumer-a-token")).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let top_level_datasets = parsed["dataset"]
            .as_array()
            .expect("top-level `dataset` field present (even if empty)");
        assert!(top_level_datasets.is_empty());

        let nested_catalogs = parsed["catalog"]
            .as_array()
            .expect("`catalog` array present when 2+ origin nodes are cached");

        // Design decision (documented here since the task leaves this
        // choice open): a node with zero visible datasets after per-caller
        // filtering is OMITTED entirely from the nested `catalog[]` array,
        // rather than included as an entry with an empty `dataset: []`.
        // This mirrors the same "don't leak existence to a caller who
        // can't see it" principle `get_dsp_dataset`'s doc comment already
        // applies to per-dataset 404s: a caller with zero visibility into
        // a participant shouldn't learn that participant was crawled at
        // all. So node-b (0 visible datasets for this token) must not
        // appear, and only node-a's single visible dataset shows up.
        assert_eq!(
            nested_catalogs.len(),
            1,
            "node-b has zero visible datasets for this token and must be omitted entirely, got: {nested_catalogs:?}"
        );

        let node_a_entry = &nested_catalogs[0];
        assert_eq!(node_a_entry["participantId"], "did:example:node-a");
        let ids: Vec<&str> = node_a_entry["dataset"]
            .as_array()
            .expect("node-a's nested entry has its own `dataset` array")
            .iter()
            .map(|d| d["@id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["A1"]);
    }

    /// Regression guard: the single-origin-node case (every existing test
    /// in this file, including `seed_sample_catalog`'s
    /// `"sample-participant"` node) must stay byte-identical to today -
    /// flat top-level `dataset`, and `catalog` absent from the JSON
    /// entirely (not merely an empty `Vec` in the Rust struct - checked
    /// against the raw response text, since `skip_serializing_if` is what
    /// must make that true once the fix adds the field).
    #[tokio::test]
    async fn dsp_catalog_request_single_node_case_is_unaffected() {
        let state = seeded_dsp_state(DspAuthConfig::default()).await;
        let app = build_router(state);
        let response = post_catalog_request(app, None).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_text = String::from_utf8(body.to_vec()).expect("response body is valid UTF-8");

        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let dataset_ids: Vec<&str> = parsed["dataset"]
            .as_array()
            .expect("top-level `dataset` array present")
            .iter()
            .map(|d| d["@id"].as_str().unwrap())
            .collect();
        assert_eq!(dataset_ids, vec!["CAT0101", "CAT0102"]);

        assert!(
            !body_text.contains("\"catalog\""),
            "single-node response must omit the `catalog` field entirely from the JSON, got: {body_text}"
        );
    }
}
