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

use std::sync::Arc;

pub mod oauth2;

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
    },
    response::IntoResponse,
    routing::{get, post},
};
use catalog_core::{Catalog, DataService, Dataset, Distribution, NodeId};
pub use dcp_core::HolderIdentity;
pub use oauth2::{OAuth2Config, OAuth2Verifier, VerifyError};
use rdf_store::oxigraph_backend::{OxigraphCatalogCache, SparqlError};
use rdf_store::{CatalogCache, CatalogQuery, StoreResult};
use serde::{Deserialize, Serialize};

/// Shared application state: the cache, behind a trait object so the
/// concrete backend (in-memory today, RDF-backed later) is an
/// implementation detail of `main`, not of the router.
#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<dyn CatalogCache>,
    /// Shared HTTP client for this connector's own DCP *holder* role's
    /// outbound calls - `reqwest::Client` is cheap to clone (internally
    /// `Arc`-backed) and reuses connection pooling, so one instance lives
    /// on `AppState` rather than being constructed per request.
    pub http: reqwest::Client,
    /// This connector's own DCP *holder* identity - set only when a
    /// crawler config with a `[holder]` section was loaded (see `main.rs`).
    /// `None` means this connector presents no credential of its own and
    /// the two `/dsp/holder/*` routes below 404.
    pub holder: Option<Arc<HolderIdentity>>,
    /// The concrete Oxigraph-backed cache, held *in addition to* the
    /// type-erased `cache` field above, purely so `GET`/`POST /sparql` can
    /// reach `OxigraphCatalogCache::sparql_query_json` - a capability that
    /// exists on that concrete type, not on the `CatalogCache` trait (see
    /// that method's own doc comment for why). `Some` exactly when `cache`
    /// is backed by Oxigraph (i.e. `CRAWLER_CONFIG_PATH` was set, see
    /// `main.rs`); `None` when it's the plain in-memory backend, in which
    /// case `/sparql` answers 501 rather than pretending to support a
    /// query language that backend doesn't implement.
    pub sparql: Option<Arc<OxigraphCatalogCache>>,
    /// The OAuth2 Bearer resource-server gate for `GET /catalog` and
    /// `GET`/`POST /sparql` - see `oauth2`'s module doc and
    /// `docs/oauth2-bearer-gating-2026-08-28.md`. `Some` means gating is
    /// active (set only when `OAUTH2_JWKS_URI` was configured, see
    /// `main.rs`); `None` (the default) leaves both routes exactly as
    /// unauthenticated as before this feature existed. Never gates
    /// `/health` or the two `/dsp/holder/*` routes - those are unaffected
    /// by this field entirely.
    pub oauth2: Option<Arc<OAuth2Verifier>>,
}

impl AppState {
    pub fn new(cache: Arc<dyn CatalogCache>) -> Self {
        Self {
            cache,
            http: reqwest::Client::new(),
            holder: None,
            sparql: None,
            oauth2: None,
        }
    }

    /// Builder-style setter for this connector's own DCP holder identity.
    /// See the `holder` field's doc comment.
    pub fn with_holder(mut self, holder: Option<Arc<HolderIdentity>>) -> Self {
        self.holder = holder;
        self
    }

    /// Builder-style setter wiring up the SPARQL endpoint against a real
    /// Oxigraph-backed cache. See the `sparql` field's doc comment.
    pub fn with_sparql(mut self, sparql: Option<Arc<OxigraphCatalogCache>>) -> Self {
        self.sparql = sparql;
        self
    }

    /// Builder-style setter for the OAuth2 Bearer gate. See the `oauth2`
    /// field's doc comment.
    pub fn with_oauth2(mut self, oauth2: Option<Arc<OAuth2Verifier>>) -> Self {
        self.oauth2 = oauth2;
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
        // The SPARQL 1.1 Protocol query surface (gap analysis §3.3) - see
        // `sparql_route`'s own doc comment for the exact request/response
        // shape supported.
        .route("/sparql", get(sparql_route_get).post(sparql_route_post))
        // This connector's own DCP *holder* identity (see `AppState::holder`'s
        // doc comment) - this participant's own credential-presentation
        // capability for crawling a DCP-gated remote participant. Both
        // routes 404 when no holder is configured.
        .route("/dsp/holder/did.json", get(holder_did_document_route))
        .route(
            "/dsp/holder/presentations/query",
            post(holder_presentation_query_route),
        )
        .with_state(state)
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
async fn holder_presentation_query_route(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
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

/// Enforces the OAuth2 Bearer gate (see `AppState::oauth2`'s doc comment
/// and `docs/oauth2-bearer-gating-2026-08-28.md`'s "Response shape") for
/// `GET /catalog` and `GET`/`POST /sparql` - the only two routes this
/// mechanism gates. `Ok(())` means either gating is off (`state.oauth2` is
/// `None`) or the caller presented a valid, sufficiently-scoped token;
/// `Err(response)` is the exact response the caller should get instead of
/// running the route's own handler.
///
/// - No/malformed `Authorization: Bearer` header, or a token that fails
///   verification for any reason other than scope (unknown `kid`, bad
///   signature, expired, wrong `iss`/`aud`): `401` with a
///   `WWW-Authenticate: Bearer` header (RFC 6750).
/// - Valid token, missing the configured required scope: `403` (no
///   `WWW-Authenticate` header - the caller authenticated fine, it's an
///   authorization failure, not an authentication one).
fn check_oauth2_bearer(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), Box<axum::response::Response>> {
    let Some(verifier) = &state.oauth2 else {
        return Ok(());
    };

    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        return Err(Box::new(unauthorized_bearer_response()));
    };

    match verifier.verify(token) {
        Ok(_claims) => Ok(()),
        Err(VerifyError::InsufficientScope(scope)) => Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("token is missing required scope '{scope}'"),
                }),
            )
                .into_response(),
        )),
        Err(err) => {
            tracing::warn!(error = %err, "oauth2 bearer token verification failed");
            Err(Box::new(unauthorized_bearer_response()))
        }
    }
}

fn unauthorized_bearer_response() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Bearer")],
        Json(ErrorResponse {
            error: "missing or invalid bearer token".to_string(),
        }),
    )
        .into_response()
}

async fn get_catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<CatalogParams>,
) -> impl IntoResponse {
    if let Err(response) = check_oauth2_bearer(&state, &headers) {
        return *response;
    }

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

/// `application/sparql-results+json`, the one result media type this
/// endpoint produces (gap analysis §3.3's stated minimum).
const SPARQL_RESULTS_JSON: &str = "application/sparql-results+json";

/// `GET /sparql?query=...` - the SPARQL 1.1 Protocol's URL-encoded GET
/// form. See [`sparql_route`] for the shared handling.
#[derive(Debug, Deserialize)]
struct SparqlGetParams {
    query: Option<String>,
}

async fn sparql_route_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SparqlGetParams>,
) -> impl IntoResponse {
    sparql_route(state, headers, params.query).await
}

/// `POST /sparql` with `Content-Type: application/x-www-form-urlencoded`
/// and a `query` form field - the SPARQL 1.1 Protocol's other mandated
/// way to submit a query.
///
/// The protocol also allows a second POST style - a raw SPARQL string as
/// the body with `Content-Type: application/sparql-query` - but requires
/// only "at least one" query mechanism beyond plain GET, per the gap
/// analysis's own framing of the spec ("query" parameter over GET/POST).
/// Form-encoded POST is implemented here (this is that "at least one");
/// direct `application/sparql-query` bodies are not. Chosen over the raw
/// form because it composes with a plain HTML `<form>` and with the
/// default POST mode of common SPARQL client libraries (e.g. Python's
/// `SPARQLWrapper`), needing no bespoke `Content-Type` handling in this
/// router beyond the URL-encoded body Axum's own `Form` extractor already
/// parses.
#[derive(Debug, Deserialize)]
struct SparqlPostForm {
    query: Option<String>,
}

async fn sparql_route_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SparqlPostForm>,
) -> impl IntoResponse {
    sparql_route(state, headers, form.query).await
}

/// Whether `headers`' `Accept` value (if any) allows an
/// `application/sparql-results+json` response.
///
/// A missing `Accept` header allows it (HTTP's own "no preference"
/// default). Otherwise, at least one comma-separated media range must be
/// `application/sparql-results+json`, the bare `application/json` (a
/// reasonable specific-enough match for a JSON-speaking client that
/// doesn't know the SPARQL-specific type), or a wildcard (`*/*`,
/// `application/*`) - any `;q=...` parameter is ignored, since there is
/// only one representation on offer here to weight against.
fn accepts_sparql_results_json(headers: &HeaderMap) -> bool {
    let Some(accept) = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
    else {
        return true;
    };
    accept.split(',').any(|range| {
        matches!(
            range.split(';').next().unwrap_or("").trim(),
            SPARQL_RESULTS_JSON | "application/json" | "*/*" | "application/*"
        )
    })
}

/// Shared `GET`/`POST /sparql` handling - see `build_router`'s doc
/// comment for why both exist, and `rdf_store::oxigraph_backend`'s
/// `sparql_query_json` for the actual evaluation this delegates to
/// (read-only by construction, whole-store-by-default, real
/// `application/sparql-results+json` output).
///
/// - No `sparql` backend configured (`AppState::sparql` is `None`, i.e.
///   the in-memory cache is running - see that field's doc comment): 501
///   Not Implemented. This is a genuine backend limitation, not a
///   not-yet-built route, hence 501 rather than 404.
/// - Missing/empty `query`: 400 Bad Request.
/// - `Accept` header present and none of its media ranges match
///   `application/sparql-results+json` (see `accepts_sparql_results_json`):
///   406 Not Acceptable.
/// - Query fails to parse, fails to evaluate, or is a `CONSTRUCT`/
///   `DESCRIBE` (unsupported result shape - see `SparqlError`'s own doc
///   comments): 400 Bad Request with a plain-text explanation - these are
///   all the caller's own query's fault.
/// - Otherwise: 200 with an `application/sparql-results+json` body.
///
/// Checked first, ahead of all of the above: the OAuth2 Bearer gate (see
/// `check_oauth2_bearer`'s doc comment) - `401`/`403` when
/// `AppState::oauth2` is configured and the caller's token doesn't clear
/// it; unchanged behavior (falls straight through to the checks above)
/// when it isn't configured at all.
async fn sparql_route(
    state: AppState,
    headers: HeaderMap,
    query: Option<String>,
) -> axum::response::Response {
    if let Err(response) = check_oauth2_bearer(&state, &headers) {
        return *response;
    }

    let Some(sparql) = &state.sparql else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this instance is running the in-memory catalog cache, which has no SPARQL \
             (Oxigraph) backend - set CRAWLER_CONFIG_PATH to enable the SPARQL endpoint"
                .to_string(),
        )
            .into_response();
    };

    if !accepts_sparql_results_json(&headers) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            format!("this endpoint only produces {SPARQL_RESULTS_JSON}"),
        )
            .into_response();
    }

    let query = match query.filter(|q| !q.trim().is_empty()) {
        Some(query) => query,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "missing required 'query' parameter".to_string(),
            )
                .into_response();
        }
    };

    match sparql.sparql_query_json(&query) {
        Ok(body) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, SPARQL_RESULTS_JSON)],
            body,
        )
            .into_response(),
        Err(
            err @ (SparqlError::Parse(_)
            | SparqlError::Evaluation(_)
            | SparqlError::UnsupportedGraphResult),
        ) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        Err(err @ SparqlError::Serialize(_)) => {
            tracing::error!(error = %err, "failed to serialize SPARQL results");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
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
    /// Exercises `GET /catalog` end to end through the router, not just
    /// the cache trait directly. (Previously exercised the now-removed
    /// `POST /dsp/catalog/request` DSP-serving endpoint - see
    /// `docs/gap-analysis-2026-08-27.md` §1 for why that endpoint is
    /// gone; this test keeps the same "real Oxigraph backend through the
    /// router" coverage against the surface that replaced it.)
    #[tokio::test]
    async fn catalog_endpoint_serves_data_from_the_oxigraph_backend() {
        let cache: Arc<dyn CatalogCache> =
            Arc::new(rdf_store::oxigraph_backend::OxigraphCatalogCache::in_memory().unwrap());
        seed_sample_catalog(&*cache).await.unwrap();
        let state = AppState::new(cache);

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
        let mut ids: Vec<&str> = parsed.catalogs[0]
            .datasets
            .iter()
            .map(|d| d.id.as_str())
            .collect();
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

    // --- `/sparql` (gap analysis §3.3) --------------------------------------

    /// `AppState` wired the way `main.rs` wires it once
    /// `CRAWLER_CONFIG_PATH` is set: a real Oxigraph-backed cache, with
    /// `AppState::sparql` pointed at that same store so `/sparql` is live.
    fn sparql_test_state() -> AppState {
        let store =
            Arc::new(rdf_store::oxigraph_backend::OxigraphCatalogCache::in_memory().unwrap());
        let cache: Arc<dyn CatalogCache> = store.clone();
        AppState::new(cache).with_sparql(Some(store))
    }

    /// A small but real per-participant catalog - same shape as
    /// `seed_sample_catalog`'s fixture (one dataset, one distribution, one
    /// data service), parameterized by origin node so two distinct
    /// participants' worth of real, differently-shaped data can be seeded
    /// side by side, which is what the SPARQL tests below need to prove a
    /// query genuinely spans more than one harvested participant.
    fn participant_catalog(node_id: &str, catalog_id: &str, dataset_id: &str) -> Catalog {
        let mut catalog = Catalog::new(catalog_id, NodeId::new(node_id));
        catalog.participant_id = Some(format!("did:example:{node_id}"));
        let service_id = format!("{dataset_id}-svc");
        catalog.datasets.push(Dataset {
            id: dataset_id.to_string(),
            properties: Default::default(),
            distributions: vec![Distribution {
                format: "application/json".to_string(),
                access_service: service_id.clone(),
            }],
        });
        catalog.data_services.push(DataService {
            id: service_id,
            endpoint_url: format!("https://{node_id}.example.org/dsp"),
            endpoint_description: Some("dataspace-protocol-http:1.0".to_string()),
        });
        catalog
    }

    /// The real end-to-end path this gap analysis item asks for: two
    /// seeded origin nodes, a real SPARQL SELECT sent through the actual
    /// `GET /sparql` HTTP route (not `OxigraphCatalogCache::sparql_query_json`
    /// called directly), and assertions on the real parsed
    /// `application/sparql-results+json` body - proving GET, the default
    /// whole-store scope, the real Oxigraph evaluator, and the real JSON
    /// serialization all actually work together through the router.
    #[tokio::test]
    async fn sparql_get_select_finds_datasets_from_both_seeded_participants() {
        let state = sparql_test_state();
        state
            .cache
            .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
            .await
            .unwrap();
        state
            .cache
            .upsert(participant_catalog("node-b", "cat-b", "DATASET-B"))
            .await
            .unwrap();

        let app = build_router(state);
        let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                     SELECT ?dataset WHERE { ?dataset a dcat:Dataset }";
        let uri = format!("/sparql?query={}", urlencoding::encode(query));
        let response = app
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("Accept", "application/sparql-results+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/sparql-results+json"
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["head"]["vars"], serde_json::json!(["dataset"]));
        let bindings = parsed["results"]["bindings"].as_array().unwrap();
        assert_eq!(
            bindings.len(),
            2,
            "expected one dataset per seeded participant, got {parsed}"
        );
        let mut dataset_iris: Vec<&str> = bindings
            .iter()
            .map(|b| b["dataset"]["value"].as_str().unwrap())
            .collect();
        dataset_iris.sort_unstable();
        assert!(dataset_iris[0].contains("node-a") && dataset_iris[0].contains("DATASET-A"));
        assert!(dataset_iris[1].contains("node-b") && dataset_iris[1].contains("DATASET-B"));
        assert_eq!(bindings[0]["dataset"]["type"], serde_json::json!("uri"));
    }

    /// The other mandated submission mechanism: `POST` with
    /// `application/x-www-form-urlencoded` and a `query` form field (see
    /// `sparql_route_post`'s doc comment for why this style was chosen
    /// over raw `application/sparql-query` bodies). Same real end-to-end
    /// path and assertions as the GET test above.
    #[tokio::test]
    async fn sparql_post_form_encoded_select_finds_seeded_dataset() {
        let state = sparql_test_state();
        state
            .cache
            .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
            .await
            .unwrap();

        let app = build_router(state);
        let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                     SELECT ?dataset WHERE { ?dataset a dcat:Dataset }";
        let form_body = format!("query={}", urlencoding::encode(query));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sparql")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let bindings = parsed["results"]["bindings"].as_array().unwrap();
        assert_eq!(bindings.len(), 1);
        assert!(
            bindings[0]["dataset"]["value"]
                .as_str()
                .unwrap()
                .contains("DATASET-A")
        );
    }

    /// A real SPARQL ASK, through the HTTP route, producing the
    /// spec-shaped `{"head":{},"boolean":true}` body.
    #[tokio::test]
    async fn sparql_get_ask_returns_true_over_http() {
        let state = sparql_test_state();
        state
            .cache
            .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
            .await
            .unwrap();

        let app = build_router(state);
        let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> ASK { ?d a dcat:Dataset }";
        let uri = format!("/sparql?query={}", urlencoding::encode(query));
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, serde_json::json!({"head": {}, "boolean": true}));
    }

    /// The in-memory backend (no `CRAWLER_CONFIG_PATH`, `AppState::sparql`
    /// is `None`) has no SPARQL capability at all - `/sparql` must say so
    /// plainly (501), not 404 (the route exists) and not pretend to
    /// answer.
    #[tokio::test]
    async fn sparql_endpoint_returns_501_when_no_oxigraph_backend_is_configured() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sparql?query=ASK%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn sparql_endpoint_requires_a_query_parameter() {
        let app = build_router(sparql_test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sparql")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// `Accept` demanding a representation this endpoint doesn't produce
    /// is 406, not a silent fallback to JSON anyway.
    #[tokio::test]
    async fn sparql_endpoint_rejects_an_unacceptable_accept_header() {
        let app = build_router(sparql_test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sparql?query=ASK%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D")
                    .header("Accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
    }

    /// A SPARQL Update sent to this read-only endpoint must be rejected,
    /// and must not mutate the store - the real proof (through HTTP, not
    /// a direct backend call) that this product's "read-only, never
    /// originates data" rule actually holds at the surface a caller would
    /// use.
    #[tokio::test]
    async fn sparql_endpoint_rejects_an_update_operation_and_leaves_the_store_unchanged() {
        let state = sparql_test_state();
        state
            .cache
            .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
            .await
            .unwrap();
        let cache_handle = state.cache.clone();

        let app = build_router(state);
        let injection = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                          INSERT DATA { GRAPH <urn:x> { <urn:y> a dcat:Catalog } }";
        let uri = format!("/sparql?query={}", urlencoding::encode(injection));
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let results = cache_handle.query(CatalogQuery::all()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "cat-a");
    }

    // --- OAuth2 Bearer gating (docs/oauth2-bearer-gating-2026-08-28.md) ---
    //
    // Router-level, through the real `build_router` + `oneshot` - not
    // `OAuth2Verifier::verify` called directly (that's already covered,
    // thoroughly, by `oauth2.rs`'s own unit tests). What these prove is
    // the wiring: that `check_oauth2_bearer` actually gates these two
    // routes and only these two, and that the mock JWKS server is reached
    // over a real HTTP fetch (`OAuth2Verifier::fetch`), not a pre-parsed
    // fixture - see `oauth2::test_support::spawn_jwks_server`.

    use crate::oauth2::test_support::{
        base_claims, ec_jwk, generate_key, sign_es256, spawn_jwks_server,
    };
    use crate::oauth2::{OAuth2Config, OAuth2Verifier};

    fn oauth2_config(jwks_uri: String) -> OAuth2Config {
        OAuth2Config {
            jwks_uri,
            issuer: None,
            audience: None,
            required_scope: None,
        }
    }

    /// `test_state()`, seeded the same way `catalog_endpoint_serves_seeded_sample_catalog`
    /// is, with the OAuth2 gate wired up against a real mock JWKS server -
    /// `configure` gets to adjust `issuer`/`audience`/`required_scope`
    /// before the JWKS is fetched. Returns the state alongside the signing
    /// key so each test can mint its own tokens.
    async fn oauth2_catalog_state(
        configure: impl FnOnce(&mut OAuth2Config),
    ) -> (AppState, oauth2::test_support::TestKey) {
        let key = generate_key("catalog-key");
        let jwks_uri = spawn_jwks_server(serde_json::json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut config = oauth2_config(jwks_uri);
        configure(&mut config);
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config)
            .await
            .expect("fetch mock JWKS");

        let state = test_state();
        seed_sample_catalog(&*state.cache).await.unwrap();
        let state = state.with_oauth2(Some(Arc::new(verifier)));
        (state, key)
    }

    /// Same idea as `oauth2_catalog_state`, but built on `sparql_test_state()`
    /// (a real Oxigraph backend, one seeded participant) so `/sparql` has
    /// something real to answer once a valid token clears the gate.
    async fn oauth2_sparql_state(
        configure: impl FnOnce(&mut OAuth2Config),
    ) -> (AppState, oauth2::test_support::TestKey) {
        let key = generate_key("sparql-key");
        let jwks_uri = spawn_jwks_server(serde_json::json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut config = oauth2_config(jwks_uri);
        configure(&mut config);
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config)
            .await
            .expect("fetch mock JWKS");

        let state = sparql_test_state();
        state
            .cache
            .upsert(participant_catalog("node-a", "cat-a", "DATASET-A"))
            .await
            .unwrap();
        let state = state.with_oauth2(Some(Arc::new(verifier)));
        (state, key)
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    #[tokio::test]
    async fn catalog_route_401s_with_www_authenticate_when_no_token_is_given() {
        let (state, _key) = oauth2_catalog_state(|_| {}).await;
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
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer"
        );
    }

    #[tokio::test]
    async fn catalog_route_401s_on_a_garbage_bearer_token() {
        let (state, _key) = oauth2_catalog_state(|_| {}).await;
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/catalog?node_id=sample-participant")
                    .header("Authorization", bearer("not-a-real-jwt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn catalog_route_401s_for_a_token_with_the_wrong_audience_when_audience_is_configured() {
        let (state, key) =
            oauth2_catalog_state(|config| config.audience = Some("expected-audience".to_string()))
                .await;
        let app = build_router(state);

        let mut claims = base_claims();
        claims["aud"] = serde_json::json!("someone-else");
        let token = sign_es256(&key, claims);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/catalog?node_id=sample-participant")
                    .header("Authorization", bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn catalog_route_403s_when_required_scope_is_missing() {
        let (state, key) =
            oauth2_catalog_state(|config| config.required_scope = Some("catalog:read".to_string()))
                .await;
        let app = build_router(state);

        let mut claims = base_claims();
        claims["scope"] = serde_json::json!("sparql:read");
        let token = sign_es256(&key, claims);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/catalog?node_id=sample-participant")
                    .header("Authorization", bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn catalog_route_200s_with_the_real_body_for_a_fully_valid_token() {
        let (state, key) = oauth2_catalog_state(|_| {}).await;
        let app = build_router(state);
        let token = sign_es256(&key, base_claims());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/catalog?node_id=sample-participant")
                    .header("Authorization", bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: CatalogListResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.catalogs.len(), 1);
        assert_eq!(parsed.catalogs[0].id, "sample-catalog");
    }

    #[tokio::test]
    async fn health_route_stays_reachable_without_a_token_even_when_oauth2_is_configured() {
        let (state, _key) = oauth2_catalog_state(|_| {}).await;
        let app = build_router(state);
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
    }

    #[tokio::test]
    async fn sparql_route_401s_with_www_authenticate_when_no_token_is_given() {
        let (state, _key) = oauth2_sparql_state(|_| {}).await;
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sparql?query=ASK%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer"
        );
    }

    #[tokio::test]
    async fn sparql_route_403s_when_required_scope_is_missing() {
        let (state, key) =
            oauth2_sparql_state(|config| config.required_scope = Some("sparql:read".to_string()))
                .await;
        let app = build_router(state);

        let token = sign_es256(&key, base_claims());
        let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> ASK { ?d a dcat:Dataset }";
        let uri = format!("/sparql?query={}", urlencoding::encode(query));

        let response = app
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("Authorization", bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sparql_get_route_200s_with_the_real_body_for_a_fully_valid_token() {
        let (state, key) = oauth2_sparql_state(|_| {}).await;
        let app = build_router(state);
        let token = sign_es256(&key, base_claims());

        let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                     SELECT ?dataset WHERE { ?dataset a dcat:Dataset }";
        let uri = format!("/sparql?query={}", urlencoding::encode(query));
        let response = app
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("Authorization", bearer(&token))
                    .header("Accept", "application/sparql-results+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let bindings = parsed["results"]["bindings"].as_array().unwrap();
        assert_eq!(bindings.len(), 1);
        assert!(
            bindings[0]["dataset"]["value"]
                .as_str()
                .unwrap()
                .contains("DATASET-A")
        );
    }

    #[tokio::test]
    async fn sparql_post_route_200s_with_the_real_body_for_a_fully_valid_token() {
        let (state, key) = oauth2_sparql_state(|_| {}).await;
        let app = build_router(state);
        let token = sign_es256(&key, base_claims());

        let query = "PREFIX dcat: <http://www.w3.org/ns/dcat#> \
                     SELECT ?dataset WHERE { ?dataset a dcat:Dataset }";
        let form_body = format!("query={}", urlencoding::encode(query));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sparql")
                    .header("Authorization", bearer(&token))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let bindings = parsed["results"]["bindings"].as_array().unwrap();
        assert_eq!(bindings.len(), 1);
        assert!(
            bindings[0]["dataset"]["value"]
                .as_str()
                .unwrap()
                .contains("DATASET-A")
        );
    }
}
