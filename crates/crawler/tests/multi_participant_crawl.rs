//! Hermetic, in-process multi-participant crawl integration test.
//!
//! Everything here runs inside this one test binary: no real EDC/JVM
//! process, no external network. Two real `ds-catalog-broker-rs` server
//! instances, one hand-built mock DCP-gated provider, and one hand-built
//! `did:web` issuer are bound to OS-assigned `127.0.0.1` ports and driven
//! with real HTTP calls (`reqwest`) through the crawler's actual
//! `crawler::crawl_once`:
//!
//! - **O ("open")**: a real `ds-catalog-broker-rs` instance,
//!   `DspAuthMode::Disabled`, seeded (directly via the cache's own
//!   `upsert`, not `seed_sample_catalog`) with distinct
//!   `OPEN-01`/`OPEN-02` datasets. No auth needed.
//! - **P ("provider", DCP-gated)**: **not** a `ds-catalog-broker-rs`
//!   instance - a small, standalone mock DSP catalog-request endpoint
//!   built by hand in this file (`spawn_mock_gated_provider`, a bare
//!   `axum::Router`), seeded with distinct `GATED-01`/`GATED-02` datasets.
//!   Only reachable with a valid DCP self-issued token backed by a
//!   Verifiable Credential that grants `GATED-01` (and, deliberately,
//!   *not* `GATED-02`). See the module-level note below,
//!   ["Why Instance P is no longer a `ds-catalog-broker-rs` instance"],
//!   for why.
//! - **H ("holder")**: the crawler's own `dcp_core::HolderIdentity` -
//!   `/dsp/holder/presentations/query` is the real, unmodified route
//!   `ds_catalog_broker_rs::build_router` already serves; the mock
//!   provider's own presentation-verification logic (below) calls it
//!   exactly as a real relying party would.
//!
//! ## Why Instance P is no longer a `ds-catalog-broker-rs` instance
//!
//! Instance P used to be a real `ds-catalog-broker-rs` server running
//! under `DspAuthMode::Dcp` (its DSP catalog-serving endpoint, gated by
//! its DCP *verifier* role, `dcp::verify_dcp_bearer_token`). Per
//! `docs/gap-analysis-2026-08-27.md` (S1), the next phase of this
//! workflow deletes that entire surface: `POST /dsp/catalog/request`,
//! `GET /dsp/did.json`, `DspAuthMode`/`DspAuthConfig`, and
//! `dcp::verify_dcp_bearer_token` itself - this product is a DSP
//! *Consumer* (Catalog Broker), and must never answer
//! `CatalogRequestMessage` as a Provider.
//!
//! Without a replacement, that deletion would silently take this test's
//! only real coverage of the crawler's outbound DCP token-minting/holder
//! path with it. So this test now builds its own minimal, independent
//! mock DCP-gated Catalog Service (`spawn_mock_gated_provider`) directly
//! out of `dcp_core`'s shared, role-agnostic JWS/`did:web` primitives -
//! the same ones the (soon-to-be-deleted) verifier used, and the same
//! ones `dcp_core::HolderIdentity` (staying, see below) still needs. The
//! mock's `mock_verify_dcp_bearer_token` function below is a faithful,
//! independent reimplementation of the same verification flow
//! `ds_catalog_broker_rs::dcp::verify_dcp_bearer_token` implements today
//! (resolve the caller's `did:web`, verify the signature, check
//! `aud`/`exp`, re-package the nested token, POST it to the caller's
//! Presentation API, verify the returned VP/VC) - not a stub that always
//! says yes. It does not import anything from `ds_catalog_broker_rs::dcp`
//! (that module is going away); it is built only from `dcp_core` plus a
//! bare `axum::Router`, so it keeps working unmodified once the product's
//! own verifier role is deleted.
//!
//! `dcp_core::HolderIdentity` (Instance H) is unaffected by any of this -
//! the DCP *holder* role is explicitly staying in scope (gap analysis
//! S2), and its routes (`/dsp/holder/did.json`,
//! `/dsp/holder/presentations/query`) are untouched product code.
//!
//! ## Three real bugs found while first writing this test, now fixed
//!
//! The first version of this test surfaced three genuine, confirmed bugs
//! that made even the DCP happy path unreachable via real, unmodified
//! routes. All three are now fixed in the implementation (not worked
//! around test-side).
//!
//! 1. `dcp_core::did_web_to_url`'s non-empty-path-segments branch never
//!    appended the `/did.json` suffix its own doc comment described, and
//!    `HolderIdentity::new` built a holder's own DID with a single
//!    hyphenated `dsp-holder` path segment rather than the two-segment
//!    `dsp:holder` that resolves (via `did_web_to_url`'s
//!    segments-joined-by-"/" rule) to the real registered route
//!    `/dsp/holder/did.json`. See
//!    [`resolve_did_reaches_the_real_holder_dsp_did_route`] below - it
//!    directly exercises `did_web_to_url` against the holder's real DID
//!    and confirms the computed URL now matches the real route exactly.
//!
//!    (This regression test originally also exercised the *verifier's*
//!    own `did:web` -> `/dsp/did.json` resolution the same way, using
//!    `ds_catalog_broker_rs`'s `DspAuthConfig`/`DspAuthMode::Dcp`/
//!    `DcpConfig`. That route and those types are exactly what
//!    `docs/gap-analysis-2026-08-27.md` (S1) removes in the next phase -
//!    this product never legitimately hosts a DSP catalog-serving
//!    endpoint, verifier-gated or not - so that half of the test was
//!    removed here rather than left asserting behavior of code that no
//!    longer exists. The mock provider built for this file now owns the
//!    equivalent "resolve a did:web to the right route" exercise for its
//!    *own* DID, as part of `mock_verify_dcp_bearer_token`'s real
//!    resolution of the holder's DID - see that function below.)
//! 2. `http-api::dcp::verify_dcp_bearer_token` (as it was before this
//!    workflow, now reimplemented independently below as
//!    `mock_verify_dcp_bearer_token`) builds the Presentation API query
//!    URL by appending `/presentations/query` to whatever the
//!    `CredentialService` `serviceEndpoint` is - a convention already
//!    validated against a real running `eclipse-edc/IdentityHub` (see
//!    `compliance/benchmark-dcp-2026-08-27.md`), i.e. that endpoint is
//!    expected to be a *base* URL. `HolderIdentity::own_did_document` was
//!    publishing the *already-complete* endpoint instead, so the append
//!    landed on a URL with the suffix doubled and 404'd. Fixed by making
//!    `HolderIdentity::own_did_document` publish the base URL, conforming
//!    to that pre-existing, already-proven convention. See
//!    [`credential_service_endpoint_is_the_real_reachable_presentation_api`]
//!    below.
//! 3. A per-VC verification loop shaped like `mock_verify_dcp_bearer_token`'s
//!    below (originally `verify_dcp_bearer_token`'s) treated an expired
//!    credential as "skip it, no error" - if the *only* VC in a
//!    presentation was expired, the function still returned an empty,
//!    ostensibly-successful access set, indistinguishable from a caller
//!    genuinely, correctly authorized for zero datasets.
//!    `crawler::crawl_one` then saw `Ok` and `crawl_once` overwrote that
//!    node's previously-good cached catalog with an empty one. Fixed: an
//!    all-expired presentation now returns `Err`, recorded as a crawl
//!    failure - see
//!    [`crawl_once_records_a_failure_for_an_expired_dcp_credential_and_preserves_prior_cache_data`]
//!    below. This test's assertions were never weakened; it simply
//!    passes now, and `mock_verify_dcp_bearer_token` preserves the fixed
//!    behavior (not the original buggy one) since it is what this test's
//!    negative-path assertions actually exercise now that Instance P is
//!    this file's own mock rather than product code.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use catalog_core::{Catalog, Dataset, NodeId};
use crawler::{ParticipantEntry, crawl_once};
use dcp_core::{
    DcpKeyPair, EXPECTED_CREDENTIAL_TYPE, HolderIdentity, PRESENTATION_QUERY_CONTEXT, PresentationQueryMessage,
    PresentationResponseMessage, decode_jws_unverified, did_web_to_url, find_verifying_key, now_secs, resolve_did,
    service_endpoint_url, sign_jws, verify_jws_signature,
};
use ds_catalog_broker_rs::{AppState, build_router};
use rdf_store::memory::InMemoryCatalogCache;
use rdf_store::{CatalogCache, CatalogQuery};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use uuid::Uuid;

const SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read";
/// `did:web` path-segment convention this test's own mock gated provider
/// uses for its own identity (`did:web:<host>:dsp`) - chosen to mirror the
/// real, now-being-removed verifier's own convention purely for realism;
/// nothing in the mock or in production code requires this exact segment.
const MOCK_PROVIDER_DID_PATH_SEGMENT: &str = "dsp";

async fn bind_localhost() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");
    (listener, addr)
}

fn spawn(listener: TcpListener, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum::serve");
    })
}

fn dataset(id: &str) -> Dataset {
    Dataset {
        id: id.to_string(),
        properties: Default::default(),
        distributions: Vec::new(),
    }
}

// --- Regression test for bug #1 (holder half only - see module doc) ---

/// Regression test for bug #1: `did_web_to_url` (the function
/// `resolve_did`/`answer_presentation_query` use internally) now computes
/// the exact URL a real, unmodified `ds-catalog-broker-rs` instance
/// actually serves for a holder's own DID - no test-side route
/// substitution. See the module doc's
/// ["Why Instance P is no longer a `ds-catalog-broker-rs` instance"]
/// section for why this no longer also covers the verifier's own DID -
/// that route is being removed as part of this workflow's next phase,
/// and `ds_catalog_broker_rs::build_router` is no longer given a
/// `DspAuthConfig` here at all.
#[tokio::test]
async fn resolve_did_reaches_the_real_holder_dsp_did_route() {
    let (listener, addr) = bind_localhost().await;
    let host = format!("127.0.0.1:{}", addr.port());
    let holder = Arc::new(HolderIdentity::new(host.clone(), true, "unused.unused.unused".to_string(), SCOPE.to_string()));
    let holder_did = holder.key_pair.own_did.clone();

    let state = AppState::new(Arc::new(InMemoryCatalogCache::new())).with_holder(Some(holder));
    let app = build_router(state);
    let _server = spawn(listener, app);

    let client = reqwest::Client::new();
    let base = format!("http://{host}");

    let holder_url = did_web_to_url(&holder_did, true).expect("did_web_to_url");
    assert_eq!(holder_url, format!("{base}/dsp/holder/did.json"));
    let holder_response = client.get(&holder_url).send().await.expect("GET holder DID doc");
    assert_eq!(holder_response.status(), reqwest::StatusCode::OK, "computed holder DID URL reaches the real route");
}

/// Regression test for bug #2: `HolderIdentity::own_did_document` now
/// publishes a *base* `CredentialService` endpoint, and
/// `format!("{endpoint}/presentations/query")` - exactly what
/// `mock_verify_dcp_bearer_token` below builds (mirroring what the real,
/// now-being-removed `verify_dcp_bearer_token` built) - reaches the real,
/// unmodified route.
#[tokio::test]
async fn credential_service_endpoint_is_the_real_reachable_presentation_api() {
    let (listener, addr) = bind_localhost().await;
    let host = format!("127.0.0.1:{}", addr.port());
    let holder = Arc::new(HolderIdentity::new(host.clone(), true, "unused.unused.unused".to_string(), SCOPE.to_string()));
    let published_endpoint = holder
        .own_did_document()
        .get("service")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|entry| entry.get("serviceEndpoint"))
        .and_then(|v| v.as_str())
        .expect("CredentialService entry with a serviceEndpoint")
        .to_string();
    assert_eq!(published_endpoint, format!("http://{host}/dsp/holder"), "published endpoint is the base URL");

    let state = AppState::new(Arc::new(InMemoryCatalogCache::new())).with_holder(Some(holder));
    let app = build_router(state);
    let _server = spawn(listener, app);

    let client = reqwest::Client::new();
    let query_url = format!("{published_endpoint}/presentations/query");
    assert_eq!(query_url, format!("http://{host}/dsp/holder/presentations/query"));

    // No auth header: 401 (the real handler ran and rejected it), not 404
    // (which would mean the route doesn't exist at this address).
    let response = client.post(&query_url).send().await.expect("POST presentations/query");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the real route is reachable at exactly the URL mock_verify_dcp_bearer_token builds"
    );
}

// --- Wiring for the happy-path / negative-path scenarios below --------

struct OpenParticipant {
    entry: ParticipantEntry,
    _server: JoinHandle<()>,
}

async fn spawn_open_participant() -> OpenParticipant {
    let (listener, addr) = bind_localhost().await;
    let cache = Arc::new(InMemoryCatalogCache::new());
    let mut catalog = Catalog::new("open-catalog", NodeId::new("open-participant"));
    catalog.participant_id = Some("did:example:open-participant".to_string());
    catalog.datasets.push(dataset("OPEN-01"));
    catalog.datasets.push(dataset("OPEN-02"));
    cache.upsert(catalog).await.expect("seed open catalog");

    let state = AppState::new(cache);
    let server = spawn(listener, build_router(state));

    OpenParticipant {
        entry: ParticipantEntry {
            id: "open-participant".to_string(),
            name: "Open participant".to_string(),
            catalog_request_url: format!("http://{addr}/dsp/catalog/request"),
            requires_dcp: false,
            provider_did: None,
        },
        _server: server,
    }
}

// --- The mock DCP-gated provider (Instance P) --------------------------
//
// A small, self-contained, TEST-ONLY stand-in for a DCP-gated remote DSP
// Catalog Service. Built directly out of `dcp_core`'s shared primitives -
// not `ds_catalog_broker_rs`, not `ds_catalog_broker_rs::dcp` - so it
// keeps exercising the crawler's real outbound DCP-holder path once this
// product's own verifier role (and the endpoint it gated) are deleted.
// See the module doc's
// ["Why Instance P is no longer a `ds-catalog-broker-rs` instance"]
// section.

/// Everything the mock provider's handlers need: its own signing
/// identity, the scope it requests from a caller's Presentation API, the
/// shared `reqwest::Client` used for its own outbound DID
/// resolution/Presentation API calls, and the seeded dataset list it
/// serves once a caller is verified.
struct MockGatedProviderState {
    key_pair: DcpKeyPair,
    required_scope: String,
    insecure_http: bool,
    http: reqwest::Client,
    catalog_id: String,
    participant_id: String,
    datasets: Vec<Dataset>,
}

/// `GET /dsp/did.json` - this mock provider's own `did:web` document, so
/// a caller's Presentation API (via the proof-of-original-possession
/// re-packaged token this mock sends it - see `mock_verify_dcp_bearer_token`)
/// can resolve the key that signs it. Mirrors what the real, now-being-
/// removed verifier's `own_did_document_route` served, but is this test's
/// own, independent handler.
async fn mock_provider_did_document(State(state): State<Arc<MockGatedProviderState>>) -> impl IntoResponse {
    Json(state.key_pair.did_document(&[]))
}

/// `POST /dsp/catalog/request` - the mock provider's DSP catalog
/// endpoint. Requires `Authorization: Bearer <token>`; the token is
/// verified for real by `mock_verify_dcp_bearer_token` below (real
/// signature checks and DID resolution, not a stub), and the response is
/// this participant's seeded dataset list, filtered to what the verified
/// caller's credential(s) actually grant.
async fn mock_provider_catalog_request(State(state): State<Arc<MockGatedProviderState>>, headers: HeaderMap) -> impl IntoResponse {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response();
    };

    match mock_verify_dcp_bearer_token(token, &state).await {
        Ok(catalog_access) => {
            let visible_datasets: Vec<Value> = state
                .datasets
                .iter()
                .filter(|d| catalog_access.contains(&d.id))
                .map(|d| json!({"@id": d.id, "id": d.id}))
                .collect();
            let body = json!({
                "@id": state.catalog_id,
                "participantId": state.participant_id,
                "dataset": visible_datasets,
                "service": [],
            });
            Json(body).into_response()
        }
        Err(err) => (StatusCode::UNAUTHORIZED, err).into_response(),
    }
}

/// Independent reimplementation of the real (soon-to-be-deleted)
/// `ds_catalog_broker_rs::dcp::verify_dcp_bearer_token`'s flow, built only
/// from `dcp_core`'s shared, role-agnostic primitives - see the module
/// doc for why this exists and what it deliberately preserves: real
/// `did:web` resolution, real JWS signature verification (of the
/// self-issued token, the re-packaged proof-of-original-possession token,
/// the returned VerifiablePresentation, and each embedded Verifiable
/// Credential against its own issuer), and the same expired-credential
/// failure semantics as bug #3 above.
async fn mock_verify_dcp_bearer_token(token: &str, state: &MockGatedProviderState) -> Result<HashSet<String>, String> {
    let (_, header_t1, payload_t1) = decode_jws_unverified(token)?;
    let holder_did = payload_t1.get("iss").and_then(Value::as_str).ok_or("token has no iss")?.to_string();
    let kid_t1 = header_t1.get("kid").and_then(Value::as_str).ok_or("token has no kid")?;

    let holder_doc = resolve_did(&state.http, &holder_did, state.insecure_http).await?;
    let holder_key = find_verifying_key(&holder_doc, kid_t1)?;
    verify_jws_signature(token, &holder_key)?;

    let aud = payload_t1.get("aud").and_then(Value::as_str).unwrap_or("");
    if aud != state.key_pair.own_did {
        return Err(format!("token audience '{aud}' does not match this mock provider's DID '{}'", state.key_pair.own_did));
    }

    let exp = payload_t1.get("exp").and_then(Value::as_u64).unwrap_or(0);
    if exp <= now_secs() {
        return Err("token has expired".to_string());
    }

    let nested_token = payload_t1
        .get("token")
        .and_then(Value::as_str)
        .ok_or("token has no nested presentation-access-token claim")?;

    // Proof of original possession: re-package the nested token into a
    // new self-issued token, signed with this mock provider's own key,
    // addressed back to the holder - exactly what the real verifier did.
    let now = now_secs();
    let repackaged_payload = json!({
        "iss": state.key_pair.own_did,
        "sub": state.key_pair.own_did,
        "aud": holder_did,
        "token": nested_token,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": Uuid::new_v4().to_string(),
    });
    let repackaged_token = sign_jws(&repackaged_payload, &state.key_pair.signing_key(), &state.key_pair.own_key_id);

    let credential_service = service_endpoint_url(&holder_doc, "CredentialService")?;
    let query_url = format!("{credential_service}/presentations/query");
    let query_body = PresentationQueryMessage {
        context: PRESENTATION_QUERY_CONTEXT,
        ld_type: "PresentationQueryMessage",
        scope: vec![state.required_scope.clone()],
    };
    let response = state
        .http
        .post(&query_url)
        .bearer_auth(&repackaged_token)
        .json(&query_body)
        .send()
        .await
        .map_err(|e| format!("presentation query to {query_url} failed: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("presentation query returned HTTP {status}: {body}"));
    }
    let presentation_response: PresentationResponseMessage =
        response.json().await.map_err(|e| format!("malformed presentation response: {e}"))?;
    let vp_jws = presentation_response.presentation.first().ok_or("presentation response had no presentation")?;

    // Verify the VP itself (signed by the holder).
    let (_, vp_header, vp_payload) = decode_jws_unverified(vp_jws)?;
    let vp_kid = vp_header.get("kid").and_then(Value::as_str).ok_or("VP has no kid")?;
    let vp_key = find_verifying_key(&holder_doc, vp_kid)?;
    verify_jws_signature(vp_jws, &vp_key)?;

    let vc_jws_list = vp_payload
        .get("vp")
        .and_then(|vp| vp.get("verifiableCredential"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if vc_jws_list.is_empty() {
        return Err("VerifiablePresentation contained no credentials".to_string());
    }

    let mut catalog_access = HashSet::new();
    let mut had_expired_credential = false;
    for vc_value in &vc_jws_list {
        let vc_jws = vc_value.as_str().ok_or("verifiableCredential entry was not a string")?;
        let (_, vc_header, vc_payload) = decode_jws_unverified(vc_jws)?;
        let issuer_did = vc_payload.get("iss").and_then(Value::as_str).ok_or("VC has no iss")?.to_string();
        let vc_kid = vc_header.get("kid").and_then(Value::as_str).ok_or("VC has no kid")?;

        // Each credential may (in general) come from a different issuer -
        // resolve per credential rather than assuming they share the
        // holder's DID.
        let issuer_doc = resolve_did(&state.http, &issuer_did, state.insecure_http).await?;
        let issuer_key = find_verifying_key(&issuer_doc, vc_kid)?;
        verify_jws_signature(vc_jws, &issuer_key)?;

        let vc_exp = vc_payload.get("exp").and_then(Value::as_u64).unwrap_or(0);
        if vc_exp <= now_secs() {
            // Expired credential: skip granting its access, but remember
            // this happened - an all-expired presentation must not read
            // as "authenticated, genuinely granted nothing" (bug #3).
            had_expired_credential = true;
            continue;
        }

        let vc_body = vc_payload.get("vc").cloned().unwrap_or(Value::Null);
        let types = vc_body.get("type").and_then(Value::as_array).cloned().unwrap_or_default();
        let has_expected_type = types.iter().any(|t| t.as_str() == Some(EXPECTED_CREDENTIAL_TYPE));
        if !has_expected_type {
            continue;
        }

        if let Some(access) = vc_body
            .get("credentialSubject")
            .and_then(|s| s.get("catalogAccess"))
            .and_then(Value::as_array)
        {
            for id in access {
                if let Some(id) = id.as_str() {
                    catalog_access.insert(id.to_string());
                }
            }
        }
    }

    // An empty result is normally a legitimate "authenticated, genuinely
    // granted nothing" outcome - but if it's empty *because* every
    // credential presented was expired, that's an authentication
    // failure, not a valid zero-access caller (bug #3).
    if catalog_access.is_empty() && had_expired_credential {
        return Err("all presented credentials are expired".to_string());
    }

    Ok(catalog_access)
}

struct GatedParticipant {
    entry: ParticipantEntry,
    _server: JoinHandle<()>,
}

/// Spin up the mock DCP-gated provider (Instance P), seeded with
/// `GATED-01`/`GATED-02`, serving its own real (test-only) `/dsp/did.json`
/// and `/dsp/catalog/request` routes - see the module doc and this file's
/// "mock DCP-gated provider" section above for why this is no longer a
/// `ds-catalog-broker-rs` instance.
async fn spawn_gated_participant() -> GatedParticipant {
    let (listener, addr) = bind_localhost().await;
    let host = format!("127.0.0.1:{}", addr.port());
    let own_did = format!("did:web:{}:{MOCK_PROVIDER_DID_PATH_SEGMENT}", host.replace(':', "%3A"));

    let state = Arc::new(MockGatedProviderState {
        key_pair: DcpKeyPair::generate(own_did.clone()),
        required_scope: SCOPE.to_string(),
        insecure_http: true,
        http: reqwest::Client::new(),
        catalog_id: "gated-catalog".to_string(),
        participant_id: "did:example:gated-participant".to_string(),
        datasets: vec![dataset("GATED-01"), dataset("GATED-02")],
    });

    let app = Router::new()
        .route("/dsp/did.json", get(mock_provider_did_document))
        .route("/dsp/catalog/request", post(mock_provider_catalog_request))
        .with_state(state);
    let server = spawn(listener, app);

    GatedParticipant {
        entry: ParticipantEntry {
            id: "gated-participant".to_string(),
            name: "DCP-gated participant".to_string(),
            catalog_request_url: format!("http://{addr}/dsp/catalog/request"),
            requires_dcp: true,
            provider_did: Some(own_did),
        },
        _server: server,
    }
}

struct HolderRig {
    holder: Arc<HolderIdentity>,
    _server: JoinHandle<()>,
}

/// Spin up Instance H (the crawler's own DCP holder identity, reused as
/// the Presentation API callback target): a real `HolderIdentity` serving
/// the real, unmodified `/dsp/holder/did.json` and
/// `/dsp/holder/presentations/query` routes on a real
/// `ds-catalog-broker-rs` instance - no test-side route substitution
/// needed now that bugs #1/#2 are fixed. This is untouched by Instance
/// P's move to a hand-built mock: the DCP holder role, and the product
/// routes serving it, are staying in scope (gap analysis S2).
///
/// `credential_jws_for` receives the holder's own DID (only known once
/// `HolderIdentity::new` has run inside this function) and returns the
/// already-signed VC JWS `answer_presentation_query` will serve.
async fn spawn_holder(credential_jws_for: impl FnOnce(&str) -> String) -> HolderRig {
    let (listener, addr) = bind_localhost().await;
    let host = format!("127.0.0.1:{}", addr.port());

    // HolderIdentity::new generates a fresh key every call (see its doc
    // comment) - this must be the one and only instance we build and then
    // finalize below, not a second throwaway.
    let mut holder = HolderIdentity::new(host.clone(), true, String::new(), SCOPE.to_string());
    let holder_did = holder.key_pair.own_did.clone();
    holder.credential_jws = credential_jws_for(&holder_did);

    let holder = Arc::new(holder);
    let state = AppState::new(Arc::new(InMemoryCatalogCache::new())).with_holder(Some(holder.clone()));
    let server = spawn(listener, build_router(state));

    HolderRig { holder, _server: server }
}

/// Spin up a minimal, standalone `did:web` identity for a credential
/// issuer - a real party distinct from the holder, as real DCP has it
/// (rather than co-residing the issuer's key in the holder's own DID
/// document, a simplification that isn't necessary now that DID
/// resolution actually works end to end). Path-segment-free DIDs
/// (`did:web:<host>`, no further `:segment`s) resolve to
/// `/.well-known/did.json` per `did_web_to_url` - that branch was never
/// affected by bug #1, so no `ds-catalog-broker-rs` dependency is needed
/// here at all (nor was it ever - this was already a bare, hand-built
/// `axum::Router`, the same pattern the mock gated provider above now
/// also uses).
async fn spawn_issuer() -> (DcpKeyPair, JoinHandle<()>) {
    let (listener, addr) = bind_localhost().await;
    let issuer_did = format!("did:web:127.0.0.1%3A{}", addr.port());
    let issuer_key = DcpKeyPair::generate(issuer_did);
    let did_doc = issuer_key.did_document(&[]);

    let app = Router::new().route(
        "/.well-known/did.json",
        get(move || {
            let did_doc = did_doc.clone();
            async move { Json(did_doc) }
        }),
    );
    let server = spawn(listener, app);
    (issuer_key, server)
}

/// Sign a `FederatedCatalogAccessCredential` VC JWS shaped exactly as
/// `mock_verify_dcp_bearer_token`'s VC-verification steps expect to
/// parse: `iss` = the issuer's own DID, `sub` = holder DID, `vc.type`
/// includes `FederatedCatalogAccessCredential`,
/// `vc.credentialSubject.catalogAccess` = the granted dataset ids, `exp` =
/// the given expiry (a past timestamp produces a deliberately expired
/// credential).
fn issue_credential(issuer_key: &DcpKeyPair, holder_did: &str, catalog_access: &[&str], exp: u64) -> String {
    let payload = json!({
        "iss": issuer_key.own_did,
        "sub": holder_did,
        "vc": {
            "type": ["VerifiableCredential", "FederatedCatalogAccessCredential"],
            "credentialSubject": {
                "catalogAccess": catalog_access,
            }
        },
        "exp": exp,
    });
    sign_jws(&payload, &issuer_key.signing_key(), &issuer_key.own_key_id)
}

// --- Happy path: two participants, one gated with real per-caller ------
// --- DCP filtering ------------------------------------------------------

#[tokio::test]
async fn crawl_once_pulls_open_and_dcp_gated_catalogs_with_real_per_caller_filtering() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn,ds_catalog_broker_rs=debug,dcp_core=debug").try_init();
    let open = spawn_open_participant().await;
    let gated = spawn_gated_participant().await;

    let (issuer_key, _issuer_server) = spawn_issuer().await;
    let holder_rig = spawn_holder(move |holder_did| {
        // Grants GATED-01 only - GATED-02 must never appear in the
        // crawler's result for this participant.
        issue_credential(&issuer_key, holder_did, &["GATED-01"], now_secs() + 3600)
    })
    .await;

    let participants = vec![clone_entry(&open.entry), clone_entry(&gated.entry)];
    let http = reqwest::Client::new();
    let cache = InMemoryCatalogCache::new();

    let summary = crawl_once(&http, &participants, Some(holder_rig.holder.as_ref()), &cache).await;

    assert_eq!(summary.attempted, 2, "attempted: {summary:?}");
    assert_eq!(summary.failed, 0, "failed (failures: {:?}): {summary:?}", summary.failures);
    assert_eq!(summary.succeeded, 2, "succeeded: {summary:?}");

    let open_catalogs = cache.query(CatalogQuery::for_node(NodeId::new("open-participant"))).await.unwrap();
    assert_eq!(open_catalogs.len(), 1);
    let mut open_ids: Vec<&str> = open_catalogs[0].datasets.iter().map(|d| d.id.as_str()).collect();
    open_ids.sort_unstable();
    assert_eq!(open_ids, vec!["OPEN-01", "OPEN-02"]);

    let gated_catalogs = cache.query(CatalogQuery::for_node(NodeId::new("gated-participant"))).await.unwrap();
    assert_eq!(gated_catalogs.len(), 1);
    let gated_ids: Vec<&str> = gated_catalogs[0].datasets.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(gated_ids, vec!["GATED-01"], "GATED-02 was never granted by the credential and must not be visible");
}

// --- Negative path: an expired credential must not be treated as a ----
// --- silent, empty success --------------------------------------------

/// This test is written to assert the behavior the task briefing calls
/// for. That signal is a **third confirmed bug**: with only one VC in the
/// presentation and that VC expired, a per-VC verification loop shaped
/// like `mock_verify_dcp_bearer_token`'s below (originally
/// `verify_dcp_bearer_token`'s, in the now-being-removed product verifier)
/// treated an expired credential as "skip it, no error" - if the *only*
/// VC in a presentation was expired, the function still returned an
/// ostensibly-successful, empty access set - indistinguishable from a
/// caller genuinely, correctly authorized for zero datasets. The gated
/// provider therefore answered success with an empty dataset list
/// (identical to "authenticated, but genuinely granted nothing"), so
/// `crawler::crawl_one` saw `Ok`, `crawl_once` called `cache.upsert` on
/// the resulting *empty* catalog, and that overwrote this node's prior
/// good cached data. `mock_verify_dcp_bearer_token` preserves the fixed
/// behavior (an all-expired presentation is a hard failure, not a valid
/// zero-access caller - see bug #3 in the module doc), so this test
/// exercises the same real signal the original did, independent of
/// `ds_catalog_broker_rs`.
#[tokio::test]
async fn crawl_once_records_a_failure_for_an_expired_dcp_credential_and_preserves_prior_cache_data() {
    let gated = spawn_gated_participant().await;

    let (issuer_key, _issuer_server) = spawn_issuer().await;
    let holder_rig = spawn_holder(move |holder_did| {
        // exp in the past: this credential is already expired the moment
        // it's presented.
        issue_credential(&issuer_key, holder_did, &["GATED-01"], now_secs().saturating_sub(3600))
    })
    .await;

    let participants = vec![clone_entry(&gated.entry)];
    let http = reqwest::Client::new();
    let cache = InMemoryCatalogCache::new();

    // Seed the cache with prior, good crawl data for this same node -
    // proof that a failed re-crawl must not clobber it.
    let mut prior_good = Catalog::new("gated-catalog-prior", NodeId::new("gated-participant"));
    prior_good.datasets.push(dataset("GATED-01"));
    cache.upsert(prior_good.clone()).await.unwrap();

    let summary = crawl_once(&http, &participants, Some(holder_rig.holder.as_ref()), &cache).await;

    assert_eq!(summary.attempted, 1, "attempted: {summary:?}");
    assert_eq!(
        summary.failed, 1,
        "an expired credential must be recorded as a crawl failure, not a silent empty success: {summary:?}"
    );
    assert_eq!(summary.succeeded, 0, "succeeded: {summary:?}");

    let stored = cache.query(CatalogQuery::for_node(NodeId::new("gated-participant"))).await.unwrap();
    assert_eq!(stored.len(), 1, "prior cached catalog for this node must still be present");
    assert_eq!(
        stored[0], prior_good,
        "a failed crawl must not overwrite the previously cached good catalog for this node"
    );
}

/// `ParticipantEntry` has no `Clone` derive (it's not needed anywhere in
/// production code), but this test file wants to keep each fixture's
/// `entry` alongside its still-alive server handle while also building a
/// `Vec<ParticipantEntry>` to hand to `crawl_once` - so build the vec by
/// hand instead of adding a `Clone` derive to production code for a
/// test-only convenience.
fn clone_entry(entry: &ParticipantEntry) -> ParticipantEntry {
    ParticipantEntry {
        id: entry.id.clone(),
        name: entry.name.clone(),
        catalog_request_url: entry.catalog_request_url.clone(),
        requires_dcp: entry.requires_dcp,
        provider_did: entry.provider_did.clone(),
    }
}
