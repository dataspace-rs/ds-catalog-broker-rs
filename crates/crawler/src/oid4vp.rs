//! OID4VP (OpenID for Verifiable Presentations) v1, single-shot holder
//! presentation - see `docs/oid4vp-holder-2026-08-28.md` for the full
//! design and why this is deliberately *not* the full interactive
//! Authorization Request/Response negotiation.
//!
//! Reuses `dcp_core::DcpKeyPair` (ES256 signing, `did:web` identity) and
//! `dcp_core::{sign_jws, b64_encode, now_secs}` - the same "sign this JSON
//! with my key" primitives `HolderIdentity::mint_self_issued_token`
//! already uses for DCP's own T1, just wrapped in OID4VP's own wire shape
//! (`vp_token` + `presentation_submission`, `direct_post`-style) instead
//! of DCP's bearer-token-with-callback shape.

use dcp_core::{DcpKeyPair, now_secs, sign_jws};
use serde_json::{Value, json};

/// This project defines and expects exactly one credential type per
/// participant (mirroring `dcp_core::EXPECTED_CREDENTIAL_TYPE`'s own
/// single-credential-type assumption on the DCP side), not a general
/// Presentation-Exchange client capable of satisfying an arbitrary
/// requested `presentation_definition`. A participant requiring a
/// different shape is out of scope for v1 - see
/// `docs/oid4vp-holder-2026-08-28.md`.
pub const DEFINITION_ID: &str = "federated-catalog-access";

/// The fixed `descriptor_map` entry id every `presentation_submission`
/// this crawler builds uses - see [`DEFINITION_ID`]'s doc comment.
const DESCRIPTOR_ID: &str = "federated-catalog-access-credential";

/// Builds a JWT-VP: a JWT enveloping the existing W3C VC-JWT
/// `credential_jws` as its `vp` claim - the standard nesting for
/// `vp_formats: jwt_vp_json`. `nonce` is a fresh UUID per call (this is
/// v1's self-generated nonce, not a verifier-issued one - see the design
/// doc's "Consequence, stated plainly" section on why that limits, rather
/// than eliminates, replay protection). `exp` is `iat + 300` seconds,
/// matching DCP's own T1/T2 lifetime.
pub fn build_vp_token(key_pair: &DcpKeyPair, credential_jws: &str, audience: &str) -> String {
    let now = now_secs();
    let payload = json!({
        "iss": key_pair.own_did,
        "sub": key_pair.own_did,
        "aud": audience,
        "nonce": uuid::Uuid::new_v4().to_string(),
        "iat": now,
        "exp": now + 300,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [credential_jws],
        },
    });
    sign_jws(&payload, &key_pair.signing_key(), &key_pair.own_key_id)
}

/// Builds the DIF Presentation Exchange `presentation_submission` object
/// OID4VP requires alongside `vp_token`, referencing one fixed,
/// well-known `descriptor_map` entry - see [`DEFINITION_ID`]'s doc
/// comment for why this is fixed rather than general. `id` is a fresh
/// UUID per call (the submission's own id, distinct from the
/// `definition_id` it answers).
pub fn build_presentation_submission(definition_id: &str) -> Value {
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "definition_id": definition_id,
        "descriptor_map": [{
            "id": DESCRIPTOR_ID,
            "format": "jwt_vp_json",
            "path": "$",
        }],
    })
}

/// A failure presenting an OID4VP `vp_token` to a participant's
/// `oid4vp_response_uri`. Returned by [`present`] rather than panicking -
/// matching every other per-participant crawl-failure mode already in
/// `crawler::crawl_one`.
#[derive(Debug, thiserror::Error)]
pub enum Oid4VpError {
    #[error("request to {uri} failed: {source}")]
    Transport {
        uri: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{uri} returned HTTP {status}")]
    NonSuccessStatus { uri: String, status: reqwest::StatusCode },
    #[error("response from {uri} was not valid JSON: {source}")]
    MalformedResponse {
        uri: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("response from {uri} had no access_token field")]
    MissingAccessToken { uri: String },
}

/// Builds a `vp_token` + `presentation_submission` and POSTs them
/// `application/x-www-form-urlencoded` to `response_uri` (`direct_post`
/// style), returning the `access_token` a `200` JSON response is expected
/// to carry - the short-lived credential this crawler then attaches as
/// `Authorization: Bearer <access_token>` on the real
/// `catalog_request_url` call, exactly parallel to how the DCP path
/// attaches its self-issued T1.
///
/// `audience` for the `vp_token`'s `aud` claim is `response_uri` itself -
/// v1 has no separate verifier `client_id` to address it to (see the
/// design doc's single-shot-not-interactive scope), and the response
/// endpoint is the only identifier of "who this presentation is for" this
/// crawler actually has.
pub async fn present(
    http: &reqwest::Client,
    key_pair: &DcpKeyPair,
    credential_jws: &str,
    response_uri: &str,
) -> Result<String, Oid4VpError> {
    let vp_token = build_vp_token(key_pair, credential_jws, response_uri);
    let presentation_submission = build_presentation_submission(DEFINITION_ID).to_string();

    let response = http
        .post(response_uri)
        .form(&[("vp_token", vp_token.as_str()), ("presentation_submission", presentation_submission.as_str())])
        .send()
        .await
        .map_err(|source| Oid4VpError::Transport { uri: response_uri.to_string(), source })?;

    if !response.status().is_success() {
        return Err(Oid4VpError::NonSuccessStatus {
            uri: response_uri.to_string(),
            status: response.status(),
        });
    }

    let body: Value = response
        .json()
        .await
        .map_err(|source| Oid4VpError::MalformedResponse { uri: response_uri.to_string(), source })?;

    body.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Oid4VpError::MissingAccessToken { uri: response_uri.to_string() })
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::{Json, Router};
    use dcp_core::{DcpKeyPair, DidDocument, decode_jws_unverified, find_verifying_key, verify_jws_signature};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use super::*;

    const CREDENTIAL_JWS: &str = "fake.credential.jws";
    const AUDIENCE: &str = "http://127.0.0.1:19003/oid4vp/response";

    fn key_pair() -> DcpKeyPair {
        DcpKeyPair::generate("did:web:localhost%3A19100:dsp:holder".to_string())
    }

    /// Resolves `token`'s own signature against `key_pair`'s own public
    /// key, going through `key_pair.did_document(&[])` +
    /// `dcp_core::find_verifying_key` rather than constructing a
    /// `p256::ecdsa::VerifyingKey` by hand - proves the token verifies the
    /// same way a real relying party resolving this holder's `did:web`
    /// document would.
    fn assert_signature_verifies(token: &str, key_pair: &DcpKeyPair) {
        let doc: DidDocument = serde_json::from_value(key_pair.did_document(&[])).expect("valid did document");
        let verifying_key = find_verifying_key(&doc, &key_pair.own_key_id).expect("key pair's own kid is in its own did document");
        verify_jws_signature(token, &verifying_key).expect("signature must verify against the key pair's own public key");
    }

    #[test]
    fn build_vp_token_produces_a_three_segment_jws_with_the_documented_claims() {
        let key_pair = key_pair();
        let token = build_vp_token(&key_pair, CREDENTIAL_JWS, AUDIENCE);

        assert_eq!(token.split('.').count(), 3, "a compact JWS has exactly 3 dot-separated segments");

        let (_, header, payload) = decode_jws_unverified(&token).expect("valid JWS");
        assert_eq!(header["alg"], json!("ES256"));
        assert_eq!(header["kid"], json!(key_pair.own_key_id));

        assert_eq!(payload["iss"], json!(key_pair.own_did));
        assert_eq!(payload["sub"], json!(key_pair.own_did));
        assert_eq!(payload["aud"], json!(AUDIENCE));
        assert!(payload["nonce"].is_string(), "nonce must be present");

        let iat = payload["iat"].as_u64().expect("iat present");
        let exp = payload["exp"].as_u64().expect("exp present");
        assert_eq!(exp, iat + 300, "exp must be iat + 300s, matching DCP's own T1/T2 lifetime");

        let vp = &payload["vp"];
        assert_eq!(vp["@context"], json!(["https://www.w3.org/2018/credentials/v1"]));
        assert_eq!(vp["type"], json!(["VerifiablePresentation"]));
        assert_eq!(vp["verifiableCredential"], json!([CREDENTIAL_JWS]));

        assert_signature_verifies(&token, &key_pair);
    }

    #[test]
    fn build_vp_token_uses_a_fresh_nonce_on_every_call() {
        let key_pair = key_pair();
        let token_a = build_vp_token(&key_pair, CREDENTIAL_JWS, AUDIENCE);
        let token_b = build_vp_token(&key_pair, CREDENTIAL_JWS, AUDIENCE);

        let (_, _, payload_a) = decode_jws_unverified(&token_a).expect("valid JWS");
        let (_, _, payload_b) = decode_jws_unverified(&token_b).expect("valid JWS");

        assert_ne!(
            payload_a["nonce"], payload_b["nonce"],
            "each call must mint a fresh nonce, proving freshness rather than a static/reused value"
        );
    }

    #[test]
    fn build_presentation_submission_has_the_documented_fixed_shape() {
        let submission = build_presentation_submission("federated-catalog-access");

        assert!(submission["id"].is_string(), "submission needs its own fresh id");
        assert_eq!(submission["definition_id"], json!("federated-catalog-access"));

        let descriptor_map = submission["descriptor_map"].as_array().expect("descriptor_map array");
        assert_eq!(descriptor_map.len(), 1, "this project expects exactly one credential type per participant");
        assert_eq!(descriptor_map[0]["id"], json!("federated-catalog-access-credential"));
        assert_eq!(descriptor_map[0]["format"], json!("jwt_vp_json"));
        assert_eq!(descriptor_map[0]["path"], json!("$"));
    }

    #[test]
    fn build_presentation_submission_mints_a_fresh_id_on_every_call() {
        let a = build_presentation_submission("federated-catalog-access");
        let b = build_presentation_submission("federated-catalog-access");
        assert_ne!(a["id"], b["id"]);
    }

    async fn bind_localhost() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");
        (listener, format!("http://{addr}/oid4vp/response"))
    }

    fn spawn(listener: TcpListener, app: Router) {
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("axum::serve");
        });
    }

    async fn respond_json(status: axum::http::StatusCode, body: Value) -> impl IntoResponse {
        (status, Json(body))
    }

    #[tokio::test]
    async fn present_returns_the_access_token_on_a_real_200_response() {
        let (listener, response_uri) = bind_localhost().await;
        let app = Router::new().route(
            "/oid4vp/response",
            post(|| respond_json(axum::http::StatusCode::OK, json!({"access_token": "mock-access-token-123"}))),
        );
        spawn(listener, app);

        let key_pair = key_pair();
        let http = reqwest::Client::new();
        let token = present(&http, &key_pair, CREDENTIAL_JWS, &response_uri).await.expect("present should succeed");

        assert_eq!(token, "mock-access-token-123");
    }

    #[tokio::test]
    async fn present_returns_a_distinct_error_for_a_non_2xx_response() {
        let (listener, response_uri) = bind_localhost().await;
        let app = Router::new().route(
            "/oid4vp/response",
            post(|| respond_json(axum::http::StatusCode::UNAUTHORIZED, json!({"error": "invalid_request"}))),
        );
        spawn(listener, app);

        let key_pair = key_pair();
        let http = reqwest::Client::new();
        let err = present(&http, &key_pair, CREDENTIAL_JWS, &response_uri).await.expect_err("should fail on 401");

        assert!(matches!(err, Oid4VpError::NonSuccessStatus { .. }), "unexpected error variant: {err:?}");
    }

    #[tokio::test]
    async fn present_returns_a_distinct_error_for_a_response_missing_access_token() {
        let (listener, response_uri) = bind_localhost().await;
        let app = Router::new().route(
            "/oid4vp/response",
            post(|| respond_json(axum::http::StatusCode::OK, json!({"token_type": "Bearer"}))),
        );
        spawn(listener, app);

        let key_pair = key_pair();
        let http = reqwest::Client::new();
        let err = present(&http, &key_pair, CREDENTIAL_JWS, &response_uri)
            .await
            .expect_err("should fail when access_token is missing");

        assert!(matches!(err, Oid4VpError::MissingAccessToken { .. }), "unexpected error variant: {err:?}");
    }

    #[tokio::test]
    async fn present_returns_a_distinct_error_for_a_transport_failure() {
        // Port 0 never accepts connections, so this is guaranteed to fail
        // at the transport level without needing a real server.
        let key_pair = key_pair();
        let http = reqwest::Client::new();
        let err = present(&http, &key_pair, CREDENTIAL_JWS, "http://127.0.0.1:0/oid4vp/response")
            .await
            .expect_err("should fail when the response_uri is unreachable");

        assert!(matches!(err, Oid4VpError::Transport { .. }), "unexpected error variant: {err:?}");
    }
}
