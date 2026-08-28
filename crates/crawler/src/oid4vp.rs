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
//!
//! RED STATE (docs/oid4vp-holder-2026-08-28.md TDD pass): only the tests
//! below exist so far - `build_vp_token`, `build_presentation_submission`,
//! `present`, and `Oid4VpError` are not implemented yet. This is expected
//! not to compile.

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
