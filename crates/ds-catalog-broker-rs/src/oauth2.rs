//! OAuth2 Bearer resource-server gating for `GET /catalog` and
//! `GET`/`POST /sparql` - see `docs/oauth2-bearer-gating-2026-08-28.md` for
//! the full design.
//!
//! This is a real OAuth2 resource-server check: a caller presents an
//! access token minted by some external OAuth2/OIDC authorization server,
//! and [`OAuth2Verifier`] verifies it against that authorization server's
//! published JWKS (fetched once, eagerly, at startup - see
//! [`OAuth2Verifier::fetch`]). It uses the `jsonwebtoken` crate rather than
//! hand-rolling JWT parsing the way `dcp-core` hand-rolls compact JWS for
//! its own, narrower use case (a single self-issued ES256 token type with
//! a known shape, entirely controlled by this project - see that crate's
//! module doc for why hand-rolling was the right call *there*). Here, the
//! token comes from an arbitrary external authorization server whose
//! signing algorithm and claim shape aren't controlled by this project,
//! which is exactly the case a maintained, spec-tested JWT library is for.
//! This module has no dependency on `dcp-core` and is not a revival of the
//! old, removed `DspAuthMode::Bearer`/`DspAuthMode::Dcp` - see the design
//! doc's "Why this exists" section.
//!
//! The one deliberate, security-relevant design point: the algorithm used
//! to verify a token is always taken from the *matched JWK itself* (its
//! own `alg`, or inferred from `kty`/`crv` when absent), **never** from the
//! caller's own JWT header - see [`OAuth2Verifier::verify`]'s doc comment.
//! That is what actually
//! prevents an algorithm-confusion downgrade, not the `kid` lookup by
//! itself.
//!
//! RED STATE (docs/oauth2-bearer-gating-2026-08-28.md TDD pass): only the
//! test fixtures and tests below exist so far - `OAuth2Config`,
//! `OAuth2Verifier`, `JwksError`, `VerifyError` are not implemented yet.
//! This is expected not to compile.

#[cfg(test)]
pub(crate) mod test_support {
    //! Test-only JWKS/JWT fixtures, independent of both `jsonwebtoken`'s
    //! own `EncodingKey` and of `dcp-core`'s `sign_jws` - a hand-rolled
    //! ES256 signer built directly from `p256`, so the production
    //! `OAuth2Verifier` this exercises is proven against a signer sharing
    //! no code with either. `pub(crate)` (not private to this module) so
    //! `lib.rs`'s own router-level integration tests can reuse it - see
    //! that file's `oauth2` test section.

    use axum::routing::get;
    use axum::{Json, Router};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    /// Binds a real `127.0.0.1` HTTP server (the mock-HTTP-server pattern
    /// this workspace already uses - see
    /// `crates/crawler/tests/multi_participant_crawl.rs`) serving `jwks`
    /// at `/jwks.json`, and returns that URL. Shared by this module's own
    /// unit tests and by `lib.rs`'s router-level integration tests, so
    /// both prove the real fetch path (not just verification of an
    /// already-parsed key) against the same, one implementation of "spin
    /// up a mock JWKS endpoint".
    pub async fn spawn_jwks_server(jwks: Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");
        let app = Router::new().route(
            "/jwks.json",
            get(move || {
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("axum::serve");
        });
        format!("http://{addr}/jwks.json")
    }

    pub struct TestKey {
        pub signing_key: SigningKey,
        pub verifying_key: VerifyingKey,
        pub kid: String,
    }

    pub fn generate_key(kid: &str) -> TestKey {
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        TestKey {
            signing_key,
            verifying_key,
            kid: kid.to_string(),
        }
    }

    fn b64(bytes: impl AsRef<[u8]>) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A P-256 JWK for `key`. `alg`, when given, sets the JWK's own `alg`
    /// field - proving the "alg present" branch of algorithm
    /// determination; `None` proves the "infer from kty/crv" branch
    /// instead. See the module doc.
    pub fn ec_jwk(key: &TestKey, alg: Option<&str>) -> Value {
        let point = key.verifying_key.to_encoded_point(false);
        let x = point.x().expect("uncompressed point has x");
        let y = point.y().expect("uncompressed point has y");
        let mut jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "kid": key.kid,
            "x": b64(x),
            "y": b64(y),
        });
        if let Some(alg) = alg {
            jwk["alg"] = json!(alg);
        }
        jwk
    }

    /// A symmetric (`oct`) JWK - must be skipped at [`super::OAuth2Verifier::fetch`]
    /// construction, never treated as usable key material. See the module
    /// doc and design doc's "Symmetric (`oct`) keys are rejected" note.
    pub fn oct_jwk(kid: &str) -> Value {
        json!({"kty": "oct", "kid": kid, "k": b64(b"not-a-real-hmac-secret")})
    }

    /// A JWK whose `kty`/`crv` this module cannot verify (P-521) - proves
    /// the "unsupported, skip" branch of algorithm determination, distinct
    /// from the explicit `oct` rejection above.
    pub fn unsupported_curve_jwk(kid: &str, key: &TestKey) -> Value {
        let point = key.verifying_key.to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-521",
            "kid": kid,
            "x": b64(point.x().expect("x")),
            "y": b64(point.y().expect("y")),
        })
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs()
    }

    /// A hand-rolled compact JWS (ES256): base64url(header).base64url(claims).base64url(signature),
    /// where `signature` is the raw fixed-size (r||s) ECDSA signature JOSE
    /// expects (not a DER encoding).
    pub fn sign_es256(key: &TestKey, claims: Value) -> String {
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": key.kid});
        let header_b64 = b64(header.to_string());
        let claims_b64 = b64(claims.to_string());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature: Signature = key.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = b64(signature.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    /// Claims for a token that is valid by default (future `exp`, no
    /// `iss`/`aud`/`scope`) - individual tests override specific fields.
    pub fn base_claims() -> Value {
        json!({
            "sub": "test-subject",
            "iat": now_secs(),
            "exp": now_secs() + 3600,
        })
    }

    pub fn expired_claims() -> Value {
        json!({
            "sub": "test-subject",
            "iat": now_secs().saturating_sub(7200),
            "exp": now_secs().saturating_sub(3600),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::test_support::spawn_jwks_server as spawn_jwks;
    use super::{JwksError, OAuth2Config, OAuth2Verifier, VerifyError};
    use base64::Engine;
    use serde_json::json;
    use tokio::net::TcpListener;

    fn config(jwks_uri: String) -> OAuth2Config {
        OAuth2Config {
            jwks_uri,
            issuer: None,
            audience: None,
            required_scope: None,
        }
    }

    #[tokio::test]
    async fn jwks_round_trip_verifies_a_token_signed_for_the_matching_kid() {
        let key = generate_key("key-1");
        // No `alg` field on the JWK: proves the "infer ES256 from
        // kty=EC/crv=P-256" branch.
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect("fetch JWKS");

        let token = sign_es256(&key, base_claims());
        let claims = verifier.verify(&token).expect("valid token verifies");
        assert_eq!(claims["sub"], json!("test-subject"));
    }

    #[tokio::test]
    async fn verify_rejects_an_unknown_kid() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri)).await.expect("fetch JWKS");

        let stranger = generate_key("unregistered-kid");
        let token = sign_es256(&stranger, base_claims());
        let err = verifier.verify(&token).expect_err("unregistered kid must be rejected");
        assert!(matches!(err, VerifyError::UnknownKid), "expected UnknownKid, got {err:?}");
    }

    #[tokio::test]
    async fn verify_rejects_a_token_with_an_invalid_signature() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri)).await.expect("fetch JWKS");

        // Signed by a *different* key, but claiming the registered kid in
        // its header - a forged token, not just an unknown-key one.
        let forger = generate_key("key-1");
        let token = sign_es256(&forger, base_claims());
        let err = verifier.verify(&token).expect_err("forged signature must be rejected");
        assert!(matches!(err, VerifyError::InvalidToken(_)), "expected InvalidToken, got {err:?}");
    }

    #[tokio::test]
    async fn verify_rejects_an_expired_token() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri)).await.expect("fetch JWKS");

        let token = sign_es256(&key, expired_claims());
        let err = verifier.verify(&token).expect_err("expired token must be rejected");
        assert!(matches!(err, VerifyError::InvalidToken(_)), "expected InvalidToken, got {err:?}");
    }

    #[tokio::test]
    async fn construction_skips_a_symmetric_oct_key_but_keeps_a_valid_ec_key() {
        let ec_key = generate_key("ec-key");
        let jwks_uri = spawn_jwks(json!({"keys": [oct_jwk("oct-key"), ec_jwk(&ec_key, None)]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect("fetch JWKS - one usable key remains after skipping the oct key");

        let good_token = sign_es256(&ec_key, base_claims());
        assert!(verifier.verify(&good_token).is_ok(), "the real EC key must still work");

        // The oct key's kid was never admitted into the verifier's key map.
        let oct_stand_in = generate_key("oct-key");
        let token_claiming_oct_kid = sign_es256(&oct_stand_in, base_claims());
        let err = verifier.verify(&token_claiming_oct_kid).expect_err("the oct kid must not be usable");
        assert!(matches!(err, VerifyError::UnknownKid), "expected UnknownKid, got {err:?}");
    }

    #[tokio::test]
    async fn construction_fails_when_the_jwks_has_no_usable_keys() {
        let jwks_uri = spawn_jwks(json!({"keys": [oct_jwk("only-key")]})).await;
        let err = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect_err("a JWKS with only a symmetric key has no usable keys");
        assert!(matches!(err, JwksError::NoUsableKeys { .. }), "expected NoUsableKeys, got {err:?}");
    }

    #[tokio::test]
    async fn construction_skips_a_key_with_an_unsupported_curve() {
        let key = generate_key("bad-curve-key");
        let jwks_uri = spawn_jwks(json!({"keys": [unsupported_curve_jwk("bad-curve-key", &key)]})).await;
        let err = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect_err("a JWKS with only an unsupported-curve key has no usable keys");
        assert!(matches!(err, JwksError::NoUsableKeys { .. }), "expected NoUsableKeys, got {err:?}");
    }

    #[tokio::test]
    async fn fetch_fails_clearly_when_the_jwks_endpoint_is_unreachable() {
        // A real, closed local port - nothing is listening here.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let unreachable_uri = format!("http://{addr}/jwks.json");

        let err = OAuth2Verifier::fetch(&reqwest::Client::new(), config(unreachable_uri))
            .await
            .expect_err("an unreachable JWKS endpoint must fail construction");
        assert!(matches!(err, JwksError::Fetch { .. }), "expected Fetch, got {err:?}");
    }

    #[tokio::test]
    async fn verify_rejects_a_token_with_the_wrong_issuer_when_issuer_is_configured() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.issuer = Some("https://expected-issuer.example".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg).await.expect("fetch JWKS");

        let mut claims = base_claims();
        claims["iss"] = json!("https://someone-else.example");
        let token = sign_es256(&key, claims);
        let err = verifier.verify(&token).expect_err("mismatched issuer must be rejected");
        assert!(matches!(err, VerifyError::InvalidToken(_)), "expected InvalidToken, got {err:?}");
    }

    #[tokio::test]
    async fn verify_accepts_a_token_with_the_matching_issuer() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.issuer = Some("https://expected-issuer.example".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg).await.expect("fetch JWKS");

        let mut claims = base_claims();
        claims["iss"] = json!("https://expected-issuer.example");
        let token = sign_es256(&key, claims);
        assert!(verifier.verify(&token).is_ok(), "matching issuer must be accepted");
    }

    #[tokio::test]
    async fn verify_rejects_a_token_with_the_wrong_audience_when_audience_is_configured() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.audience = Some("expected-audience".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg).await.expect("fetch JWKS");

        let mut claims = base_claims();
        claims["aud"] = json!("someone-else");
        let token = sign_es256(&key, claims);
        let err = verifier.verify(&token).expect_err("mismatched audience must be rejected");
        assert!(matches!(err, VerifyError::InvalidToken(_)), "expected InvalidToken, got {err:?}");
    }

    #[tokio::test]
    async fn verify_accepts_a_token_with_the_matching_audience() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.audience = Some("expected-audience".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg).await.expect("fetch JWKS");

        let mut claims = base_claims();
        claims["aud"] = json!("expected-audience");
        let token = sign_es256(&key, claims);
        assert!(verifier.verify(&token).is_ok(), "matching audience must be accepted");
    }

    /// Regression guard for a real `jsonwebtoken` footgun: `Validation`
    /// defaults to rejecting any token that carries an `aud` claim unless
    /// an expected audience was explicitly set, even when the caller never
    /// asked for audience checking at all. `OAUTH2_AUDIENCE` unset must
    /// mean "don't check `aud`", not "reject any token that happens to
    /// have one" - see the design doc's config table ("checked only if
    /// set").
    #[tokio::test]
    async fn verify_accepts_a_token_with_an_aud_claim_when_audience_is_not_configured() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri)).await.expect("fetch JWKS");

        let mut claims = base_claims();
        claims["aud"] = json!("some-audience-nobody-configured");
        let token = sign_es256(&key, claims);
        assert!(
            verifier.verify(&token).is_ok(),
            "an unconfigured audience must not reject a token that merely happens to carry an aud claim"
        );
    }

    #[tokio::test]
    async fn verify_rejects_a_token_missing_the_required_scope() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.required_scope = Some("catalog:read".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg).await.expect("fetch JWKS");

        let mut claims = base_claims();
        claims["scope"] = json!("sparql:read other:scope");
        let token = sign_es256(&key, claims);
        let err = verifier.verify(&token).expect_err("missing required scope must be rejected");
        assert!(matches!(err, VerifyError::InsufficientScope(ref s) if s == "catalog:read"), "expected InsufficientScope, got {err:?}");
    }

    #[tokio::test]
    async fn verify_accepts_a_token_with_the_required_scope_among_several() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.required_scope = Some("catalog:read".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg).await.expect("fetch JWKS");

        let mut claims = base_claims();
        claims["scope"] = json!("sparql:read catalog:read other:scope");
        let token = sign_es256(&key, claims);
        assert!(verifier.verify(&token).is_ok(), "required scope present among several must be accepted");
    }

    #[tokio::test]
    async fn verify_rejects_a_token_with_no_scope_claim_at_all_when_scope_is_required() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.required_scope = Some("catalog:read".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg).await.expect("fetch JWKS");

        let token = sign_es256(&key, base_claims());
        let err = verifier.verify(&token).expect_err("no scope claim at all must be rejected when a scope is required");
        assert!(matches!(err, VerifyError::InsufficientScope(_)), "expected InsufficientScope, got {err:?}");
    }

    /// An explicit `alg` field on the JWK (rather than inference from
    /// `kty`/`crv`) must be honored too - the other branch of algorithm
    /// determination.
    #[tokio::test]
    async fn jwks_key_with_an_explicit_alg_field_verifies_correctly() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, Some("ES256"))]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri)).await.expect("fetch JWKS");

        let token = sign_es256(&key, base_claims());
        assert!(verifier.verify(&token).is_ok());
    }

    #[tokio::test]
    async fn construction_infers_rs256_for_an_rsa_key_with_no_alg_field() {
        // A structurally-fake-but-base64-valid RSA JWK: `DecodingKey::from_jwk`
        // only base64-decodes n/e at construction time (no key-validity
        // check happens until an actual RS256 signature is verified
        // against it), so this is enough to prove the RSA -> RS256
        // inference rule without needing a real RSA keypair.
        let rsa_jwk = json!({
            "kty": "RSA",
            "kid": "rsa-key",
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"fake-modulus-bytes"),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"fake-exponent"),
        });
        let jwks_uri = spawn_jwks(json!({"keys": [rsa_jwk]})).await;
        OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect("an RSA JWK with no alg field must be inferred as RS256 and admitted, not skipped");
    }
}
