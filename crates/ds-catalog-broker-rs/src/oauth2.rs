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

use std::collections::HashMap;

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use thiserror::Error;

/// Opt-in configuration for the OAuth2 Bearer gate - see the module doc
/// and `docs/oauth2-bearer-gating-2026-08-28.md`'s config table for what
/// each field means and how `main.rs` populates it from env vars.
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    pub jwks_uri: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub required_scope: Option<String>,
}

/// Failure fetching or parsing the JWKS at [`OAuth2Config::jwks_uri`] -
/// returned by [`OAuth2Verifier::fetch`]. `main.rs` panics on any of
/// these at startup, the same failure posture as a bad
/// `CRAWLER_CONFIG_PATH` - see the design doc's config table.
#[derive(Debug, Error)]
pub enum JwksError {
    #[error("failed to fetch JWKS from {uri}: {source}")]
    Fetch {
        uri: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("JWKS response from {uri} was not a valid JWK Set: {source}")]
    Parse {
        uri: String,
        #[source]
        source: reqwest::Error,
    },
    #[error(
        "JWKS at {uri} contained no usable key: every entry was either missing a kid, a \
         symmetric (oct) key (never accepted here - see the module doc), or used an \
         algorithm/curve this verifier doesn't support (only RS256, ES256, ES384)"
    )]
    NoUsableKeys { uri: String },
}

/// Why a bearer token was rejected by [`OAuth2Verifier::verify`] -
/// distinguished so the router can answer `401` vs `403` (see
/// `docs/oauth2-bearer-gating-2026-08-28.md`'s "Response shape").
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The token header had no `kid`, or its `kid` doesn't match any key
    /// admitted into this verifier (including a `kid` that *is* present in
    /// the source JWKS but was skipped at construction - e.g. an `oct`
    /// key, see [`JwksError::NoUsableKeys`]'s doc comment).
    #[error("token has no kid, or its kid does not match any key in the configured JWKS")]
    UnknownKid,
    /// Signature, `exp`/`nbf`, or (when configured) `iss`/`aud` failed.
    /// Deliberately not split further - all of these are "this is not a
    /// token this resource server accepts" from the caller's point of
    /// view, and all map to the same `401`.
    #[error("token failed verification: {0}")]
    InvalidToken(String),
    /// The token verified, but its space-delimited `scope` claim doesn't
    /// contain [`OAuth2Config::required_scope`]. The caller authenticated
    /// fine; this is an authorization failure, hence kept distinguishable
    /// from [`VerifyError::InvalidToken`] so the router can answer `403`
    /// instead of `401`.
    #[error("token is missing required scope '{0}'")]
    InsufficientScope(String),
}

/// One JWKS entry this verifier is willing to use: the key material,
/// alongside the algorithm *this module itself* determined for it (from
/// the JWK's own `alg`, or inferred from `kty`/`crv`) - never the
/// algorithm a caller's own JWT header claims. See the module doc.
struct VerificationKey {
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

/// Verifies OAuth2 access tokens against a JWKS fetched once, eagerly, at
/// construction (see [`OAuth2Verifier::fetch`]). See the module doc for
/// the full design; **known limitation** (also flagged in the design
/// doc): no background refresh - a JWKS rotated after this verifier was
/// built requires a process restart to pick up.
pub struct OAuth2Verifier {
    config: OAuth2Config,
    keys: HashMap<String, VerificationKey>,
}

/// Hand-written (not derived): `jsonwebtoken::DecodingKey` doesn't
/// implement `Debug`, and this deliberately never prints key material
/// anyway - just the config and which `kid`s are loaded, enough for
/// `Result::expect_err`/panic messages in tests and logs.
impl std::fmt::Debug for OAuth2Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Verifier")
            .field("config", &self.config)
            .field("kids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl OAuth2Verifier {
    /// Fetch and parse the JWKS at `config.jwks_uri`, building a `kid ->`
    /// key map. Symmetric (`oct`) keys, keys with no `kid`, and keys whose
    /// algorithm can't be determined (see `determine_algorithm`) are
    /// individually skipped (logged at `warn`, not treated as a hard
    /// failure on their own - a JWKS that also carries key material this
    /// module doesn't accept should still work for its *usable* keys); the
    /// whole call
    /// fails only when fetching/parsing itself fails, or when *no* key
    /// survives that filtering (`JwksError::NoUsableKeys`).
    pub async fn fetch(client: &reqwest::Client, config: OAuth2Config) -> Result<Self, JwksError> {
        let uri = config.jwks_uri.clone();
        let response = client
            .get(&uri)
            .send()
            .await
            .map_err(|source| JwksError::Fetch {
                uri: uri.clone(),
                source,
            })?;
        let response = response
            .error_for_status()
            .map_err(|source| JwksError::Fetch {
                uri: uri.clone(),
                source,
            })?;
        let jwk_set: JwkSet = response.json().await.map_err(|source| JwksError::Parse {
            uri: uri.clone(),
            source,
        })?;

        let mut keys = HashMap::new();
        for jwk in &jwk_set.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                tracing::warn!("skipping a JWK in the configured JWKS that has no kid");
                continue;
            };
            if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
                tracing::warn!(kid = %kid, "skipping a symmetric (oct) key in the configured JWKS - never accepted by this OAuth2 resource server check");
                continue;
            }
            let Some(algorithm) = determine_algorithm(jwk) else {
                tracing::warn!(kid = %kid, "skipping a JWK with an unsupported or undeterminable algorithm (only RS256, ES256, ES384 are supported)");
                continue;
            };
            let decoding_key = match DecodingKey::from_jwk(jwk) {
                Ok(key) => key,
                Err(err) => {
                    tracing::warn!(kid = %kid, error = %err, "skipping a JWK that failed to convert to a decoding key");
                    continue;
                }
            };
            keys.insert(
                kid,
                VerificationKey {
                    decoding_key,
                    algorithm,
                },
            );
        }

        if keys.is_empty() {
            return Err(JwksError::NoUsableKeys { uri });
        }

        Ok(Self { config, keys })
    }

    /// Verify `token`: signature (against the key its header's `kid`
    /// selects, validated using *that key's own* algorithm - see the
    /// module doc's algorithm-confusion note, never the token header's own
    /// `alg`), `exp` always, `nbf` when present, `iss`/`aud` when
    /// configured, and (when configured) that the space-delimited `scope`
    /// claim contains [`OAuth2Config::required_scope`]. Returns the
    /// decoded claims on success.
    pub fn verify(&self, token: &str) -> Result<serde_json::Value, VerifyError> {
        let header =
            decode_header(token).map_err(|err| VerifyError::InvalidToken(err.to_string()))?;
        let kid = header.kid.ok_or(VerifyError::UnknownKid)?;
        let key = self.keys.get(&kid).ok_or(VerifyError::UnknownKid)?;

        let mut validation = Validation::new(key.algorithm);
        // `nbf` is only actually checked (per `jsonwebtoken`'s own rule)
        // when the claim is present at all - "exp always, nbf if present"
        // per the design doc - so this is safe to always turn on.
        validation.validate_nbf = true;
        if let Some(issuer) = &self.config.issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(audience) = &self.config.audience {
            validation.set_audience(&[audience]);
        } else {
            // `jsonwebtoken`'s `Validation` otherwise rejects *any* token
            // that merely carries an `aud` claim once `validate_aud`
            // defaults to `true` and no expected audience was set - not
            // what "OAUTH2_AUDIENCE unset -> unchecked" (design doc) means.
            validation.validate_aud = false;
        }

        let data = decode::<serde_json::Value>(token, &key.decoding_key, &validation)
            .map_err(|err| VerifyError::InvalidToken(err.to_string()))?;

        if let Some(required_scope) = &self.config.required_scope {
            let has_scope = data
                .claims
                .get("scope")
                .and_then(|v| v.as_str())
                .map(|scopes| scopes.split_whitespace().any(|s| s == required_scope))
                .unwrap_or(false);
            if !has_scope {
                return Err(VerifyError::InsufficientScope(required_scope.clone()));
            }
        }

        Ok(data.claims)
    }
}

/// Determines the algorithm to verify `jwk` with: its own `alg` field when
/// present (mapped to the three algorithms this verifier supports - any
/// other declared `alg` is treated as unsupported, not silently
/// re-inferred from `kty`/`crv` instead), else inferred from `kty`/`crv`
/// (RSA -> RS256; EC P-256 -> ES256; EC P-384 -> ES384). `None` for
/// anything else (RSA-family PSS variants, EC P-521, OKP/EdDSA, ...) -
/// the caller skips that key rather than erroring the whole fetch.
///
/// This is the algorithm-confusion guard the module doc describes: the
/// result is used as the *only* algorithm [`OAuth2Verifier::verify`]
/// accepts for this `kid`, regardless of what a presented token's own
/// header claims.
fn determine_algorithm(jwk: &Jwk) -> Option<Algorithm> {
    if let Some(key_algorithm) = jwk.common.key_algorithm {
        return match key_algorithm {
            KeyAlgorithm::RS256 => Some(Algorithm::RS256),
            KeyAlgorithm::ES256 => Some(Algorithm::ES256),
            KeyAlgorithm::ES384 => Some(Algorithm::ES384),
            _ => None,
        };
    }
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Some(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(params) => match params.curve {
            EllipticCurve::P256 => Some(Algorithm::ES256),
            EllipticCurve::P384 => Some(Algorithm::ES384),
            _ => None,
        },
        _ => None,
    }
}

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
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind 127.0.0.1:0");
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
    use super::test_support::spawn_jwks_server as spawn_jwks;
    use super::test_support::*;
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
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect("fetch JWKS");

        let stranger = generate_key("unregistered-kid");
        let token = sign_es256(&stranger, base_claims());
        let err = verifier
            .verify(&token)
            .expect_err("unregistered kid must be rejected");
        assert!(
            matches!(err, VerifyError::UnknownKid),
            "expected UnknownKid, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_a_token_with_an_invalid_signature() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect("fetch JWKS");

        // Signed by a *different* key, but claiming the registered kid in
        // its header - a forged token, not just an unknown-key one.
        let forger = generate_key("key-1");
        let token = sign_es256(&forger, base_claims());
        let err = verifier
            .verify(&token)
            .expect_err("forged signature must be rejected");
        assert!(
            matches!(err, VerifyError::InvalidToken(_)),
            "expected InvalidToken, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_an_expired_token() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect("fetch JWKS");

        let token = sign_es256(&key, expired_claims());
        let err = verifier
            .verify(&token)
            .expect_err("expired token must be rejected");
        assert!(
            matches!(err, VerifyError::InvalidToken(_)),
            "expected InvalidToken, got {err:?}"
        );
    }

    #[tokio::test]
    async fn construction_skips_a_symmetric_oct_key_but_keeps_a_valid_ec_key() {
        let ec_key = generate_key("ec-key");
        let jwks_uri =
            spawn_jwks(json!({"keys": [oct_jwk("oct-key"), ec_jwk(&ec_key, None)]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect("fetch JWKS - one usable key remains after skipping the oct key");

        let good_token = sign_es256(&ec_key, base_claims());
        assert!(
            verifier.verify(&good_token).is_ok(),
            "the real EC key must still work"
        );

        // The oct key's kid was never admitted into the verifier's key map.
        let oct_stand_in = generate_key("oct-key");
        let token_claiming_oct_kid = sign_es256(&oct_stand_in, base_claims());
        let err = verifier
            .verify(&token_claiming_oct_kid)
            .expect_err("the oct kid must not be usable");
        assert!(
            matches!(err, VerifyError::UnknownKid),
            "expected UnknownKid, got {err:?}"
        );
    }

    #[tokio::test]
    async fn construction_fails_when_the_jwks_has_no_usable_keys() {
        let jwks_uri = spawn_jwks(json!({"keys": [oct_jwk("only-key")]})).await;
        let err = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect_err("a JWKS with only a symmetric key has no usable keys");
        assert!(
            matches!(err, JwksError::NoUsableKeys { .. }),
            "expected NoUsableKeys, got {err:?}"
        );
    }

    #[tokio::test]
    async fn construction_skips_a_key_with_an_unsupported_curve() {
        let key = generate_key("bad-curve-key");
        let jwks_uri =
            spawn_jwks(json!({"keys": [unsupported_curve_jwk("bad-curve-key", &key)]})).await;
        let err = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect_err("a JWKS with only an unsupported-curve key has no usable keys");
        assert!(
            matches!(err, JwksError::NoUsableKeys { .. }),
            "expected NoUsableKeys, got {err:?}"
        );
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
        assert!(
            matches!(err, JwksError::Fetch { .. }),
            "expected Fetch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_a_token_with_the_wrong_issuer_when_issuer_is_configured() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.issuer = Some("https://expected-issuer.example".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg)
            .await
            .expect("fetch JWKS");

        let mut claims = base_claims();
        claims["iss"] = json!("https://someone-else.example");
        let token = sign_es256(&key, claims);
        let err = verifier
            .verify(&token)
            .expect_err("mismatched issuer must be rejected");
        assert!(
            matches!(err, VerifyError::InvalidToken(_)),
            "expected InvalidToken, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_accepts_a_token_with_the_matching_issuer() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.issuer = Some("https://expected-issuer.example".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg)
            .await
            .expect("fetch JWKS");

        let mut claims = base_claims();
        claims["iss"] = json!("https://expected-issuer.example");
        let token = sign_es256(&key, claims);
        assert!(
            verifier.verify(&token).is_ok(),
            "matching issuer must be accepted"
        );
    }

    #[tokio::test]
    async fn verify_rejects_a_token_with_the_wrong_audience_when_audience_is_configured() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.audience = Some("expected-audience".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg)
            .await
            .expect("fetch JWKS");

        let mut claims = base_claims();
        claims["aud"] = json!("someone-else");
        let token = sign_es256(&key, claims);
        let err = verifier
            .verify(&token)
            .expect_err("mismatched audience must be rejected");
        assert!(
            matches!(err, VerifyError::InvalidToken(_)),
            "expected InvalidToken, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_accepts_a_token_with_the_matching_audience() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.audience = Some("expected-audience".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg)
            .await
            .expect("fetch JWKS");

        let mut claims = base_claims();
        claims["aud"] = json!("expected-audience");
        let token = sign_es256(&key, claims);
        assert!(
            verifier.verify(&token).is_ok(),
            "matching audience must be accepted"
        );
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
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect("fetch JWKS");

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
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg)
            .await
            .expect("fetch JWKS");

        let mut claims = base_claims();
        claims["scope"] = json!("sparql:read other:scope");
        let token = sign_es256(&key, claims);
        let err = verifier
            .verify(&token)
            .expect_err("missing required scope must be rejected");
        assert!(
            matches!(err, VerifyError::InsufficientScope(ref s) if s == "catalog:read"),
            "expected InsufficientScope, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_accepts_a_token_with_the_required_scope_among_several() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.required_scope = Some("catalog:read".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg)
            .await
            .expect("fetch JWKS");

        let mut claims = base_claims();
        claims["scope"] = json!("sparql:read catalog:read other:scope");
        let token = sign_es256(&key, claims);
        assert!(
            verifier.verify(&token).is_ok(),
            "required scope present among several must be accepted"
        );
    }

    #[tokio::test]
    async fn verify_rejects_a_token_with_no_scope_claim_at_all_when_scope_is_required() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, None)]})).await;
        let mut cfg = config(jwks_uri);
        cfg.required_scope = Some("catalog:read".to_string());
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), cfg)
            .await
            .expect("fetch JWKS");

        let token = sign_es256(&key, base_claims());
        let err = verifier
            .verify(&token)
            .expect_err("no scope claim at all must be rejected when a scope is required");
        assert!(
            matches!(err, VerifyError::InsufficientScope(_)),
            "expected InsufficientScope, got {err:?}"
        );
    }

    /// An explicit `alg` field on the JWK (rather than inference from
    /// `kty`/`crv`) must be honored too - the other branch of algorithm
    /// determination.
    #[tokio::test]
    async fn jwks_key_with_an_explicit_alg_field_verifies_correctly() {
        let key = generate_key("key-1");
        let jwks_uri = spawn_jwks(json!({"keys": [ec_jwk(&key, Some("ES256"))]})).await;
        let verifier = OAuth2Verifier::fetch(&reqwest::Client::new(), config(jwks_uri))
            .await
            .expect("fetch JWKS");

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
            .expect(
                "an RSA JWK with no alg field must be inferred as RS256 and admitted, not skipped",
            );
    }
}
