//! Role-agnostic Decentralized Claims Protocol (DCP) primitives: compact
//! JWS (ES256) signing/verification, `did:web` resolution, and the small
//! set of DCP wire-message shapes (`PresentationQueryMessage` /
//! `PresentationResponseMessage`) needed to talk to a Presentation API.
//!
//! This crate hand-rolls JWS and does its own `did:web` resolution over
//! plain HTTP requests, rather than pulling in a JSON-LD or full
//! JWT-framework crate - see `ds-catalog-broker-rs`'s `dcp.rs` module doc comment for
//! the rationale (unchanged by this extraction).
//!
//! Everything here is deliberately **role-agnostic**: the same "sign this
//! JSON with my key" / "verify this compact JWS against a resolved JWK" /
//! "resolve a did:web" operations are needed both by a *verifier*
//! (relying party checking an incoming self-issued token, see
//! `ds_catalog_broker_rs::dcp`) and by a *holder* (a party presenting its own
//! credential to someone else's DSP endpoint - not yet implemented
//! anywhere in this workspace). Nothing in this crate assumes which side
//! of that exchange the caller is playing.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// `@context` for a `PresentationQueryMessage` sent to a Presentation API.
pub const PRESENTATION_QUERY_CONTEXT: &str = "https://w3id.org/dspace-dcp/v1.0/dcp.jsonld";
/// The credential type this workspace's federated-catalog access
/// credential is expected to carry.
pub const EXPECTED_CREDENTIAL_TYPE: &str = "FederatedCatalogAccessCredential";

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

pub fn b64_decode(segment: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("invalid base64url: {e}"))
}

pub fn b64_encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Splits a compact JWS into (signing_input, header, payload) without
/// verifying anything - used to peek at `iss`/`kid` before the caller
/// knows which key to verify against.
pub fn decode_jws_unverified(token: &str) -> Result<(String, Value, Value), String> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or("missing JWS header")?;
    let payload_b64 = parts.next().ok_or("missing JWS payload")?;
    let _sig_b64 = parts.next().ok_or("missing JWS signature")?;
    if parts.next().is_some() {
        return Err("JWS has more than 3 segments".to_string());
    }
    let signing_input = format!("{header_b64}.{payload_b64}");
    let header: Value =
        serde_json::from_slice(&b64_decode(header_b64)?).map_err(|e| e.to_string())?;
    let payload: Value =
        serde_json::from_slice(&b64_decode(payload_b64)?).map_err(|e| e.to_string())?;
    Ok((signing_input, header, payload))
}

pub fn verify_jws_signature(token: &str, verifying_key: &VerifyingKey) -> Result<(), String> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or("missing JWS header")?;
    let payload_b64 = parts.next().ok_or("missing JWS payload")?;
    let sig_b64 = parts.next().ok_or("missing JWS signature")?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = b64_decode(sig_b64)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| format!("malformed signature: {e}"))?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| format!("signature verification failed: {e}"))
}

pub fn sign_jws(payload: &Value, signing_key: &SigningKey, kid: &str) -> String {
    let header = json!({"kid": kid, "alg": "ES256"});
    let header_b64 = b64_encode(header.to_string());
    let payload_b64 = b64_encode(payload.to_string());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = b64_encode(signature.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

/// did:web resolution per the (simplified) spec: `did:web:<host>[:<path
/// segments>]` -> `https://<host>/<path segments joined by "/">/did.json`,
/// or `https://<host>/.well-known/did.json` with no path segments.
pub fn did_web_to_url(did: &str, insecure_http: bool) -> Result<String, String> {
    let rest = did.strip_prefix("did:web:").ok_or("not a did:web DID")?;
    let mut segments = rest.split(':');
    let host = segments.next().ok_or("did:web has no host segment")?;
    let host = urlencoding_decode(host);
    let path_segments: Vec<String> = segments.map(urlencoding_decode).collect();
    let scheme = if insecure_http { "http" } else { "https" };
    if path_segments.is_empty() {
        Ok(format!("{scheme}://{host}/.well-known/did.json"))
    } else {
        Ok(format!(
            "{scheme}://{host}/{}/did.json",
            path_segments.join("/")
        ))
    }
}

pub fn urlencoding_decode(segment: &str) -> String {
    // did:web only ever percent-encodes ":" (as "%3A") in practice (to
    // embed a port number in the host segment) - a full percent-decoder
    // would be more correct but is unneeded machinery for this project's
    // one actual use case.
    segment.replace("%3A", ":").replace("%3a", ":")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub service: Vec<DidService>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    pub public_key_jwk: Option<Jwk>,
}

#[derive(Debug, Deserialize)]
pub struct Jwk {
    pub x: String,
    pub y: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidService {
    #[serde(rename = "type")]
    pub ty: String,
    pub service_endpoint: String,
}

pub async fn resolve_did(
    client: &reqwest::Client,
    did: &str,
    insecure_http: bool,
) -> Result<DidDocument, String> {
    let url = did_web_to_url(did, insecure_http)?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("failed to resolve DID {did} at {url}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "DID resolution for {did} returned HTTP {}",
            response.status()
        ));
    }
    response
        .json::<DidDocument>()
        .await
        .map_err(|e| format!("DID document for {did} was not valid: {e}"))
}

pub fn find_verifying_key(doc: &DidDocument, kid: &str) -> Result<VerifyingKey, String> {
    let method = doc
        .verification_method
        .iter()
        .find(|m| m.id == kid)
        .ok_or_else(|| format!("no verification method '{kid}' in DID document"))?;
    let jwk = method
        .public_key_jwk
        .as_ref()
        .ok_or_else(|| format!("verification method '{kid}' has no publicKeyJwk"))?;
    jwk_to_verifying_key(jwk)
}

pub fn jwk_to_verifying_key(jwk: &Jwk) -> Result<VerifyingKey, String> {
    let x = b64_decode(&jwk.x)?;
    let y = b64_decode(&jwk.y)?;
    if x.len() != 32 || y.len() != 32 {
        return Err("EC JWK x/y must be 32 bytes for P-256".to_string());
    }
    // p256 0.13's own generic-array 0.14 re-export deprecates `from_slice`/
    // `as_slice` in favor of a generic-array 1.x API p256 0.13 doesn't
    // itself use yet - tracked as a pending upstream dependency bump, not
    // fixable from this crate alone without pulling p256 forward.
    #[allow(deprecated)]
    let point = p256::EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(&x),
        p256::FieldBytes::from_slice(&y),
        false,
    );
    let public_key = p256::PublicKey::from_encoded_point(&point);
    let public_key =
        Option::<p256::PublicKey>::from(public_key).ok_or("invalid EC point in JWK")?;
    Ok(VerifyingKey::from(public_key))
}

/// Looks up a DID document's `service` array by `type`, e.g.
/// `"CredentialService"` - used both by a verifier (finding the holder's
/// Presentation API) and by a holder advertising its own such entry in
/// `DcpKeyPair::did_document`'s `services` argument.
pub fn service_endpoint_url(doc: &DidDocument, service_type: &str) -> Result<String, String> {
    doc.service
        .iter()
        .find(|s| s.ty == service_type)
        .map(|s| s.service_endpoint.clone())
        .ok_or_else(|| format!("DID document has no {service_type} entry"))
}

#[derive(Debug, Serialize)]
pub struct PresentationQueryMessage {
    #[serde(rename = "@context")]
    pub context: &'static str,
    #[serde(rename = "@type")]
    pub ld_type: &'static str,
    pub scope: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresentationResponseMessage {
    pub presentation: Vec<String>,
}

/// `@context` for the `VerifiablePresentation` a holder wraps its
/// credential(s) in when answering a `PresentationQueryMessage` - see
/// [`HolderIdentity::answer_presentation_query`].
pub const VERIFIABLE_PRESENTATION_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

/// A P-256 key pair plus its `did:web` identity - the reusable half of
/// what either a verifier or a holder needs: something to sign with, and
/// a DID document to publish so others can resolve the matching public
/// key.
///
/// Kept as plain, `Debug`/`Clone`-able data (the signing key as a raw
/// scalar, not a `p256` key object) so it composes trivially into a
/// larger config struct; `signing_key()`/the stored `public_key_xy`
/// reconstruct the actual key types on demand, which is cheap.
#[derive(Debug, Clone)]
pub struct DcpKeyPair {
    /// This party's own `did:web` identifier, e.g.
    /// `did:web:localhost%3A18080:dsp`.
    pub own_did: String,
    /// Full `<own_did>#<fragment>` form used as the JWS `kid` header on
    /// tokens this party signs, and as the matching
    /// `verificationMethod.id` in its own hosted DID document.
    pub own_key_id: String,
    pub signing_key_bytes: [u8; 32],
    /// Uncompressed public key point, as (x, y) big-endian byte arrays -
    /// kept alongside the private scalar so `did_document()` doesn't need
    /// to re-derive it on every call.
    pub public_key_xy: ([u8; 32], [u8; 32]),
}

impl DcpKeyPair {
    pub fn generate(own_did: String) -> Self {
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let point = verifying_key.to_encoded_point(false);
        // See jwk_to_verifying_key's own #[allow(deprecated)] comment: same
        // pending generic-array 1.x upgrade, not fixable here alone.
        #[allow(deprecated)]
        let x: [u8; 32] = point
            .x()
            .expect("uncompressed point has x")
            .as_slice()
            .try_into()
            .expect("32 bytes");
        #[allow(deprecated)]
        let y: [u8; 32] = point
            .y()
            .expect("uncompressed point has y")
            .as_slice()
            .try_into()
            .expect("32 bytes");
        Self {
            own_key_id: format!("{own_did}#dsp-key"),
            own_did,
            signing_key_bytes: signing_key.to_bytes().into(),
            public_key_xy: (x, y),
        }
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes((&self.signing_key_bytes).into())
            .expect("stored key bytes are always valid")
    }

    /// This party's own DID document. `services` lets a holder advertise
    /// e.g. a `CredentialService` entry pointing at its own
    /// presentation-query endpoint; a verifier with no such endpoint to
    /// advertise passes an empty slice.
    pub fn did_document(&self, services: &[(String, String)]) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": self.own_did,
            "verificationMethod": [{
                "id": self.own_key_id,
                "type": "JsonWebKey2020",
                "controller": self.own_did,
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": b64_encode(self.public_key_xy.0),
                    "y": b64_encode(self.public_key_xy.1),
                }
            }],
            "service": services.iter().map(|(ty, endpoint)| json!({
                "type": ty,
                "serviceEndpoint": endpoint,
            })).collect::<Vec<_>>(),
        })
    }
}

/// A DCP **holder** identity: a party that presents a credential of its
/// own to remote relying parties (here, participants the crawler polls
/// with `requires_dcp = true`) and answers their Presentation API
/// callback in turn.
///
/// ## Why the signing key is generated fresh every process start
///
/// `key_pair` is produced by [`DcpKeyPair::generate`] - a fresh random
/// P-256 key every time a `HolderIdentity` is constructed - and is never
/// persisted to or read from config. Only `own_did_host` and
/// `credential_jws` are config-driven (see `crawler::config::HolderConfig`).
///
/// This is safe, not an oversight to "fix" later: a `did:web` identity is
/// entirely self-hosted (the DID document is served *by this same
/// process*, at `GET /dsp/holder/did.json`), so whichever key happens to
/// be running when a relying party resolves the DID is, by construction,
/// the key that document advertises. There is no external registry
/// (unlike `did:key` or a ledger-based method) that could ever hold a
/// stale public key, and no other party ever needs to have pre-agreed on
/// this key ahead of time. Persisting the private key would only add a
/// secret-at-rest to guard for no corresponding correctness benefit;
/// regenerating it is strictly simpler and just as correct. What *is*
/// pre-agreed (and therefore *does* need to persist in config, not be
/// regenerated) is `credential_jws` - a credential some external issuer
/// signed for this holder's `own_did` ahead of time, which is exactly why
/// it lives in `HolderConfig` while the key pair does not.
#[derive(Debug, Clone)]
pub struct HolderIdentity {
    pub key_pair: DcpKeyPair,
    /// The `host[:port]` this holder's own `did:web` document (and its
    /// `CredentialService` endpoint) is served from - kept separately
    /// from `key_pair.own_did` since it's also needed, un-encoded, to
    /// build plain HTTP(S) URLs.
    pub own_did_host: String,
    /// Resolve `did:web` DIDs (of relying parties calling back into this
    /// holder, and vice versa) over plain HTTP instead of HTTPS - for
    /// local/test environments. Also picks the scheme this holder's own
    /// `CredentialService` endpoint is advertised under.
    pub insecure_http: bool,
    /// The pre-issued Verifiable Credential (JWS compact string) this
    /// holder presents as itself. See this type's doc comment for why
    /// this - unlike the signing key - is genuinely config-driven state.
    pub credential_jws: String,
    /// The DCP scope this holder is expected to be queried for. Not
    /// currently used to filter `answer_presentation_query`'s response
    /// (this holder has exactly one credential to present regardless of
    /// requested scope), but kept alongside the credential since a real
    /// multi-credential holder would need it to select which
    /// credential(s) satisfy a given request.
    pub required_scope: String,
}

impl HolderIdentity {
    /// Builds a fresh holder identity: `own_did` is derived as
    /// `did:web:<own_did_host, ':' percent-encoded>:dsp:holder` - two
    /// colon-separated segments, matching `did_web_to_url`'s
    /// segments-joined-by-"/" resolution to `.../dsp/holder/did.json`,
    /// the actual route `ds_catalog_broker_rs::build_router` registers - and a new
    /// signing key is generated (see this type's doc comment for why that
    /// key is never persisted).
    pub fn new(
        own_did_host: String,
        insecure_http: bool,
        credential_jws: String,
        required_scope: String,
    ) -> Self {
        let own_did = format!("did:web:{}:dsp:holder", own_did_host.replace(':', "%3A"));
        Self {
            key_pair: DcpKeyPair::generate(own_did),
            own_did_host,
            insecure_http,
            credential_jws,
            required_scope,
        }
    }

    /// This holder's own `did:web` document, served at `GET
    /// /dsp/holder/did.json`. Unlike a bare verifier (`DcpConfig::own_did_document`,
    /// which advertises no services), this includes one `CredentialService`
    /// entry so a relying party this holder queried can discover where to
    /// query it back.
    ///
    /// The published `serviceEndpoint` is a *base* URL
    /// (`.../dsp/holder`), not the complete Presentation API endpoint -
    /// `ds_catalog_broker_rs::dcp::verify_dcp_bearer_token` (the verifier side, already
    /// validated against a real running `eclipse-edc/IdentityHub` before
    /// this holder role existed - see `compliance/benchmark-dcp-2026-08-27.md`)
    /// appends `/presentations/query` itself. Publishing the complete URL
    /// here would get that suffix appended a second time and 404. This
    /// holder conforms to the verifier's pre-existing, already-proven
    /// convention rather than the other way around.
    pub fn own_did_document(&self) -> Value {
        let scheme = if self.insecure_http { "http" } else { "https" };
        let endpoint = format!("{scheme}://{}/dsp/holder", self.own_did_host);
        self.key_pair
            .did_document(&[("CredentialService".to_string(), endpoint)])
    }

    /// Builds T1, the self-issued token this holder presents as
    /// `Authorization: Bearer <T1>` when calling a `requires_dcp = true`
    /// participant's DSP catalog endpoint, addressed to
    /// `target_provider_did` (that participant's own DID, used as `aud`).
    ///
    /// Shaped to exactly what `ds_catalog_broker_rs::dcp::verify_dcp_bearer_token`
    /// expects on the receiving end: `iss`/`sub` = this holder's own DID,
    /// `aud` = `target_provider_did`, and a nested `token` claim (T2 - a
    /// presentation-access-token, itself a JWS signed with this same key,
    /// scoped/audience-restricted to this holder's own DID) that function
    /// forwards opaquely as-is.
    pub fn mint_self_issued_token(&self, target_provider_did: &str) -> String {
        let signing_key = self.key_pair.signing_key();
        let now = now_secs();

        // T2: a presentation-access-token scoped to this holder's own
        // DID. Nothing on the receiving end verifies T2's signature
        // directly (it's forwarded opaquely, see the doc comment above),
        // but it's still a real JWS signed with this holder's own key
        // rather than a bare unsigned blob, matching the shape a real
        // Secure Token Service would issue.
        let access_token_payload = json!({
            "iss": self.key_pair.own_did,
            "sub": self.key_pair.own_did,
            "aud": self.key_pair.own_did,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        let access_token = sign_jws(
            &access_token_payload,
            &signing_key,
            &self.key_pair.own_key_id,
        );

        // T1.
        let t1_payload = json!({
            "iss": self.key_pair.own_did,
            "sub": self.key_pair.own_did,
            "aud": target_provider_did,
            "token": access_token,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        sign_jws(&t1_payload, &signing_key, &self.key_pair.own_key_id)
    }

    /// The receiving side of a Presentation API callback: when a relying
    /// party this holder previously queried (via `mint_self_issued_token`)
    /// calls back into `POST /dsp/holder/presentations/query`, it sends
    /// its own re-packaged token (T3 in `verify_dcp_bearer_token`'s
    /// numbering) - the mirror of that function's own step 3
    /// (proof-of-original-possession repackaging), just consumed from the
    /// other side: verify the incoming token's signature against the
    /// caller's resolved `did:web` (its `iss` claim), check it's actually
    /// addressed to this holder (`aud` == this holder's own DID) and not
    /// expired, then build and sign a `VerifiablePresentation` JWS
    /// wrapping this holder's stored `credential_jws`.
    ///
    /// The returned `PresentationResponseMessage` is genuinely symmetric
    /// with how `verify_dcp_bearer_token` consumes it (its steps 4-5): the
    /// VP is signed with this holder's `own_key_id`, resolvable via this
    /// holder's own DID document (the same one `own_did_document` serves)
    /// - exactly the key `verify_dcp_bearer_token` looks up before
    ///   verifying the VP's signature.
    pub async fn answer_presentation_query(
        &self,
        incoming_bearer_token: &str,
        http: &reqwest::Client,
    ) -> Result<PresentationResponseMessage, String> {
        let (_, header, payload) = decode_jws_unverified(incoming_bearer_token)?;
        let caller_did = payload
            .get("iss")
            .and_then(Value::as_str)
            .ok_or("token has no iss")?
            .to_string();
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or("token has no kid")?;

        let caller_doc = resolve_did(http, &caller_did, self.insecure_http).await?;
        let caller_key = find_verifying_key(&caller_doc, kid)?;
        verify_jws_signature(incoming_bearer_token, &caller_key)?;

        let aud = payload.get("aud").and_then(Value::as_str).unwrap_or("");
        if aud != self.key_pair.own_did {
            return Err(format!(
                "token audience '{aud}' does not match this holder's DID '{}'",
                self.key_pair.own_did
            ));
        }

        let exp = payload.get("exp").and_then(Value::as_u64).unwrap_or(0);
        if exp <= now_secs() {
            return Err("token has expired".to_string());
        }

        let now = now_secs();
        let vp_payload = json!({
            "iss": self.key_pair.own_did,
            "sub": self.key_pair.own_did,
            "vp": {
                "@context": [VERIFIABLE_PRESENTATION_CONTEXT],
                "type": ["VerifiablePresentation"],
                "verifiableCredential": [self.credential_jws.clone()],
            },
            "iat": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        let vp_jws = sign_jws(
            &vp_payload,
            &self.key_pair.signing_key(),
            &self.key_pair.own_key_id,
        );

        Ok(PresentationResponseMessage {
            presentation: vec![vp_jws],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_self_issued_token_is_shaped_for_verify_dcp_bearer_token() {
        let holder = HolderIdentity::new(
            "localhost:19100".to_string(),
            true,
            "fake.credential.jws".to_string(),
            "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read".to_string(),
        );
        let target_provider_did = "did:web:localhost%3A19002:dsp";
        let token = holder.mint_self_issued_token(target_provider_did);

        let (_, header, payload) = decode_jws_unverified(&token).expect("valid JWS");
        assert_eq!(payload["iss"], json!(holder.key_pair.own_did));
        assert_eq!(payload["sub"], json!(holder.key_pair.own_did));
        assert_eq!(payload["aud"], json!(target_provider_did));
        assert!(
            payload["token"].is_string(),
            "T1 must carry a nested `token` claim"
        );
        assert!(payload["exp"].as_u64().unwrap() > now_secs());

        let kid = header["kid"].as_str().expect("kid header");
        assert_eq!(kid, holder.key_pair.own_key_id);

        // Signature verifies against this holder's own public key -
        // exactly what verify_dcp_bearer_token does after resolving the
        // holder's did:web document.
        let verifying_key = p256::ecdsa::VerifyingKey::from(&holder.key_pair.signing_key());
        verify_jws_signature(&token, &verifying_key).expect("T1 signature must verify");

        // The nested token (T2) is itself a well-formed, self-signed JWS
        // scoped to the holder's own DID.
        let nested = payload["token"].as_str().unwrap();
        let (_, _nested_header, nested_payload) =
            decode_jws_unverified(nested).expect("valid nested JWS");
        assert_eq!(nested_payload["aud"], json!(holder.key_pair.own_did));
        verify_jws_signature(nested, &verifying_key).expect("T2 signature must verify");
    }

    #[test]
    fn own_did_document_advertises_a_credential_service() {
        let holder = HolderIdentity::new(
            "localhost:19100".to_string(),
            true,
            "fake.jws".to_string(),
            "scope".to_string(),
        );
        let doc = holder.own_did_document();
        let services = doc["service"].as_array().expect("service array");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["type"], json!("CredentialService"));
        assert_eq!(
            services[0]["serviceEndpoint"],
            json!("http://localhost:19100/dsp/holder"),
            "the published endpoint is the base URL - verify_dcp_bearer_token appends /presentations/query itself"
        );
    }
}
