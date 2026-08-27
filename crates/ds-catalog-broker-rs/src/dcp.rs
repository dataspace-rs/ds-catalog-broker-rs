//! Minimal Decentralized Claims Protocol (DCP) *verification* support for
//! the DSP catalog endpoints - the "narrowed (b)" scope from
//! `compliance/benchmark-2026-08-27.md`'s follow-up work: validate an
//! incoming self-issued token/Verifiable Presentation from a caller who
//! already has real DID/Credential-Service infrastructure, without
//! implementing DCP's issuer/holder-wallet side (this project has no
//! credentials of its own to present - see
//! `compliance/dcp-test-env/README.md` for the real, running
//! `eclipse-edc/IdentityHub` + Issuer Service this was built and tested
//! against).
//!
//! The JWS/`did:web` primitives this module builds on live in the
//! `dcp-core` crate, shared with a future credential-*holder* role (a
//! crawler presenting its own credential to a remote participant) - see
//! that crate's doc comment. This module keeps only what's specific to
//! the *verifier* side: `DcpConfig`, the proof-of-original-possession
//! re-packaging step, and `verify_dcp_bearer_token`'s end-to-end flow.
//!
//! ## The flow this implements
//!
//! 1. A caller ("holder") presents `Authorization: Bearer <T1>` on a DSP
//!    request, where T1 is a self-issued JWT (signed with the holder's
//!    own `did:web` key) containing a nested `token` claim (T2 - a
//!    presentation-access-token, itself a JWT, scoped and audience-
//!    restricted to the holder's own DID).
//! 2. This connector resolves the holder's DID document, verifies T1's
//!    signature against it, and checks `aud` matches this connector's
//!    own DID (see `own_did_document`, hosted at `GET /dsp/did.json`).
//! 3. **Proof of original possession**: DCP requires the party that
//!    received T1 (this connector) to re-package the nested T2 into a
//!    *new* self-issued token (T3), signed with *this connector's own*
//!    key, before the holder's Presentation API will honor it - a bare
//!    forward of T2 is rejected (`compliance/dcp-test-env/README.md`
//!    documents the trail of 401s that surfaced this). This connector
//!    signs T3 itself, in-process - no separate STS service, since it
//!    has no need to issue tokens for any other purpose.
//! 4. T3 is POSTed to the holder's Presentation API (discovered from the
//!    holder's DID document's `CredentialService` entry), requesting
//!    `required_scope`. The response is a signed VerifiablePresentation
//!    (a JWS) wrapping one or more Verifiable Credentials (also JWS).
//! 5. The VP's signature is checked against the holder's DID (again),
//!    and each embedded VC's signature is checked against *its own*
//!    issuer's DID (resolved separately) plus expiry. The verified
//!    credential(s)' `catalogAccess` claim becomes this caller's
//!    dataset allow-list - see `visible_datasets` in `lib.rs` for the
//!    bearer-mode equivalent this mirrors.
//!
//! What this deliberately does not do: verify credential *status*
//! (revocation lists), enforce a trusted-issuer allowlist (any issuer
//! whose DID resolves and whose signature checks out is accepted - a
//! real deployment should add one), or support any VC format other than
//! the JWT-VC (`VC1_0_JWT`) shape this was built and tested against.

use std::collections::HashSet;
use std::ops::Deref;

use dcp_core::{
    DcpKeyPair, PRESENTATION_QUERY_CONTEXT, PresentationQueryMessage, PresentationResponseMessage,
    decode_jws_unverified, find_verifying_key, now_secs, resolve_did, service_endpoint_url, sign_jws,
    verify_jws_signature,
};
use serde_json::{Value, json};
use uuid::Uuid;

/// Config for `DspAuthMode::Dcp`. Wraps a role-agnostic `DcpKeyPair`
/// (this connector's own signing identity, shared shape with
/// `dcp-core`'s holder-side use) plus the two fields that are actually
/// verifier-specific. `Deref`s to the inner `DcpKeyPair` so existing call
/// sites (`config.own_did`, `config.signing_key()`) keep working
/// unchanged.
#[derive(Debug, Clone)]
pub struct DcpConfig {
    pub key_pair: DcpKeyPair,
    /// Whether to resolve `did:web` DIDs over plain HTTP instead of
    /// HTTPS. `did:web` resolution defaults to HTTPS per spec; this
    /// exists only for `compliance/dcp-test-env`'s local, unencrypted
    /// IdentityHub/Issuer Service instances (mirrors
    /// `EDC_IAM_DID_WEB_USE_HTTPS=false`, the same setting that
    /// environment's own EDC connectors need).
    pub insecure_http: bool,
    /// The DCP scope string requested from the holder's Presentation
    /// API, e.g. `org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read`.
    pub required_scope: String,
}

impl Deref for DcpConfig {
    type Target = DcpKeyPair;

    fn deref(&self) -> &DcpKeyPair {
        &self.key_pair
    }
}

impl DcpConfig {
    pub fn generate(own_did: String, insecure_http: bool, required_scope: String) -> Self {
        Self {
            key_pair: DcpKeyPair::generate(own_did),
            insecure_http,
            required_scope,
        }
    }

    /// This connector's own DID document, served at `GET /dsp/did.json`
    /// so holders' Presentation APIs (via `SelfIssuedTokenVerifier`) can
    /// resolve the key that signs the re-packaged token this connector
    /// sends them. A verifier has no Presentation API of its own to
    /// advertise, so it publishes an empty `service` array.
    pub fn own_did_document(&self) -> Value {
        self.key_pair.did_document(&[])
    }
}

/// The caller identity and dataset entitlements a successful DCP
/// verification establishes - the DCP-mode equivalent of the bearer-mode
/// `caller` token in `authorize`/`visible_datasets` (`lib.rs`).
#[derive(Debug)]
pub struct VerifiedCaller {
    pub holder_did: String,
    pub catalog_access: HashSet<String>,
}

/// Verifies an incoming DCP self-issued bearer token per the flow
/// documented on this module, returning the caller's DID and the set of
/// dataset ids their presented credential(s) grant access to.
pub async fn verify_dcp_bearer_token(token: &str, config: &DcpConfig, http: &reqwest::Client) -> Result<VerifiedCaller, String> {
    let (signing_input_t1, header_t1, payload_t1) = decode_jws_unverified(token)?;
    let _ = signing_input_t1;
    let holder_did = payload_t1.get("iss").and_then(Value::as_str).ok_or("token has no iss")?.to_string();
    let kid_t1 = header_t1.get("kid").and_then(Value::as_str).ok_or("token has no kid")?;

    let holder_doc = resolve_did(http, &holder_did, config.insecure_http).await?;
    let holder_key = find_verifying_key(&holder_doc, kid_t1)?;
    verify_jws_signature(token, &holder_key)?;

    let aud = payload_t1.get("aud").and_then(Value::as_str).unwrap_or("");
    if aud != config.own_did {
        return Err(format!("token audience '{aud}' does not match this connector's DID '{}'", config.own_did));
    }

    let exp = payload_t1.get("exp").and_then(Value::as_u64).unwrap_or(0);
    if exp <= now_secs() {
        return Err("token has expired".to_string());
    }

    let nested_token = payload_t1
        .get("token")
        .and_then(Value::as_str)
        .ok_or("token has no nested presentation-access-token claim")?;

    // Step 3: proof of original possession - re-package the nested
    // token into a new self-issued token, signed with this connector's
    // own key, addressed back to the holder.
    let now = now_secs();
    let repackaged_payload = json!({
        "iss": config.own_did,
        "sub": config.own_did,
        "aud": holder_did,
        "token": nested_token,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": Uuid::new_v4().to_string(),
    });
    let repackaged_token = sign_jws(&repackaged_payload, &config.signing_key(), &config.own_key_id);

    let credential_service = service_endpoint_url(&holder_doc, "CredentialService")?;
    let query_url = format!("{credential_service}/presentations/query");
    let query_body = PresentationQueryMessage {
        context: PRESENTATION_QUERY_CONTEXT,
        ld_type: "PresentationQueryMessage",
        scope: vec![config.required_scope.clone()],
    };
    let response = http
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

    // Step 5: verify the VP itself (signed by the holder).
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

        // Each credential may (in general) come from a different
        // issuer - resolve per credential rather than assuming they
        // share the holder's DID.
        let issuer_doc = resolve_did(http, &issuer_did, config.insecure_http).await?;
        let issuer_key = find_verifying_key(&issuer_doc, vc_kid)?;
        verify_jws_signature(vc_jws, &issuer_key)?;

        let vc_exp = vc_payload.get("exp").and_then(Value::as_u64).unwrap_or(0);
        if vc_exp <= now_secs() {
            // Expired credential: skip granting its access, but remember
            // this happened - an all-expired presentation must not read
            // as "authenticated, genuinely granted nothing" (see below).
            had_expired_credential = true;
            continue;
        }

        let vc_body = vc_payload.get("vc").cloned().unwrap_or(Value::Null);
        let types = vc_body.get("type").and_then(Value::as_array).cloned().unwrap_or_default();
        let has_expected_type = types.iter().any(|t| t.as_str() == Some(dcp_core::EXPECTED_CREDENTIAL_TYPE));
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
    // granted nothing" outcome (see `visible_datasets`'s doc comment in
    // lib.rs) - but if it's empty *because* every credential presented was
    // expired, that's an authentication failure, not a valid zero-access
    // caller, and must not be cached as if it were (a caller with a
    // temporarily expired credential would otherwise silently overwrite
    // their own previously-good cached catalog with an empty one).
    if catalog_access.is_empty() && had_expired_credential {
        return Err("all presented credentials are expired".to_string());
    }

    Ok(VerifiedCaller { holder_did, catalog_access })
}
