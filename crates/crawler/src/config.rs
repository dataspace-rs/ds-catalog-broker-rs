//! Local-config participant registry for the scheduled crawler.
//!
//! This stands in for a real dataspace participant directory (a
//! catalog-of-catalogs, or a registry service queried at runtime): for
//! now, "which DSP catalog endpoints does this connector poll" is a
//! hand-maintained TOML file. See the `dataspace` study repo's
//! `docs/adr/` for whether/when this gets replaced by something dynamic -
//! that is a governance-adjacent decision (who gets to add a participant)
//! out of scope for this crate.
//!
//! Example file:
//!
//! ```toml
//! interval_secs = 300
//!
//! [[participants]]
//! id = "participant-a"
//! name = "Participant A"
//! catalog_request_url = "http://127.0.0.1:19001/dsp/catalog/request"
//! requires_dcp = false
//!
//! [[participants]]
//! id = "gated-participant"
//! name = "DCP-gated participant"
//! catalog_request_url = "http://127.0.0.1:19002/dsp/catalog/request"
//! requires_dcp = true
//! provider_did = "did:web:localhost%3A19002:dsp"
//!
//! [holder]
//! own_did_host = "localhost:19100"
//! insecure_http = true
//! credential_jws = "..."
//! required_scope = "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read"
//! ```

use serde::Deserialize;

/// The parsed, *validated* contents of a crawler config file. Construct
/// via [`ParticipantsConfig::load`] or [`ParticipantsConfig::parse`] -
/// both enforce the `requires_dcp` invariants documented on
/// [`ParticipantEntry`], so a value of this type is always internally
/// consistent by the time crawl code ever sees it.
#[derive(Debug, Clone, Deserialize)]
pub struct ParticipantsConfig {
    /// How often to run a full crawl cycle over every configured
    /// participant.
    pub interval_secs: u64,
    #[serde(default)]
    pub participants: Vec<ParticipantEntry>,
    /// This crawler's own DCP holder identity. Required exactly when at
    /// least one participant has `requires_dcp = true` - see
    /// [`ParticipantsConfig::validate`].
    #[serde(default)]
    pub holder: Option<HolderConfig>,
}

/// One participant this crawler polls.
#[derive(Debug, Clone, Deserialize)]
pub struct ParticipantEntry {
    pub id: String,
    pub name: String,
    pub catalog_request_url: String,
    /// Whether this participant's catalog endpoint requires a DCP
    /// self-issued token (`Authorization: Bearer <token>`) rather than an
    /// unauthenticated request. When `true`, `provider_did` is required
    /// (this participant's own DID, used as the token's `aud`) and the
    /// config's top-level `[holder]` section must be present.
    #[serde(default)]
    pub requires_dcp: bool,
    /// Required when `requires_dcp = true`: this participant's own DID -
    /// the audience of the self-issued token the crawler sends it.
    #[serde(default)]
    pub provider_did: Option<String>,
}

/// This crawler's own DCP holder identity configuration. Optional at the
/// file level - omit entirely if no participant in the file
/// `requires_dcp`.
#[derive(Debug, Clone, Deserialize)]
pub struct HolderConfig {
    /// This crawler's own `did:web` host\[:port\] -
    /// `did:web:<own_did_host>:dsp:holder` is derived from it (see
    /// `dcp_core::HolderIdentity::new`).
    pub own_did_host: String,
    /// Resolve `did:web` DIDs over plain `http://` instead of `https://` -
    /// for local/test environments.
    #[serde(default)]
    pub insecure_http: bool,
    /// The pre-issued Verifiable Credential (JWS compact string) this
    /// connector presents as itself.
    ///
    /// Yes, this genuinely lives in plain config, unencrypted. That's a
    /// deliberate tradeoff for this project's current scope, not an
    /// oversight: a VC is a *bearer credential* - whoever holds the JWS
    /// can present it - so in a real deployment this belongs in a secret
    /// store (or a proper wallet/holder agent) with access-controlled
    /// retrieval, not a checked-in or plaintext-on-disk TOML file. This
    /// project has no secret-management story yet (see the `dataspace`
    /// study repo's `authority/` placeholder for the same
    /// not-yet-solved-here class of problem), so for now the honest
    /// choice is to store it in the open and say so here, rather than
    /// give it a false sense of protection.
    pub credential_jws: String,
    /// The DCP scope this holder's credential is expected to satisfy.
    pub required_scope: String,
}

/// A crawler config file that failed to load or violated one of the
/// `requires_dcp` invariants. Returned by [`ParticipantsConfig::load`] /
/// [`ParticipantsConfig::parse`] rather than panicking, so a bad config
/// file fails fast and legibly at startup instead of surfacing deep
/// inside a crawl loop.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read crawler config file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse crawler config file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("participant '{id}' has requires_dcp = true but no provider_did is set")]
    MissingProviderDid { id: String },
    #[error(
        "participant '{id}' has requires_dcp = true but this config file has no [holder] section"
    )]
    MissingHolderSection { id: String },
}

impl ParticipantsConfig {
    /// Load and parse a crawler config file from `path`, then validate it.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let path_display = path_ref.display().to_string();
        let raw = std::fs::read_to_string(path_ref).map_err(|source| ConfigError::Io {
            path: path_display.clone(),
            source,
        })?;
        Self::parse(&raw, &path_display)
    }

    /// Parse `raw` TOML text (with `path_for_errors` used only to label
    /// any error), then validate it. Exposed separately from [`Self::load`]
    /// so tests can exercise parsing/validation without touching the
    /// filesystem.
    pub fn parse(raw: &str, path_for_errors: &str) -> Result<Self, ConfigError> {
        let config: ParticipantsConfig =
            toml::from_str(raw).map_err(|source| ConfigError::Parse {
                path: path_for_errors.to_string(),
                source,
            })?;
        config.validate()?;
        Ok(config)
    }

    /// Enforces the `requires_dcp` invariants documented on
    /// [`ParticipantEntry`]: any such participant must carry a
    /// `provider_did`, and the file must have a `[holder]` section for
    /// the crawler to actually authenticate as.
    fn validate(&self) -> Result<(), ConfigError> {
        for participant in &self.participants {
            if !participant.requires_dcp {
                continue;
            }
            if participant.provider_did.is_none() {
                return Err(ConfigError::MissingProviderDid {
                    id: participant.id.clone(),
                });
            }
            if self.holder.is_none() {
                return Err(ConfigError::MissingHolderSection {
                    id: participant.id.clone(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
        interval_secs = 300

        [[participants]]
        id = "participant-a"
        name = "Participant A"
        catalog_request_url = "http://127.0.0.1:19001/dsp/catalog/request"

        [[participants]]
        id = "gated-participant"
        name = "DCP-gated participant"
        catalog_request_url = "http://127.0.0.1:19002/dsp/catalog/request"
        credential_protocol = "dcp"
        provider_did = "did:web:localhost%3A19002:dsp"

        [holder]
        own_did_host = "localhost:19100"
        insecure_http = true
        credential_jws = "header.payload.signature"
        required_scope = "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read"
    "#;

    #[test]
    fn parses_a_valid_config_file() {
        let config = ParticipantsConfig::parse(VALID_CONFIG, "test.toml").expect("should parse");
        assert_eq!(config.interval_secs, 300);
        assert_eq!(config.participants.len(), 2);

        let a = &config.participants[0];
        assert_eq!(a.id, "participant-a");
        assert_eq!(a.name, "Participant A");
        assert_eq!(
            a.catalog_request_url,
            "http://127.0.0.1:19001/dsp/catalog/request"
        );
        assert!(matches!(a.credential_protocol, CredentialProtocol::None));
        assert!(a.provider_did.is_none());
        assert!(a.oid4vp_response_uri.is_none());

        let gated = &config.participants[1];
        assert!(matches!(gated.credential_protocol, CredentialProtocol::Dcp));
        assert_eq!(
            gated.provider_did.as_deref(),
            Some("did:web:localhost%3A19002:dsp")
        );

        let holder = config.holder.expect("holder section present");
        assert_eq!(holder.own_did_host, "localhost:19100");
        assert!(holder.insecure_http);
        assert_eq!(holder.credential_jws, "header.payload.signature");
        assert_eq!(
            holder.required_scope,
            "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read"
        );
    }

    #[test]
    fn a_participant_with_no_credential_protocol_field_defaults_to_none_and_needs_nothing_else() {
        let raw = r#"
            interval_secs = 60

            [[participants]]
            id = "open-participant"
            name = "Open participant"
            catalog_request_url = "http://127.0.0.1:19001/dsp/catalog/request"
        "#;
        let config = ParticipantsConfig::parse(raw, "test.toml").expect("should parse");
        assert!(matches!(config.participants[0].credential_protocol, CredentialProtocol::None));
        assert!(config.holder.is_none());
    }

    #[test]
    fn rejects_dcp_without_provider_did() {
        let raw = r#"
            interval_secs = 60

            [[participants]]
            id = "gated-participant"
            name = "DCP-gated participant"
            catalog_request_url = "http://127.0.0.1:19002/dsp/catalog/request"
            credential_protocol = "dcp"

            [holder]
            own_did_host = "localhost:19100"
            credential_jws = "header.payload.signature"
            required_scope = "some-scope"
        "#;
        let err = ParticipantsConfig::parse(raw, "test.toml").expect_err("should reject");
        match err {
            ConfigError::MissingProviderDid { id } => assert_eq!(id, "gated-participant"),
            other => panic!("expected MissingProviderDid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_dcp_without_holder_section() {
        let raw = r#"
            interval_secs = 60

            [[participants]]
            id = "gated-participant"
            name = "DCP-gated participant"
            catalog_request_url = "http://127.0.0.1:19002/dsp/catalog/request"
            credential_protocol = "dcp"
            provider_did = "did:web:localhost%3A19002:dsp"
        "#;
        let err = ParticipantsConfig::parse(raw, "test.toml").expect_err("should reject");
        match err {
            ConfigError::MissingHolderSection { id } => assert_eq!(id, "gated-participant"),
            other => panic!("expected MissingHolderSection, got {other:?}"),
        }
    }

    #[test]
    fn parses_an_oid4vp_participant_with_response_uri_set() {
        let raw = r#"
            interval_secs = 60

            [[participants]]
            id = "oid4vp-participant"
            name = "OID4VP-gated participant"
            catalog_request_url = "http://127.0.0.1:19003/dsp/catalog/request"
            credential_protocol = "oid4vp"
            oid4vp_response_uri = "http://127.0.0.1:19003/oid4vp/response"

            [holder]
            own_did_host = "localhost:19100"
            credential_jws = "header.payload.signature"
            required_scope = "some-scope"
        "#;
        let config = ParticipantsConfig::parse(raw, "test.toml").expect("should parse");
        let p = &config.participants[0];
        assert!(matches!(p.credential_protocol, CredentialProtocol::Oid4Vp));
        assert_eq!(p.oid4vp_response_uri.as_deref(), Some("http://127.0.0.1:19003/oid4vp/response"));
        assert!(p.provider_did.is_none());
    }

    #[test]
    fn rejects_oid4vp_without_response_uri() {
        let raw = r#"
            interval_secs = 60

            [[participants]]
            id = "oid4vp-participant"
            name = "OID4VP-gated participant"
            catalog_request_url = "http://127.0.0.1:19003/dsp/catalog/request"
            credential_protocol = "oid4vp"

            [holder]
            own_did_host = "localhost:19100"
            credential_jws = "header.payload.signature"
            required_scope = "some-scope"
        "#;
        let err = ParticipantsConfig::parse(raw, "test.toml").expect_err("should reject");
        match err {
            ConfigError::MissingOid4VpResponseUri { id } => assert_eq!(id, "oid4vp-participant"),
            other => panic!("expected MissingOid4VpResponseUri, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oid4vp_without_holder_section() {
        let raw = r#"
            interval_secs = 60

            [[participants]]
            id = "oid4vp-participant"
            name = "OID4VP-gated participant"
            catalog_request_url = "http://127.0.0.1:19003/dsp/catalog/request"
            credential_protocol = "oid4vp"
            oid4vp_response_uri = "http://127.0.0.1:19003/oid4vp/response"
        "#;
        let err = ParticipantsConfig::parse(raw, "test.toml").expect_err("should reject");
        match err {
            ConfigError::MissingHolderSection { id } => assert_eq!(id, "oid4vp-participant"),
            other => panic!("expected MissingHolderSection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_toml() {
        let err =
            ParticipantsConfig::parse("not = [valid", "test.toml").expect_err("should reject");
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn load_reports_a_clear_error_for_a_missing_file() {
        let err = ParticipantsConfig::load("/nonexistent/path/to/crawler-config.toml")
            .expect_err("should fail");
        assert!(matches!(err, ConfigError::Io { .. }));
    }
}
