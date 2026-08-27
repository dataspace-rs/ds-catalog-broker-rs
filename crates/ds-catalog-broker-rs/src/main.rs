use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crawler::ParticipantsConfig;
use dcp_core::HolderIdentity;
use ds_catalog_broker_rs::{AppState, DcpConfig, DspAuthConfig, DspAuthMode, build_router, seed_sample_catalog};
use rdf_store::CatalogCache;
use rdf_store::memory::InMemoryCatalogCache;

const DEFAULT_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_DCP_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read";

/// Reads `CRAWLER_CONFIG_PATH` (optional). When set, loads and validates
/// the TOML file at that path and builds this connector's own DCP holder
/// identity from its `[holder]` section (if any). When unset, returns
/// `None` and the caller must fall back to today's placeholder
/// (`seed_sample_catalog`) - see `main`'s doc comment on why that
/// fallback is a strict backward-compatibility requirement, not a default
/// worth changing here.
fn load_crawler_config() -> Option<ParticipantsConfig> {
    let path = std::env::var("CRAWLER_CONFIG_PATH").ok()?;
    let config = ParticipantsConfig::load(&path)
        .unwrap_or_else(|err| panic!("failed to load CRAWLER_CONFIG_PATH={path:?}: {err}"));
    Some(config)
}

fn build_holder(config: &ParticipantsConfig) -> Option<Arc<HolderIdentity>> {
    config.holder.as_ref().map(|holder_config| {
        Arc::new(HolderIdentity::new(
            holder_config.own_did_host.clone(),
            holder_config.insecure_http,
            holder_config.credential_jws.clone(),
            holder_config.required_scope.clone(),
        ))
    })
}

/// Reads `DSP_AUTH_MODE` (`"none"` (default) | `"bearer"` | `"dcp"`, case
/// insensitive):
///
/// - `bearer`: `DSP_CATALOG_ACCESS` - a JSON object mapping bearer token
///   to an array of dataset ids that token may see, e.g.
///   `{"consumer-a-token":["CAT0101"],"consumer-b-token":["CAT0101","CAT0102"]}`.
///   Unset is valid (any presented token is then denied by default - see
///   `visible_datasets`'s doc comment), it just means nobody is
///   configured yet.
/// - `dcp`: `DSP_DCP_OWN_DID_HOST` (required, e.g. `localhost:18080` -
///   this connector's own `did:web` host:port, used to build and host
///   `did:web:<host>:dsp`, see `dcp::DcpConfig::own_did_document`),
///   `DSP_DCP_INSECURE_HTTP` (optional, default `false` - set `true` to
///   resolve `did:web` DIDs over plain HTTP instead of HTTPS, matching
///   `compliance/dcp-test-env`'s local setup), `DSP_DCP_REQUIRED_SCOPE`
///   (optional, defaults to the scope `compliance/dcp-test-env` seeds).
///
/// See `DspAuthConfig`'s doc comment and `dcp.rs`'s module doc comment
/// for what `bearer` vs `dcp` actually verify.
fn load_dsp_auth() -> DspAuthConfig {
    let mode = match std::env::var("DSP_AUTH_MODE") {
        Ok(value) if value.eq_ignore_ascii_case("bearer") => DspAuthMode::Bearer,
        Ok(value) if value.eq_ignore_ascii_case("dcp") => DspAuthMode::Dcp,
        Ok(value) if value.eq_ignore_ascii_case("none") || value.is_empty() => DspAuthMode::Disabled,
        Ok(other) => panic!(
            "DSP_AUTH_MODE={other:?} is not recognized - expected \"none\", \"bearer\", or \"dcp\""
        ),
        Err(_) => DspAuthMode::Disabled,
    };

    let catalog_access = match std::env::var("DSP_CATALOG_ACCESS") {
        Ok(raw) => {
            let parsed: HashMap<String, HashSet<String>> = serde_json::from_str(&raw)
                .unwrap_or_else(|err| panic!("DSP_CATALOG_ACCESS is not valid JSON: {err}"));
            parsed
        }
        Err(_) => HashMap::new(),
    };

    let dcp = if mode == DspAuthMode::Dcp {
        let own_did_host = std::env::var("DSP_DCP_OWN_DID_HOST")
            .unwrap_or_else(|_| panic!("DSP_AUTH_MODE=dcp requires DSP_DCP_OWN_DID_HOST (e.g. localhost:18080)"));
        let own_did = format!("did:web:{}:dsp", own_did_host.replace(':', "%3A"));
        let insecure_http = std::env::var("DSP_DCP_INSECURE_HTTP")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let required_scope = std::env::var("DSP_DCP_REQUIRED_SCOPE").unwrap_or_else(|_| DEFAULT_DCP_SCOPE.to_string());
        Some(DcpConfig::generate(own_did, insecure_http, required_scope))
    } else {
        None
    };

    DspAuthConfig {
        mode,
        catalog_access,
        dcp,
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr = std::env::var("HTTP_API_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let dsp_auth = load_dsp_auth();
    if dsp_auth.mode == DspAuthMode::Bearer {
        tracing::info!(
            known_callers = dsp_auth.catalog_access.len(),
            "DSP catalog endpoints require Authorization: Bearer <token> (DSP_AUTH_MODE=bearer)"
        );
    }
    if let Some(dcp_config) = &dsp_auth.dcp {
        tracing::info!(
            own_did = %dcp_config.own_did,
            "DSP catalog endpoints require a real DCP self-issued token (DSP_AUTH_MODE=dcp); \
             this connector's own DID document is hosted at GET /dsp/did.json"
        );
    }

    let http_client = reqwest::Client::new();

    // CRAWLER_CONFIG_PATH unset: byte-identical to this connector's
    // original behavior - a plain in-memory HashMap cache, seeded with one
    // placeholder sample catalog, no crawler started.
    //
    // CRAWLER_CONFIG_PATH set: this connector now works the way EDC's own
    // federated catalog does - a periodic, config-driven crawl populates a
    // real RDF (Oxigraph) store, which the DSP catalog endpoint then
    // serves. In-memory only, same as EDC's own federated-catalog cache:
    // there is no on-disk persistence option here either, by design, not
    // as a gap - see `rdf_store::oxigraph_backend`'s module doc for the
    // backend itself and `crates/crawler`'s doc comments for the crawl
    // loop. `InMemoryCatalogCache` (a plain `HashMap`, not backed by RDF
    // at all) stays the default for everyone not opting into the crawler,
    // per this function's own strict backward-compatibility requirement.
    let (cache, holder): (Arc<dyn CatalogCache>, Option<Arc<HolderIdentity>>) = match load_crawler_config() {
        Some(config) => {
            let cache: Arc<dyn CatalogCache> =
                Arc::new(rdf_store::oxigraph_backend::OxigraphCatalogCache::in_memory().expect("open in-memory Oxigraph store"));
            let holder = build_holder(&config);
            tracing::info!(
                participants = config.participants.len(),
                interval_secs = config.interval_secs,
                holder_configured = holder.is_some(),
                "starting scheduled catalog crawler (CRAWLER_CONFIG_PATH set); serving from an in-memory Oxigraph store"
            );
            crawler::spawn_scheduler(cache.clone(), config, http_client.clone(), holder.clone());
            (cache, holder)
        }
        None => {
            // No crawler configured: the plain in-memory cache, seeded
            // with one sample catalog - this stands in for a real crawl
            // result until CRAWLER_CONFIG_PATH is set.
            let cache: Arc<dyn CatalogCache> = Arc::new(InMemoryCatalogCache::new());
            seed_sample_catalog(&*cache)
                .await
                .expect("seeding sample catalog failed");
            (cache, None)
        }
    };

    let mut state = AppState::new(cache).with_dsp_auth(dsp_auth).with_holder(holder);
    state.http = http_client;
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|err| panic!("failed to bind {addr}: {err}"));
    tracing::info!("ds-catalog-broker-rs listening on {addr}");

    axum::serve(listener, app)
        .await
        .expect("ds-catalog-broker-rs server failed");
}
