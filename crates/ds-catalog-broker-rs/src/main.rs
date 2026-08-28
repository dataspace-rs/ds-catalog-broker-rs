use std::sync::Arc;

use crawler::ParticipantsConfig;
use dcp_core::HolderIdentity;
use ds_catalog_broker_rs::oauth2::{OAuth2Config, OAuth2Verifier};
use ds_catalog_broker_rs::{AppState, build_router, seed_sample_catalog};
use rdf_store::CatalogCache;
use rdf_store::memory::InMemoryCatalogCache;

const DEFAULT_ADDR: &str = "127.0.0.1:8080";

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

/// Reads the `OAUTH2_*` env vars (see
/// `docs/oauth2-bearer-gating-2026-08-28.md`'s config table) and builds an
/// [`OAuth2Config`], the same "presence of the required var decides
/// opt-in" shape as `load_crawler_config`. `OAUTH2_JWKS_URI` unset ->
/// `None`, and gating stays off - byte-identical behavior to before this
/// feature existed. `OAUTH2_ISSUER`/`OAUTH2_AUDIENCE`/`OAUTH2_REQUIRED_SCOPE`
/// are all optional and independent of each other.
fn load_oauth2_config() -> Option<OAuth2Config> {
    let jwks_uri = std::env::var("OAUTH2_JWKS_URI").ok()?;
    Some(OAuth2Config {
        jwks_uri,
        issuer: std::env::var("OAUTH2_ISSUER").ok(),
        audience: std::env::var("OAUTH2_AUDIENCE").ok(),
        required_scope: std::env::var("OAUTH2_REQUIRED_SCOPE").ok(),
    })
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr = std::env::var("HTTP_API_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());

    let http_client = reqwest::Client::new();

    // OAUTH2_JWKS_URI unset: `oauth2_verifier` stays `None` and both gated
    // routes are byte-identical to before this feature existed (see
    // `AppState::oauth2`'s doc comment). Set: fetched eagerly, here, before
    // `AppState` is built - a bad/unreachable JWKS panics on boot rather
    // than silently starting unauthenticated, the same failure posture as
    // a bad `CRAWLER_CONFIG_PATH` below.
    let oauth2_verifier = match load_oauth2_config() {
        Some(config) => {
            let jwks_uri = config.jwks_uri.clone();
            let verifier = OAuth2Verifier::fetch(&http_client, config)
                .await
                .unwrap_or_else(|err| {
                    panic!("failed to fetch/verify OAUTH2_JWKS_URI={jwks_uri:?}: {err}")
                });
            Some(Arc::new(verifier))
        }
        None => None,
    };
    tracing::info!(
        oauth2_gating_active = oauth2_verifier.is_some(),
        "oauth2 bearer gating configuration resolved (OAUTH2_JWKS_URI unset means both /catalog and /sparql stay unauthenticated)"
    );

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
    type CacheHolderSparql = (
        Arc<dyn CatalogCache>,
        Option<Arc<HolderIdentity>>,
        Option<Arc<rdf_store::oxigraph_backend::OxigraphCatalogCache>>,
    );
    let (cache, holder, sparql): CacheHolderSparql = match load_crawler_config() {
        Some(config) => {
            // Kept as a concrete `Arc<OxigraphCatalogCache>` (not just the
            // `Arc<dyn CatalogCache>` coercion below) purely so `AppState`
            // can also wire up `/sparql` against it - see
            // `AppState::sparql`'s own doc comment for why that can't be
            // recovered from the trait object alone.
            let store = Arc::new(
                rdf_store::oxigraph_backend::OxigraphCatalogCache::in_memory()
                    .expect("open in-memory Oxigraph store"),
            );
            let cache: Arc<dyn CatalogCache> = store.clone();
            let holder = build_holder(&config);
            tracing::info!(
                participants = config.participants.len(),
                interval_secs = config.interval_secs,
                holder_configured = holder.is_some(),
                "starting scheduled catalog crawler (CRAWLER_CONFIG_PATH set); serving from an in-memory Oxigraph store, with /sparql enabled"
            );
            crawler::spawn_scheduler(cache.clone(), config, http_client.clone(), holder.clone());
            (cache, holder, Some(store))
        }
        None => {
            // No crawler configured: the plain in-memory cache, seeded
            // with one sample catalog - this stands in for a real crawl
            // result until CRAWLER_CONFIG_PATH is set. No SPARQL backend
            // either (see `AppState::sparql`'s doc comment): `/sparql`
            // answers 501 until a real Oxigraph-backed crawl is running.
            let cache: Arc<dyn CatalogCache> = Arc::new(InMemoryCatalogCache::new());
            seed_sample_catalog(&*cache)
                .await
                .expect("seeding sample catalog failed");
            (cache, None, None)
        }
    };

    let mut state = AppState::new(cache)
        .with_holder(holder)
        .with_sparql(sparql)
        .with_oauth2(oauth2_verifier);
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
