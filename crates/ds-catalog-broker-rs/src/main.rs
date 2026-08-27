use std::sync::Arc;

use crawler::ParticipantsConfig;
use dcp_core::HolderIdentity;
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

    let mut state = AppState::new(cache).with_holder(holder);
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
