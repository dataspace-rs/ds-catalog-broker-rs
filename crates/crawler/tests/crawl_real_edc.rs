//! Proves `crawler::crawl_once` against **real, running Eclipse EDC 0.18.0**
//! control-plane instances - not this workspace's own `ds-catalog-broker-rs`, not an
//! in-process test fixture. `#[ignore]`d because it depends on three
//! external processes this repo does not manage: start them first (see
//! `compliance/crawler-edc-fixture/`), then run
//!
//! ```bash
//! cargo test --workspace -- --ignored crawls_three_real_edc_instances_and_aggregates_all_seeded_datasets
//! ```
//!
//! Full setup/teardown commands and real output are in
//! `compliance/crawler-edc-integration-test.md`.

use std::collections::BTreeSet;

use crawler::{ParticipantsConfig, crawl_once};
use rdf_store::memory::InMemoryCatalogCache;
use rdf_store::{CatalogCache, CatalogQuery};

const PARTICIPANTS_TOML: &str =
    include_str!("../../../compliance/crawler-edc-fixture/participants.toml");

/// The six dataset ids `compliance/crawler-edc-fixture`'s three instances
/// are expected to be seeded with (instance A: 2, B: 1, C: 3) - see
/// `compliance/crawler-edc-integration-test.md` for the exact
/// `run-instance.sh` invocations that seed them.
const EXPECTED_DATASET_IDS: [&str; 6] = [
    "EDC-A-01", "EDC-A-02", "EDC-B-01", "EDC-C-01", "EDC-C-02", "EDC-C-03",
];

#[tokio::test]
#[ignore = "requires three real Eclipse EDC 0.18.0 instances running - see compliance/crawler-edc-fixture/"]
async fn crawls_three_real_edc_instances_and_aggregates_all_seeded_datasets() {
    let config = ParticipantsConfig::parse(
        PARTICIPANTS_TOML,
        "compliance/crawler-edc-fixture/participants.toml",
    )
    .expect("participants.toml should parse and validate");
    assert_eq!(
        config.participants.len(),
        3,
        "expected exactly the three real-EDC participants"
    );

    let cache = InMemoryCatalogCache::new();
    let http = reqwest::Client::new();

    let summary = crawl_once(&http, &config.participants, None, &cache).await;

    assert_eq!(
        summary.attempted, 3,
        "expected one crawl attempt per configured real-EDC instance"
    );
    assert_eq!(
        summary.failures,
        Vec::<(String, String)>::new(),
        "expected zero crawl failures against the three real EDC instances - got: {:?}",
        summary.failures
    );
    assert_eq!(
        summary.succeeded, 3,
        "expected all three real-EDC instances to be crawled successfully"
    );

    let catalogs = cache
        .query(CatalogQuery::all())
        .await
        .expect("querying the cache should not fail");
    assert_eq!(
        catalogs.len(),
        3,
        "expected one cached Catalog per real-EDC instance, got {}",
        catalogs.len()
    );

    let observed_ids: BTreeSet<String> = catalogs
        .iter()
        .flat_map(|catalog| catalog.datasets.iter().map(|dataset| dataset.id.clone()))
        .collect();

    let expected_ids: BTreeSet<String> =
        EXPECTED_DATASET_IDS.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        observed_ids, expected_ids,
        "aggregated catalog across all three real EDC instances did not contain exactly the six expected seeded dataset ids"
    );
}
