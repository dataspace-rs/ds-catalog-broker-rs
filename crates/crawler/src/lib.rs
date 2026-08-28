//! Scheduled catalog crawler.
//!
//! Polls each participant in a local-config registry (see [`config`]) for
//! its DSP catalog, parses the response leniently enough to tolerate both
//! this workspace's own compact DSP shape and real Eclipse EDC's fuller
//! JSON-LD shape (see [`parse_catalog_response`]'s doc comment), and
//! upserts the result into an `rdf_store::CatalogCache` - the same trait
//! `ds-catalog-broker-rs` serves `GET /catalog` and the DSP catalog endpoints from, so
//! a successful crawl cycle is immediately visible there.
//!
//! [`crawl_once`] runs exactly one cycle over every configured
//! participant and returns a [`CrawlSummary`] - useful directly in tests,
//! and as the building block [`spawn_scheduler`] calls on a
//! `tokio::time::interval` tick.

pub mod config;

pub use config::{ConfigError, HolderConfig, ParticipantEntry, ParticipantsConfig};

use std::sync::Arc;
use std::time::Duration;

use catalog_core::{Catalog, DataService, Dataset, Distribution, NodeId};
use dcp_core::HolderIdentity;
use rdf_store::CatalogCache;
use serde_json::Value;

/// `@context` for the `CatalogRequestMessage` this crawler POSTs to each
/// participant - matches what `ds-catalog-broker-rs`'s own `catalog_request` handler
/// already accepts (and, today, ignores the rest of).
const DSP_CONTEXT_URL: &str = "https://w3id.org/dspace/2025/1/context.jsonld";

/// Placeholder `Authorization` header value sent to a `requires_dcp = false`
/// participant. Real Eclipse EDC's DSP catalog handler
/// (`DspRequestHandlerImpl`) returns `401` on a *missing* `Authorization`
/// header unconditionally, before any `IdentityService` ever runs - even
/// when that participant's own identity service (e.g. a no-op/permissive
/// one, or none at all beyond a bare presence check) would accept anything.
/// This workspace's own `ds-catalog-broker-rs` under `DspAuthMode::Disabled` ignores
/// the header entirely either way, so sending a fixed, non-secret,
/// non-empty placeholder here is harmless to it and required for real EDC
/// interop - confirmed against a real, unmodified EDC 0.18.0 instance, see
/// `compliance/crawler-edc-integration-test.md`.
const OPEN_PARTICIPANT_PLACEHOLDER_AUTH: &str = "federated-catalog-rs-crawler-anonymous";

/// The outcome of one [`crawl_once`] cycle. Callers (tests, the scheduler
/// loop) get real counts and per-participant error messages rather than a
/// bare pass/fail bool, since "3 of 5 participants failed, here's why" is
/// the actionable signal a scheduled job needs to log or assert on.
#[derive(Debug, Default, Clone)]
pub struct CrawlSummary {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    /// `(participant_id, error message)` for every participant that
    /// failed this cycle, in participant order.
    pub failures: Vec<(String, String)>,
}

/// Run one crawl cycle over every entry in `participants`, upserting each
/// successful result into `cache`.
///
/// A failure fetching or parsing one participant's catalog (network
/// error, non-2xx response, malformed JSON) is recorded in the returned
/// [`CrawlSummary`] and does not abort the rest of the cycle - one bad
/// participant must never prevent the others from being crawled.
pub async fn crawl_once(
    http: &reqwest::Client,
    participants: &[ParticipantEntry],
    holder: Option<&HolderIdentity>,
    cache: &dyn CatalogCache,
) -> CrawlSummary {
    let mut summary = CrawlSummary::default();

    for participant in participants {
        summary.attempted += 1;
        match crawl_one(http, participant, holder).await {
            Ok(catalog) => match cache.upsert(catalog).await {
                Ok(()) => summary.succeeded += 1,
                Err(err) => {
                    summary.failed += 1;
                    summary.failures.push((
                        participant.id.clone(),
                        format!("failed to cache crawl result: {err}"),
                    ));
                }
            },
            Err(err) => {
                summary.failed += 1;
                summary.failures.push((participant.id.clone(), err));
            }
        }
    }

    summary
}

/// Fetch and parse one participant's catalog. Split out of [`crawl_once`]
/// so its `?`-heavy body can return a plain `Result` per participant
/// instead of threading failure bookkeeping through every step by hand.
async fn crawl_one(
    http: &reqwest::Client,
    participant: &ParticipantEntry,
    holder: Option<&HolderIdentity>,
) -> Result<Catalog, String> {
    let request_body = serde_json::json!({
        "@context": [DSP_CONTEXT_URL],
        "@type": "CatalogRequestMessage",
    });

    let mut request = http
        .post(&participant.catalog_request_url)
        .json(&request_body);

    if participant.requires_dcp {
        // Config validation (`ParticipantsConfig::validate`) already
        // guarantees a `requires_dcp` participant has a `provider_did`
        // and the file has a `[holder]` section, so a `holder` of `None`
        // or a missing `provider_did` here means the caller built
        // `ParticipantsConfig`/`HolderIdentity` inconsistently by hand
        // rather than through that validation - still handled as a
        // per-participant failure, not a panic, since a crawl cycle
        // should never take down the process.
        let holder = holder.ok_or_else(|| {
            format!(
                "participant '{}' requires_dcp but no holder identity is configured",
                participant.id
            )
        })?;
        let provider_did = participant.provider_did.as_deref().ok_or_else(|| {
            format!(
                "participant '{}' requires_dcp but has no provider_did",
                participant.id
            )
        })?;
        let token = holder.mint_self_issued_token(provider_did);
        request = request.bearer_auth(token);
    } else {
        // See `OPEN_PARTICIPANT_PLACEHOLDER_AUTH`'s doc comment: real DSP
        // servers (confirmed: Eclipse EDC) require *a* header to be
        // present even when the participant enforces no real
        // authentication - not `.bearer_auth(...)` (no "Bearer " prefix
        // wanted here; a raw header value is what real EDC's DSP layer
        // reads verbatim).
        request = request.header(
            reqwest::header::AUTHORIZATION,
            OPEN_PARTICIPANT_PLACEHOLDER_AUTH,
        );
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("request to {} failed: {e}", participant.catalog_request_url))?;

    if !response.status().is_success() {
        return Err(format!(
            "{} returned HTTP {}",
            participant.catalog_request_url,
            response.status()
        ));
    }

    let body: Value = response.json().await.map_err(|e| {
        format!(
            "malformed JSON response from {}: {e}",
            participant.catalog_request_url
        )
    })?;

    Ok(parse_catalog_response(&body, participant))
}

/// Parse a DSP catalog-request response body into a `catalog_core::Catalog`,
/// leniently enough to accept either this workspace's own compact DSP
/// shape or real Eclipse EDC's fuller one. Notably: EDC's `accessService`
/// is a full nested `DataService` object (with its own `@id`/`endpointURL`),
/// while this workspace's own DSP responses use a compact string id for
/// the same field - both are accepted here via `serde_json::Value`-based
/// extraction rather than a rigid typed struct that would only match one
/// shape.
///
/// A response missing `dataset` and/or `service` entirely is not an error
/// - it produces a `Catalog` with empty `datasets`/`data_services`.
///
/// Also tolerates a "federation of federations" response - one where the
/// crawled participant is itself a multi-participant aggregator (e.g.
/// another instance of this workspace's own `ds-catalog-broker-rs`, once it has 2+
/// origin nodes cached: see `ds-catalog-broker-rs`'s `catalog_request`) and so nests
/// its real content under a top-level `catalog` array instead of top-level
/// `dataset`/`service`. This crate's own data model is one `Catalog` per
/// configured target participant, not per nested sub-participant, so any
/// nested `catalog[]` entries found are flattened into the *same* returned
/// `Catalog` right alongside the top-level entries (recursively, in case a
/// nested entry is itself nested) - which participant a dataset nested
/// several levels down originally came from is not preserved, only that it
/// isn't silently dropped. Without this, a crawl target returning a purely
/// nested response (empty top-level `dataset`/`service`, matching what
/// `catalog_request` now does for 2+ cached origin nodes) would parse as
/// an apparently-empty catalog.
fn parse_catalog_response(value: &Value, participant: &ParticipantEntry) -> Catalog {
    let id = value
        .get("@id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4()));

    let mut catalog = Catalog::new(id, NodeId::new(participant.id.clone()));
    catalog.participant_id = value
        .get("participantId")
        .and_then(Value::as_str)
        .map(str::to_string);

    collect_datasets_and_services(value, &mut catalog);

    catalog
}

/// Extract `value`'s own `service`/`dataset` entries into `catalog`, then
/// recurse into any nested `catalog[]` entries doing the same - see
/// `parse_catalog_response`'s doc comment for why. `value` is either the
/// top-level response body or one nested `catalog[]` entry; both share the
/// same `service`/`dataset`/`catalog` shape.
fn collect_datasets_and_services(value: &Value, catalog: &mut Catalog) {
    // `service` entries first, so a dataset's nested `accessService`
    // object (parsed below) can be folded in without duplicating one
    // already listed here.
    if let Some(services) = value.get("service").and_then(Value::as_array) {
        for service_value in services {
            if let Some(service) = parse_data_service(service_value)
                && !catalog.data_services.iter().any(|s| s.id == service.id)
            {
                catalog.data_services.push(service);
            }
        }
    }

    if let Some(datasets) = value.get("dataset").and_then(Value::as_array) {
        for dataset_value in datasets {
            let Some(dataset_id) = dataset_value
                .get("@id")
                .or_else(|| dataset_value.get("id"))
                .and_then(Value::as_str)
            else {
                continue;
            };

            let mut dataset = Dataset {
                id: dataset_id.to_string(),
                properties: Default::default(),
                distributions: Vec::new(),
            };

            if let Some(distributions) = dataset_value.get("distribution").and_then(Value::as_array)
            {
                for distribution_value in distributions {
                    let format = distribution_value
                        .get("format")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();

                    let access_service = match distribution_value.get("accessService") {
                        Some(Value::String(id)) => id.clone(),
                        Some(access_service_value @ Value::Object(_)) => {
                            let id = access_service_value
                                .get("@id")
                                .or_else(|| access_service_value.get("id"))
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();
                            if let Some(service) = parse_data_service(access_service_value)
                                && !catalog.data_services.iter().any(|s| s.id == service.id)
                            {
                                catalog.data_services.push(service);
                            }
                            id
                        }
                        _ => String::new(),
                    };

                    dataset.distributions.push(Distribution {
                        format,
                        access_service,
                    });
                }
            }

            catalog.datasets.push(dataset);
        }
    }

    if let Some(nested_catalogs) = value.get("catalog").and_then(Value::as_array) {
        for nested_value in nested_catalogs {
            collect_datasets_and_services(nested_value, catalog);
        }
    }
}

/// Extract a `DataService` from either a top-level `service` array entry
/// or a nested `accessService` object - both share the same
/// `@id`/`id` + `endpointURL` (+ optional `endpointDescription`) shape.
fn parse_data_service(value: &Value) -> Option<DataService> {
    let id = value
        .get("@id")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)?
        .to_string();
    let endpoint_url = value
        .get("endpointURL")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let endpoint_description = value
        .get("endpointDescription")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some(DataService {
        id,
        endpoint_url,
        endpoint_description,
    })
}

/// Spawn a background task that runs [`crawl_once`] every
/// `config.interval_secs` seconds (starting immediately, per
/// `tokio::time::interval`'s default first-tick behavior), logging each
/// cycle's [`CrawlSummary`] via `tracing`.
///
/// Runs for the lifetime of the returned `JoinHandle` (i.e. forever,
/// unless the handle is aborted or the runtime shuts down) - there is no
/// built-in stop condition, matching a long-lived server process.
pub fn spawn_scheduler(
    cache: Arc<dyn CatalogCache>,
    config: ParticipantsConfig,
    http: reqwest::Client,
    holder: Option<Arc<HolderIdentity>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(config.interval_secs.max(1)));
        loop {
            interval.tick().await;
            let summary = crawl_once(&http, &config.participants, holder.as_deref(), &*cache).await;
            if summary.failed > 0 {
                tracing::warn!(
                    attempted = summary.attempted,
                    succeeded = summary.succeeded,
                    failed = summary.failed,
                    failures = ?summary.failures,
                    "crawl cycle completed with failures"
                );
            } else {
                tracing::info!(
                    attempted = summary.attempted,
                    succeeded = summary.succeeded,
                    "crawl cycle completed"
                );
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdf_store::CatalogQuery;
    use rdf_store::memory::InMemoryCatalogCache;
    use serde_json::json;

    fn participant(id: &str) -> ParticipantEntry {
        ParticipantEntry {
            id: id.to_string(),
            name: id.to_string(),
            catalog_request_url: "http://127.0.0.1:0/dsp/catalog/request".to_string(),
            requires_dcp: false,
            provider_did: None,
        }
    }

    /// The real-EDC-shaped sample response from this task's own briefing
    /// (`compliance/benchmark-2026-08-27.md`'s "Fidelity comparison"
    /// section): a full nested `accessService` object, not a compact
    /// string id.
    fn real_edc_shaped_response() -> Value {
        json!({
            "@id": "6d3d7a0c-bf06-4160-839f-853350446179",
            "@type": "Catalog",
            "dataset": [
                {
                    "@id": "CAT0101",
                    "@type": "Dataset",
                    "hasPolicy": [{"@id": "offer-1", "@type": "Offer", "permission": [{"action": "use"}]}],
                    "distribution": [{
                        "@type": "Distribution",
                        "format": "HttpData-PULL",
                        "accessService": {
                            "@id": "5ee7e0fa-a2bc-4251-bab3-d3a1454dcfc8",
                            "@type": "DataService",
                            "endpointDescription": "dspace:connector",
                            "endpointURL": "http://localhost:8082/api/dsp/2025-1"
                        }
                    }],
                    "id": "CAT0101"
                }
            ],
            "service": [{
                "@id": "5ee7e0fa-a2bc-4251-bab3-d3a1454dcfc8",
                "@type": "DataService",
                "endpointDescription": "dspace:connector",
                "endpointURL": "http://localhost:8082/api/dsp/2025-1"
            }],
            "participantId": "CONNECTOR_UNDER_TEST",
            "@context": ["https://w3id.org/dspace/2025/1/context.jsonld", "https://w3id.org/edc/dspace/v0.0.1"]
        })
    }

    #[test]
    fn parses_real_edc_shaped_response_with_nested_access_service_object() {
        let participant = participant("edc-participant");
        let catalog = parse_catalog_response(&real_edc_shaped_response(), &participant);

        assert_eq!(catalog.id, "6d3d7a0c-bf06-4160-839f-853350446179");
        assert_eq!(catalog.origin_node, NodeId::new("edc-participant"));
        assert_eq!(
            catalog.participant_id.as_deref(),
            Some("CONNECTOR_UNDER_TEST")
        );

        assert_eq!(catalog.datasets.len(), 1);
        let dataset = &catalog.datasets[0];
        assert_eq!(dataset.id, "CAT0101");
        assert_eq!(dataset.distributions.len(), 1);
        assert_eq!(dataset.distributions[0].format, "HttpData-PULL");
        assert_eq!(
            dataset.distributions[0].access_service,
            "5ee7e0fa-a2bc-4251-bab3-d3a1454dcfc8"
        );

        // The nested accessService object's endpointURL isn't lost: it's
        // folded into data_services (deduplicated against the top-level
        // `service` array entry sharing the same id).
        assert_eq!(catalog.data_services.len(), 1);
        assert_eq!(
            catalog.data_services[0].id,
            "5ee7e0fa-a2bc-4251-bab3-d3a1454dcfc8"
        );
        assert_eq!(
            catalog.data_services[0].endpoint_url,
            "http://localhost:8082/api/dsp/2025-1"
        );
        assert_eq!(
            catalog.data_services[0].endpoint_description.as_deref(),
            Some("dspace:connector")
        );
    }

    #[test]
    fn parses_compact_string_access_service() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "CAT0101",
                "distribution": [{"format": "application/json", "accessService": "sample-data-service"}]
            }],
            "service": [{"@id": "sample-data-service", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("compact-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.datasets.len(), 1);
        assert_eq!(
            catalog.datasets[0].distributions[0].access_service,
            "sample-data-service"
        );
        assert_eq!(catalog.data_services.len(), 1);
        assert_eq!(
            catalog.data_services[0].endpoint_url,
            "https://example.org/dsp"
        );
    }

    #[test]
    fn missing_dataset_and_service_arrays_produce_an_empty_but_valid_catalog() {
        let body = json!({"@id": "empty-cat"});
        let participant = participant("empty-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.id, "empty-cat");
        assert!(catalog.datasets.is_empty());
        assert!(catalog.data_services.is_empty());
    }

    #[test]
    fn missing_id_falls_back_to_a_fresh_uuid() {
        let body = json!({"dataset": []});
        let participant = participant("no-id-participant");
        let catalog = parse_catalog_response(&body, &participant);
        assert!(catalog.id.starts_with("urn:uuid:"));
    }

    #[test]
    fn dataset_id_falls_back_to_plain_id_field_when_at_id_is_absent() {
        let body = json!({"dataset": [{"id": "CAT0102"}]});
        let participant = participant("plain-id-participant");
        let catalog = parse_catalog_response(&body, &participant);
        assert_eq!(catalog.datasets.len(), 1);
        assert_eq!(catalog.datasets[0].id, "CAT0102");
    }

    /// "Federation of federations": the crawled participant is itself a
    /// multi-participant aggregator (another instance of this workspace's
    /// own `ds-catalog-broker-rs`, once it has 2+ origin nodes cached - see
    /// `ds_catalog_broker_rs::catalog_request`'s doc comment), so its response has
    /// empty top-level `dataset`/`service` and nests everything under
    /// `catalog[]` instead, one entry per sub-participant. Without
    /// flattening those nested entries, this would silently parse as an
    /// empty catalog even though the crawled node advertised 10 datasets.
    #[test]
    fn flattens_nested_catalog_entries_from_a_federation_of_federations_response() {
        let body = json!({
            "@id": "urn:uuid:outer-wrapper",
            "@type": "Catalog",
            "participantId": "urn:connector:upstream-aggregator",
            "dataset": [],
            "service": [],
            "catalog": [
                {
                    "@id": "urn:uuid:node-a-catalog",
                    "@type": "Catalog",
                    "participantId": "did:example:node-a",
                    "dataset": [
                        {
                            "@id": "A1",
                            "distribution": [{"format": "application/json", "accessService": "node-a-data-service"}]
                        }
                    ],
                    "service": [{"@id": "node-a-data-service", "endpointURL": "https://node-a.example.org/dsp"}]
                },
                {
                    "@id": "urn:uuid:node-b-catalog",
                    "@type": "Catalog",
                    "participantId": "did:example:node-b",
                    "dataset": [
                        {
                            "@id": "B1",
                            "distribution": [{"format": "application/json", "accessService": "node-b-data-service"}]
                        }
                    ],
                    "service": [{"@id": "node-b-data-service", "endpointURL": "https://node-b.example.org/dsp"}]
                }
            ]
        });
        let participant = participant("upstream-aggregator-participant");
        let catalog = parse_catalog_response(&body, &participant);

        // One Catalog per configured target participant is this crate's
        // own model - nested sub-participant identity isn't preserved,
        // only that the data isn't dropped. The outer wrapper's own
        // participantId is what's kept.
        assert_eq!(
            catalog.origin_node,
            NodeId::new("upstream-aggregator-participant")
        );
        assert_eq!(
            catalog.participant_id.as_deref(),
            Some("urn:connector:upstream-aggregator")
        );

        let mut dataset_ids: Vec<&str> = catalog.datasets.iter().map(|d| d.id.as_str()).collect();
        dataset_ids.sort();
        assert_eq!(dataset_ids, vec!["A1", "B1"]);

        let mut service_ids: Vec<&str> = catalog
            .data_services
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        service_ids.sort();
        assert_eq!(
            service_ids,
            vec!["node-a-data-service", "node-b-data-service"]
        );
    }

    #[tokio::test]
    async fn crawl_once_records_a_failure_for_an_unreachable_participant_and_continues() {
        // Port 0 never accepts connections, so this participant's request
        // is guaranteed to fail at the transport level without needing a
        // real server.
        let participants = vec![participant("unreachable-participant")];
        let cache = InMemoryCatalogCache::new();
        let http = reqwest::Client::new();

        let summary = crawl_once(&http, &participants, None, &cache).await;

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(summary.failures[0].0, "unreachable-participant");

        let stored = cache.query(CatalogQuery::all()).await.unwrap();
        assert!(stored.is_empty());
    }

    #[tokio::test]
    async fn crawl_one_requires_a_holder_identity_for_a_requires_dcp_participant() {
        let mut gated = participant("gated-participant");
        gated.requires_dcp = true;
        gated.provider_did = Some("did:web:localhost%3A19002:dsp".to_string());
        let http = reqwest::Client::new();

        let err = crawl_one(&http, &gated, None)
            .await
            .expect_err("should fail without a holder");
        assert!(
            err.contains("no holder identity is configured"),
            "unexpected error: {err}"
        );
    }
}
