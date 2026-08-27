//! Storage abstraction for the federated catalog cache.
//!
//! Named `rdf-store` because a crawled catalog is expected to eventually be
//! represented as an RDF named graph (one graph per participant), but the
//! [`CatalogCache`] trait itself is backend-agnostic. Which RDF store (or
//! whether RDF at all, vs. e.g. a plain document store) backs this is a
//! decision being made iteratively - see the `dataspace` study repo's
//! `docs/spikes/` for the exploration behind that choice - so this crate
//! only fixes the shape of the trait plus one in-memory implementation
//! good enough to unblock `ds-catalog-broker-rs` and its own tests.
//!
//! The trait mirrors Eclipse EDC's `FederatedCatalogCache` SPI
//! (`save`/`query`/`deleteExpired`/`expireAll`) but adapted to a
//! from-scratch design: EDC's mark-then-sweep expiry (`deleteExpired` +
//! `expireAll` called every crawl tick) is replaced here by an explicit
//! `delete(node)`, since the tick/expiry policy belongs to a future
//! crawler crate, not to the storage trait itself. Like EDC, each
//! participant's crawled catalog is upserted as a whole unit keyed by
//! origin node - not decomposed into per-dataset rows - mirroring EDC's
//! choice to key the whole `Catalog` object graph by origin node URL.
//!
//! ## Intended future backend: Oxigraph
//!
//! A research spike in the `dataspace` study repo (`docs/spikes/`) surveyed
//! the available Rust RDF/quad-store crates against this trait's shape -
//! a named-graph quad store, one graph per
//! crawled source-node IRI, upserted wholesale on crawl, removed via an
//! explicit delete - and recommended **[Oxigraph](https://crates.io/crates/oxigraph)**
//! as the eventual backend:
//!
//! - It is the only surveyed candidate that both matches the shape (named
//!   graphs, full SPARQL 1.1 Query/Update/Federated Query) and has a
//!   maturity track record to build on now: ~8 years old, actively
//!   maintained, ~700k crates.io downloads, dual Apache-2.0/MIT, with a
//!   persistent RocksDB-backed store.
//! - `cool-japan/oxirs` is the closer long-term architectural fit
//!   (async-native, purpose-built on-disk format, also named-graph
//!   capable) but at spike time was a 14-month-old, effectively
//!   single-maintainer workspace whose persistent backend had shipped only
//!   five weeks earlier, with unaudited test/scale claims - not a
//!   foundation to bet this rewrite's first concrete cache backend on.
//! - No other surveyed crate (Sophia, terminusdb-store, hdt, Grafeo,
//!   kglite, rust-rdftk) beat Oxigraph on the combination of shape-fit and
//!   maturity.
//!
//! ## Implemented backend: `oxigraph_backend`, on top of `contreforts-kg`
//!
//! [`oxigraph_backend::OxigraphCatalogCache`] is the real Oxigraph-backed
//! implementation the section above anticipated. It is built on
//! [`contreforts-kg`](https://labs.deepthought-solutions.net/contreforts/contreforts-kg),
//! an existing, actively-maintained internal Oxigraph wrapper
//! (`GraphStore` / `QueryEngine`) from a separate private repo the same
//! owner controls, rather than depending on the bare `oxigraph` crate's
//! `Store` directly. That is a deliberate choice, not an oversight: it
//! reuses store-open, named-graph insert/remove, and SPARQL-evaluation
//! plumbing that already exists and is exercised elsewhere, instead of
//! re-implementing it from scratch here. The tradeoff accepted for that
//! reuse is a coupling to a private, different-domain (knowledge-graph
//! tooling, not dataspaces) repo, vendored as a git submodule (see
//! `vendor/README.md`) - acceptable because `contreforts-kg` is a thin
//! wrapper (this crate still depends on `oxigraph` directly too, pinned to
//! the same `"0.5"` range, to construct `NamedNode`/`Literal`/`Term`
//! values), not because the coupling itself is free.
//!
//! The quad mapping has moved past the original "first cut" blob-JSON
//! bridge (one opaque `catalogJson` literal per graph) to a real RDF
//! decomposition: `Catalog`/`Dataset`/`Distribution`/`DataService` each
//! become their own resource, related by real DCAT object properties, per
//! gap analysis §3.2 (`docs/gap-analysis-2026-08-27.md`). See
//! [`oxigraph_backend`]'s module doc for the exact subject/predicate/object
//! mapping - the ADR-equivalent record this doc comment previously
//! deferred to. `catalog-core::Dataset` still has no ODRL `Offer`/`Policy`
//! field (gap analysis §3.4), so no ODRL triples are emitted yet; that
//! remains future work; not guessed at here.

use async_trait::async_trait;
use catalog_core::{Catalog, NodeId};
use thiserror::Error;

/// Errors a [`CatalogCache`] backend can report.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("catalog store backend error: {0}")]
    Backend(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// A query over stored catalogs.
///
/// Deliberately minimal - a from-scratch analogue of EDC's `QuerySpec`,
/// sized to what the in-memory backend here can serve. A real RDF backend
/// will likely need a richer query shape (e.g. SPARQL passthrough); that
/// is expected to extend or replace this type, not be forced through it.
#[derive(Debug, Clone, Default)]
pub struct CatalogQuery {
    pub origin_node: Option<NodeId>,
    pub offset: usize,
    pub limit: Option<usize>,
}

impl CatalogQuery {
    /// No filter, no offset, no limit.
    pub fn all() -> Self {
        Self::default()
    }

    /// Only the catalog crawled from `node`, if any.
    pub fn for_node(node: NodeId) -> Self {
        Self {
            origin_node: Some(node),
            ..Self::default()
        }
    }
}

/// Storage for crawled catalogs, one named graph per origin node.
///
/// Implementations must be safe to share across crawl tasks (`Send +
/// Sync`) since a real crawler runs multiple concurrent fetches.
#[async_trait]
pub trait CatalogCache: Send + Sync {
    /// Insert or replace the named graph for `catalog.origin_node`.
    ///
    /// Re-crawling the same node always overwrites its prior catalog
    /// wholesale, matching EDC's upsert-by-origin-node-url behavior.
    async fn upsert(&self, catalog: Catalog) -> StoreResult<()>;

    /// Return stored catalogs matching `query`.
    async fn query(&self, query: CatalogQuery) -> StoreResult<Vec<Catalog>>;

    /// Remove the named graph for `node`, if present.
    ///
    /// Returns `true` if a catalog was actually removed.
    async fn delete(&self, node: &NodeId) -> StoreResult<bool>;
}

/// A simple, non-persistent [`CatalogCache`] backed by an in-process map.
///
/// This exists so `ds-catalog-broker-rs` (and this crate's own tests) have something
/// to run against while the real RDF-backed implementation is chosen; it
/// is not intended to be the production backend.
pub mod memory {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    #[derive(Default)]
    pub struct InMemoryCatalogCache {
        graphs: RwLock<HashMap<NodeId, Catalog>>,
    }

    impl InMemoryCatalogCache {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl CatalogCache for InMemoryCatalogCache {
        async fn upsert(&self, catalog: Catalog) -> StoreResult<()> {
            let mut graphs = self.graphs.write().await;
            graphs.insert(catalog.origin_node.clone(), catalog);
            Ok(())
        }

        async fn query(&self, query: CatalogQuery) -> StoreResult<Vec<Catalog>> {
            let graphs = self.graphs.read().await;
            let mut results: Vec<Catalog> = graphs
                .values()
                .filter(|catalog| match &query.origin_node {
                    Some(node) => &catalog.origin_node == node,
                    None => true,
                })
                .cloned()
                .collect();
            // Deterministic ordering: HashMap iteration order isn't
            // stable, and callers (e.g. ds-catalog-broker-rs) need reproducible
            // pagination.
            results.sort_by(|a, b| a.id.cmp(&b.id));

            let skipped = results.into_iter().skip(query.offset);
            let limited: Vec<Catalog> = match query.limit {
                Some(limit) => skipped.take(limit).collect(),
                None => skipped.collect(),
            };
            Ok(limited)
        }

        async fn delete(&self, node: &NodeId) -> StoreResult<bool> {
            let mut graphs = self.graphs.write().await;
            Ok(graphs.remove(node).is_some())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sample_catalog(node: &str, id: &str) -> Catalog {
            Catalog::new(id, NodeId::new(node))
        }

        #[tokio::test]
        async fn upsert_then_query_all_returns_it() {
            let cache = InMemoryCatalogCache::new();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-1");
        }

        #[tokio::test]
        async fn upsert_replaces_prior_catalog_for_same_node() {
            let cache = InMemoryCatalogCache::new();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-1", "cat-2"))
                .await
                .unwrap();

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-2");
        }

        #[tokio::test]
        async fn query_for_node_filters_by_origin() {
            let cache = InMemoryCatalogCache::new();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-2", "cat-2"))
                .await
                .unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-2")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-2");
        }

        #[tokio::test]
        async fn query_respects_offset_and_limit() {
            let cache = InMemoryCatalogCache::new();
            for i in 0..5 {
                cache
                    .upsert(sample_catalog(&format!("node-{i}"), &format!("cat-{i}")))
                    .await
                    .unwrap();
            }

            let results = cache
                .query(CatalogQuery {
                    origin_node: None,
                    offset: 2,
                    limit: Some(2),
                })
                .await
                .unwrap();
            assert_eq!(
                results.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
                vec!["cat-2", "cat-3"]
            );
        }

        #[tokio::test]
        async fn delete_removes_catalog_and_reports_result() {
            let cache = InMemoryCatalogCache::new();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let removed = cache.delete(&NodeId::new("node-1")).await.unwrap();
            assert!(removed);

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert!(results.is_empty());

            let removed_again = cache.delete(&NodeId::new("node-1")).await.unwrap();
            assert!(!removed_again);
        }
    }
}

/// A real, Oxigraph-backed [`CatalogCache`], built on `contreforts-kg`'s
/// `GraphStore` rather than the bare `oxigraph` crate's `Store` directly.
///
/// See this module's own doc comment above ("Implemented backend") for why
/// `contreforts-kg` rather than raw `oxigraph`.
///
/// ## Quad mapping (real RDF decomposition - gap analysis §3.2)
///
/// Reuses [DCAT](http://www.w3.org/ns/dcat#) terms wherever a genuine DCAT
/// property/class fits `catalog-core`'s domain model, matching the
/// Dataspace Protocol's own stated approach ("The Catalog Protocol reuses
/// properties from the DCAT and ODRL vocabularies" - `catalog.protocol.md`,
/// "Introduction"). One non-DCAT/ODRL term is reused for the same reason:
/// [Dublin Core Terms](http://purl.org/dc/terms/)' `dct:format`, which is
/// what DCAT/DSP tooling itself actually uses for a `Distribution`'s
/// format (including the real DSP `2025-1` JSON-LD context, which maps its
/// `format` term to `dct:format` - confirmed against this project's own,
/// now-removed `http-api` DSP layer, whose `DspDistribution.format` field
/// serialized under that same context). Everything else with no DCAT/ODRL
/// (or DCTERMS) equivalent falls back to this project's own
/// `https://federated-catalog-rs.internal/ns#` namespace.
///
/// **No ODRL terms are emitted.** `catalog-core::Dataset` has no `Offer`/
/// `Policy` field at all today (see its own doc comment, and gap analysis
/// §3.4) - the only DSP `Offer`/`hasPolicy` representation that ever
/// existed in this codebase was a hardcoded placeholder in the now-removed
/// `http-api` DSP-serving layer, not data derived from anything a crawled
/// participant actually said. Inventing an ODRL shape here to have
/// *something* to point `odrl:` constants at would be exactly the "guess
/// at policy semantics" gap analysis §3.4 explicitly says not to do. What
/// *does* exist in the domain model - `Catalog.properties` and
/// `Dataset.properties` - is faithfully preserved as real triples (see
/// "Generic properties" below), so if a future crawler starts stuffing
/// policy-relevant data into those maps, it already round-trips; it is
/// just not yet modeled as `odrl:Offer`/`odrl:Policy` resources.
///
/// ### Namespaces
///
/// | Prefix | IRI |
/// |---|---|
/// | `dcat:` | `http://www.w3.org/ns/dcat#` |
/// | `dct:` | `http://purl.org/dc/terms/` |
/// | `rdf:` | `http://www.w3.org/1999/02/22-rdf-syntax-ns#` |
/// | `fcns:` (fallback) | `https://federated-catalog-rs.internal/ns#` |
///
/// ### Resource IRIs
///
/// For an origin node whose [`NodeId`] is `<node>` (percent-encoded
/// throughout, so any character the id contains still yields a valid
/// IRI), let `<base>` = `https://federated-catalog-rs.internal/nodes/<node>`:
///
/// - **Named graph** (one per origin node, matching the trait's contract):
///   `<base>`.
/// - **Catalog resource**: `<base>/catalogs/<catalog.id>`.
/// - **Dataset resource**: `<base>/datasets/<dataset.id>`.
/// - **Distribution resource**: `<base>/datasets/<dataset.id>/distributions/<index>`
///   - a distribution has no id of its own in the domain model, so it is
///     identified by its position in `dataset.distributions` instead of a
///     blank node (predictable, queryable IRIs beat blank nodes here, and
///     the index doubles as the ordering key - see "Ordering" below).
/// - **DataService resource**: `<base>/services/<data_service.id>`.
///
/// `Distribution.access_service` is a bare `String` in the domain model,
/// not a typed foreign key - it is resolved to a DataService resource IRI
/// using the exact same `<base>/services/<id>` scheme a real `DataService`
/// would get, so a distribution whose `access_service` matches a data
/// service actually present in the same catalog naturally points at that
/// same resource. A dangling reference (no such service) still round-trips
/// correctly: decoding only ever needs to strip the known prefix and
/// percent-decode the remainder, it never requires the target to exist.
///
/// ### Triples emitted, subject/predicate/object
///
/// For catalog resource `<catalog>`:
/// - `<catalog> rdf:type dcat:Catalog .`
/// - `<catalog> fcns:participantId "<participant_id>"` - only if
///   `Catalog.participant_id` is `Some`. DSP's own `participantId` is a
///   dataspace-specific concept with no DCAT/ODRL equivalent, so it falls
///   back to this project's own namespace per the rule above.
/// - `<catalog> dcat:dataset <dataset> .` - one per `Catalog.datasets`
///   entry (`dcat:dataset` is DCAT's real Catalog-to-Dataset property).
/// - `<catalog> dcat:service <service> .` - one per `Catalog.data_services`
///   entry (`dcat:service`, DCAT3's real Catalog-to-DataService property).
/// - `<catalog> <property-predicate> "<value>"` - one per
///   `Catalog.properties` entry; see "Generic properties" below.
///
/// For each dataset resource `<dataset>` (from `Catalog.datasets`):
/// - `<dataset> rdf:type dcat:Dataset .`
/// - `<dataset> fcns:sequenceIndex "<index>"^^xsd:integer .` - see
///   "Ordering" below.
/// - `<dataset> dcat:distribution <distribution> .` - one per
///   `Dataset.distributions` entry (`dcat:distribution` is DCAT's real
///   Dataset-to-Distribution property).
/// - `<dataset> <property-predicate> "<value>"` - one per
///   `Dataset.properties` entry; see "Generic properties" below.
///
/// For each distribution resource `<distribution>` (from
/// `Dataset.distributions`):
/// - `<distribution> rdf:type dcat:Distribution .`
/// - `<distribution> fcns:sequenceIndex "<index>"^^xsd:integer .`
/// - `<distribution> dct:format "<format>" .`
/// - `<distribution> dcat:accessService <service> .` - `<service>` is the
///   `<base>/services/<access_service>` IRI described above (`dcat:accessService`
///   is DCAT's real Distribution-to-DataService property).
///
/// For each data service resource `<service>` (from `Catalog.data_services`):
/// - `<service> rdf:type dcat:DataService .`
/// - `<service> fcns:sequenceIndex "<index>"^^xsd:integer .`
/// - `<service> dcat:endpointURL <endpoint_url>` (or, if `endpoint_url`
///   does not parse as a valid IRI - untrusted crawled data, not something
///   this store should reject - `"<endpoint_url>"` as a plain literal
///   instead). DCAT defines `dcat:endpointURL`'s range as `rdfs:Resource`,
///   i.e. an IRI, not a literal; since the domain field already holds a
///   URL string, minting it as the object IRI directly (rather than
///   wrapping it in a literal) is the more faithful reading of the real
///   DCAT term.
/// - `<service> dcat:endpointDescription "<endpoint_description>"` - only
///   if `DataService.endpoint_description` is `Some`. Stored as a plain
///   literal rather than an IRI even though DCAT's formal range for this
///   property is also `rdfs:Resource`: this domain field holds free text
///   (e.g. `"dataspace-protocol-http:1.0"`, see `seed_sample_catalog`), not
///   a URL, and DCAT's own usage note allows literal values in practice.
///
/// ### Generic properties (`Catalog.properties` / `Dataset.properties`)
///
/// `catalog-core`'s `properties: BTreeMap<String, String>` is an arbitrary
/// key/value bag - EDC's `Dataset`/`Asset` have the same shape, keyed by
/// whatever property IRI or name the source used. Each entry becomes
/// exactly one triple, `<resource> <predicate> "<value>"`, where
/// `<predicate>` is:
/// - the key itself, reused as-is, **if** it already parses as an absolute
///   IRI (so a crawler that already normalized a key to a real vocabulary
///   term - e.g. `http://www.w3.org/ns/dcat#keyword` - gets a genuine
///   triple using that term, not a synthesized one); otherwise
/// - `fcns:property/<percent-encoded key>` - the documented fallback.
///
/// No crawler populates `properties` today (`crawler::parse_catalog_response`
/// leaves it `Default::default()`), so this path is exercised only by
/// direct `CatalogCache::upsert` callers and this module's own tests - but
/// whatever ends up in that map, including any future policy-relevant
/// data, is faithfully represented as a triple, never silently dropped.
///
/// **Known limitation, not exercised by any current producer**: a
/// property key that happens to be exactly one of this mapping's own
/// reserved predicate IRIs (`rdf:type`, `dcat:dataset`, `dcat:service`,
/// `dcat:distribution`, `dcat:accessService`, `dcat:endpointURL`,
/// `dcat:endpointDescription`, `dct:format`, `fcns:participantId`,
/// `fcns:sequenceIndex`) would collide with this mapping's own structural
/// triples. Flagged rather than defended against, since nothing produces
/// such a key today.
///
/// ### Ordering (`fcns:sequenceIndex`)
///
/// `Catalog.datasets`, `Dataset.distributions`, and `Catalog.data_services`
/// are all `Vec`s - order (and, for distributions, even exact duplicates)
/// is part of `Catalog`'s `PartialEq`, but RDF triples are an unordered
/// set. Each dataset/distribution/data-service resource therefore carries
/// an explicit `fcns:sequenceIndex` integer literal recording its original
/// position, and `query()` sorts by it when reconstructing each `Vec` -
/// this is pure bookkeeping to make an ordered domain type round-trip
/// through an unordered store faithfully, not domain data, hence the
/// fallback namespace rather than a borrowed vocabulary term (DCAT has no
/// concept of dataset/distribution ordering).
///
/// This also implicitly assumes `Dataset.id` (and `DataService.id`) are
/// unique within one catalog: two datasets sharing an id would collide
/// onto the same `<base>/datasets/<id>` resource. This mirrors real DSP
/// semantics (a JSON-LD node's `@id` is inherently unique - that is what
/// `@id` means) and is not otherwise enforced by `catalog-core::Dataset`.
pub mod oxigraph_backend {
    use super::*;
    use catalog_core::{DataService, Dataset, Distribution};
    use contreforts_kg::GraphError;
    use contreforts_kg::store::GraphStore;
    use oxigraph::model::{Literal, NamedNode, NamedOrBlankNode, Quad, Term};
    use oxigraph::sparql::results::{QueryResultsFormat, QueryResultsSerializer};
    use oxigraph::sparql::{QueryResults, SparqlEvaluator};
    use oxigraph::store::StorageError;
    use std::collections::BTreeMap;
    use std::path::Path;

    const NODE_NS: &str = "https://federated-catalog-rs.internal/nodes/";
    const INTERNAL_NS: &str = "https://federated-catalog-rs.internal/ns#";
    const INTERNAL_PROPERTY_PREFIX: &str = "https://federated-catalog-rs.internal/ns#property/";
    const DCAT_NS: &str = "http://www.w3.org/ns/dcat#";
    const DCT_NS: &str = "http://purl.org/dc/terms/";
    const RDF_TYPE_IRI: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

    impl From<GraphError> for StoreError {
        fn from(err: GraphError) -> Self {
            StoreError::Backend(err.to_string())
        }
    }

    impl From<StorageError> for StoreError {
        fn from(err: StorageError) -> Self {
            StoreError::Backend(err.to_string())
        }
    }

    /// Errors specific to evaluating an arbitrary SPARQL query through
    /// [`OxigraphCatalogCache::sparql_query_json`] - kept distinct from
    /// [`StoreError`] because these are about a caller-supplied query
    /// string (usually the caller's own fault: bad syntax, an
    /// unsupported query form), not about the store itself.
    #[derive(Debug, Error)]
    pub enum SparqlError {
        /// The query string failed to parse as a SPARQL **Query** (the
        /// `SELECT`/`ASK`/`CONSTRUCT`/`DESCRIBE` grammar). This is also
        /// what happens for a SPARQL **Update** operation submitted here
        /// (`INSERT DATA`, `DELETE`, `LOAD`, `CLEAR`, ...): those belong to
        /// a different grammar entirely, one this method never parses
        /// with (see the method's own doc comment on why that alone is
        /// the read-only guarantee, not a separate check bolted on after).
        #[error("invalid SPARQL query: {0}")]
        Parse(String),
        /// The query parsed but failed during evaluation (e.g. a type
        /// error in a `FILTER` expression).
        #[error("SPARQL query evaluation failed: {0}")]
        Evaluation(String),
        /// The query was a well-formed `CONSTRUCT`/`DESCRIBE` - this
        /// method only serializes `SELECT`/`ASK` results (the gap
        /// analysis's stated minimum), since a graph result needs a
        /// different response media type (an RDF serialization, not
        /// `application/sparql-results+json`) that is out of scope here.
        #[error(
            "CONSTRUCT/DESCRIBE queries are not supported by this endpoint - only SELECT and ASK are"
        )]
        UnsupportedGraphResult,
        /// Writing the (already-evaluated) result set as
        /// `application/sparql-results+json` failed. Distinguished from
        /// `Evaluation` because a query that reaches this point already
        /// evaluated successfully - a failure here points at the
        /// serializer/writer, not at the caller's query.
        #[error("failed to serialize SPARQL results: {0}")]
        Serialize(String),
    }

    pub type SparqlQueryResult<T> = Result<T, SparqlError>;

    // --- Fixed vocabulary terms -------------------------------------------------
    //
    // Constructed on demand rather than cached in a `static` - cheap to build,
    // and keeps this module free of `lazy_static`/`OnceLock` machinery for a
    // handful of constant IRIs, matching the style the JSON-blob version of
    // this module used for its own single `catalogJson` predicate.

    fn iri(value: impl Into<String>) -> NamedNode {
        NamedNode::new(value).expect("constant/percent-encoded IRI is valid")
    }

    fn dcat(local: &str) -> NamedNode {
        iri(format!("{DCAT_NS}{local}"))
    }

    fn dct(local: &str) -> NamedNode {
        iri(format!("{DCT_NS}{local}"))
    }

    fn internal(local: &str) -> NamedNode {
        iri(format!("{INTERNAL_NS}{local}"))
    }

    fn rdf_type() -> NamedNode {
        iri(RDF_TYPE_IRI)
    }

    fn dcat_catalog_class() -> NamedNode {
        dcat("Catalog")
    }

    fn dcat_dataset_class() -> NamedNode {
        dcat("Dataset")
    }

    fn dcat_distribution_class() -> NamedNode {
        dcat("Distribution")
    }

    fn dcat_data_service_class() -> NamedNode {
        dcat("DataService")
    }

    fn dcat_dataset_pred() -> NamedNode {
        dcat("dataset")
    }

    fn dcat_service_pred() -> NamedNode {
        dcat("service")
    }

    fn dcat_distribution_pred() -> NamedNode {
        dcat("distribution")
    }

    fn dcat_access_service_pred() -> NamedNode {
        dcat("accessService")
    }

    fn dcat_endpoint_url_pred() -> NamedNode {
        dcat("endpointURL")
    }

    fn dcat_endpoint_description_pred() -> NamedNode {
        dcat("endpointDescription")
    }

    fn dct_format_pred() -> NamedNode {
        dct("format")
    }

    fn participant_id_pred() -> NamedNode {
        internal("participantId")
    }

    fn sequence_index_pred() -> NamedNode {
        internal("sequenceIndex")
    }

    /// The key/value-property fallback predicate for a key that isn't
    /// already an absolute IRI - see the module doc's "Generic properties".
    fn property_predicate(key: &str) -> NamedNode {
        if let Ok(existing) = NamedNode::new(key) {
            existing
        } else {
            iri(format!(
                "{INTERNAL_PROPERTY_PREFIX}{}",
                urlencoding::encode(key)
            ))
        }
    }

    /// Inverse of [`property_predicate`]: recover the original property key
    /// from a predicate IRI.
    fn decode_property_key(pred: &NamedNode) -> String {
        match pred.as_str().strip_prefix(INTERNAL_PROPERTY_PREFIX) {
            Some(rest) => urlencoding::decode(rest)
                .map(|cow| cow.into_owned())
                .unwrap_or_else(|_| rest.to_string()),
            None => pred.as_str().to_string(),
        }
    }

    // --- Resource IRI construction ----------------------------------------------

    /// The base IRI for `node`'s named graph, also the prefix every
    /// resource IRI within that graph is built from. Percent-encoding the
    /// node id guarantees a valid IRI regardless of what characters the id
    /// contains.
    fn node_base(node: &NodeId) -> String {
        format!("{NODE_NS}{}", urlencoding::encode(&node.0))
    }

    /// The subject / named-graph IRI for `node`.
    fn node_iri(node: &NodeId) -> NamedNode {
        iri(node_base(node))
    }

    fn catalog_iri(node_base: &str, catalog_id: &str) -> NamedNode {
        iri(format!(
            "{node_base}/catalogs/{}",
            urlencoding::encode(catalog_id)
        ))
    }

    fn dataset_iri(node_base: &str, dataset_id: &str) -> NamedNode {
        iri(format!(
            "{node_base}/datasets/{}",
            urlencoding::encode(dataset_id)
        ))
    }

    fn distribution_iri(node_base: &str, dataset_id: &str, index: usize) -> NamedNode {
        iri(format!(
            "{node_base}/datasets/{}/distributions/{index}",
            urlencoding::encode(dataset_id)
        ))
    }

    fn service_iri(node_base: &str, service_id: &str) -> NamedNode {
        iri(format!(
            "{node_base}/services/{}",
            urlencoding::encode(service_id)
        ))
    }

    /// Strip `prefix` off `iri` and percent-decode the remainder - the
    /// inverse of how every resource IRI above was built from an id.
    fn strip_prefix_decode(iri: &str, prefix: &str) -> StoreResult<String> {
        let rest = iri.strip_prefix(prefix).ok_or_else(|| {
            StoreError::Backend(format!("expected IRI '{iri}' to start with '{prefix}'"))
        })?;
        urlencoding::decode(rest)
            .map(|cow| cow.into_owned())
            .map_err(|e| StoreError::Backend(format!("invalid percent-encoding in '{iri}': {e}")))
    }

    fn decode_node_id(graph_iri: &NamedNode) -> StoreResult<NodeId> {
        strip_prefix_decode(graph_iri.as_str(), NODE_NS).map(NodeId::new)
    }

    /// `endpoint_url` as an IRI object when it parses as one (the faithful
    /// DCAT reading of `dcat:endpointURL`'s `rdfs:Resource` range), falling
    /// back to a plain string literal when it doesn't - defensive, since
    /// this string comes from crawled data this store should never reject.
    fn endpoint_url_term(endpoint_url: &str) -> Term {
        match NamedNode::new(endpoint_url) {
            Ok(node) => Term::from(node),
            Err(_) => Term::from(Literal::from(endpoint_url.to_string())),
        }
    }

    /// A literal's lexical value, or a `NamedNode`'s IRI string - covers
    /// both shapes [`endpoint_url_term`] can produce, so loading is
    /// agnostic to which one a given stored value took.
    fn term_as_string(term: &Term) -> StoreResult<String> {
        match term {
            Term::Literal(lit) => Ok(lit.value().to_string()),
            Term::NamedNode(node) => Ok(node.as_str().to_string()),
            other => Err(StoreError::Backend(format!(
                "expected a literal or IRI term, got {other:?}"
            ))),
        }
    }

    fn expect_named_node(term: Term, context: &str) -> StoreResult<NamedNode> {
        match term {
            Term::NamedNode(node) => Ok(node),
            other => Err(StoreError::Backend(format!(
                "expected a named node for {context}, got {other:?}"
            ))),
        }
    }

    /// A [`CatalogCache`] backed by a real `contreforts_kg::store::GraphStore`
    /// (Oxigraph under the hood).
    pub struct OxigraphCatalogCache {
        store: GraphStore,
    }

    impl OxigraphCatalogCache {
        /// Wrap an in-memory Oxigraph store. Useful for tests, and for any
        /// caller that wants the real RDF/SPARQL machinery without
        /// persistence.
        pub fn in_memory() -> StoreResult<Self> {
            let store = GraphStore::in_memory()?;
            Ok(Self { store })
        }

        /// Open (or create) a persistent Oxigraph store at `path`.
        pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
            let store = GraphStore::open(path)?;
            Ok(Self { store })
        }

        /// Quads matching the given pattern, always scoped to `graph` -
        /// every read this backend does is graph-scoped, so `graph` is a
        /// required parameter here rather than another `Option`.
        fn quads(
            &self,
            subject: Option<&NamedNode>,
            predicate: Option<&NamedNode>,
            object: Option<&Term>,
            graph: &NamedNode,
        ) -> StoreResult<Vec<Quad>> {
            self.store
                .inner()
                .quads_for_pattern(
                    subject.map(|s| s.into()),
                    predicate.map(|p| p.into()),
                    object.map(|o| o.into()),
                    Some(graph.into()),
                )
                .collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)
        }

        /// The first object found for `(subject, predicate, ?, graph)`, if
        /// any.
        fn first_object(
            &self,
            subject: &NamedNode,
            predicate: &NamedNode,
            graph: &NamedNode,
        ) -> StoreResult<Option<Term>> {
            Ok(self
                .quads(Some(subject), Some(predicate), None, graph)?
                .into_iter()
                .next()
                .map(|quad| quad.object))
        }

        fn sequence_index(&self, subject: &NamedNode, graph: &NamedNode) -> StoreResult<usize> {
            let term = self
                .first_object(subject, &sequence_index_pred(), graph)?
                .ok_or_else(|| {
                    StoreError::Backend(format!("{} is missing fcns:sequenceIndex", subject.as_str()))
                })?;
            match term {
                Term::Literal(lit) => lit
                    .value()
                    .parse::<usize>()
                    .map_err(|e| StoreError::Backend(format!("invalid sequenceIndex: {e}"))),
                other => Err(StoreError::Backend(format!(
                    "sequenceIndex must be a literal, got {other:?}"
                ))),
            }
        }

        /// Whether `graph` currently holds any quad at all.
        fn graph_nonempty(&self, graph: &NamedNode) -> StoreResult<bool> {
            Ok(!self.quads(None, None, None, graph)?.is_empty())
        }

        /// Remove every quad in `graph`, regardless of subject - the
        /// "replace wholesale" half of `upsert`, and all of `delete`.
        fn clear_named_graph(&self, graph: &NamedNode) -> StoreResult<()> {
            self.store.inner().remove_named_graph(graph)?;
            Ok(())
        }

        fn insert(
            &self,
            subject: &NamedNode,
            predicate: &NamedNode,
            object: &Term,
            graph: &NamedNode,
        ) -> StoreResult<()> {
            self.store
                .insert_in_named_graph(subject, predicate, object, graph)?;
            Ok(())
        }

        /// Write every triple for `catalog` into `graph` - see this
        /// module's own doc comment for the exact mapping.
        fn write_catalog(&self, catalog: &Catalog, graph: &NamedNode) -> StoreResult<()> {
            let base = node_base(&catalog.origin_node);
            let catalog_node = catalog_iri(&base, &catalog.id);

            self.insert(&catalog_node, &rdf_type(), &Term::from(dcat_catalog_class()), graph)?;

            if let Some(participant_id) = &catalog.participant_id {
                self.insert(
                    &catalog_node,
                    &participant_id_pred(),
                    &Term::from(Literal::from(participant_id.clone())),
                    graph,
                )?;
            }

            for (key, value) in &catalog.properties {
                self.insert(
                    &catalog_node,
                    &property_predicate(key),
                    &Term::from(Literal::from(value.clone())),
                    graph,
                )?;
            }

            for (index, dataset) in catalog.datasets.iter().enumerate() {
                let dataset_node = dataset_iri(&base, &dataset.id);
                self.insert(
                    &catalog_node,
                    &dcat_dataset_pred(),
                    &Term::from(dataset_node.clone()),
                    graph,
                )?;
                self.insert(&dataset_node, &rdf_type(), &Term::from(dcat_dataset_class()), graph)?;
                self.insert(
                    &dataset_node,
                    &sequence_index_pred(),
                    &Term::from(Literal::from(index as i64)),
                    graph,
                )?;

                for (key, value) in &dataset.properties {
                    self.insert(
                        &dataset_node,
                        &property_predicate(key),
                        &Term::from(Literal::from(value.clone())),
                        graph,
                    )?;
                }

                for (dist_index, distribution) in dataset.distributions.iter().enumerate() {
                    let distribution_node = distribution_iri(&base, &dataset.id, dist_index);
                    self.insert(
                        &dataset_node,
                        &dcat_distribution_pred(),
                        &Term::from(distribution_node.clone()),
                        graph,
                    )?;
                    self.insert(
                        &distribution_node,
                        &rdf_type(),
                        &Term::from(dcat_distribution_class()),
                        graph,
                    )?;
                    self.insert(
                        &distribution_node,
                        &sequence_index_pred(),
                        &Term::from(Literal::from(dist_index as i64)),
                        graph,
                    )?;
                    self.insert(
                        &distribution_node,
                        &dct_format_pred(),
                        &Term::from(Literal::from(distribution.format.clone())),
                        graph,
                    )?;
                    let access_service_node = service_iri(&base, &distribution.access_service);
                    self.insert(
                        &distribution_node,
                        &dcat_access_service_pred(),
                        &Term::from(access_service_node),
                        graph,
                    )?;
                }
            }

            for (index, service) in catalog.data_services.iter().enumerate() {
                let service_node = service_iri(&base, &service.id);
                self.insert(
                    &catalog_node,
                    &dcat_service_pred(),
                    &Term::from(service_node.clone()),
                    graph,
                )?;
                self.insert(&service_node, &rdf_type(), &Term::from(dcat_data_service_class()), graph)?;
                self.insert(
                    &service_node,
                    &sequence_index_pred(),
                    &Term::from(Literal::from(index as i64)),
                    graph,
                )?;
                self.insert(
                    &service_node,
                    &dcat_endpoint_url_pred(),
                    &endpoint_url_term(&service.endpoint_url),
                    graph,
                )?;
                if let Some(description) = &service.endpoint_description {
                    self.insert(
                        &service_node,
                        &dcat_endpoint_description_pred(),
                        &Term::from(Literal::from(description.clone())),
                        graph,
                    )?;
                }
            }

            Ok(())
        }

        /// Reconstruct the [`Catalog`] stored in `graph` for `node`, if any
        /// (`None` when the graph holds no `dcat:Catalog` resource at all -
        /// i.e. nothing has ever been upserted for this node).
        fn load_catalog(&self, node: &NodeId, graph: &NamedNode) -> StoreResult<Option<Catalog>> {
            let base = node_base(node);
            let catalog_class_term = Term::from(dcat_catalog_class());
            let type_pred = rdf_type();

            let Some(first) = self
                .quads(None, Some(&type_pred), Some(&catalog_class_term), graph)?
                .into_iter()
                .next()
            else {
                return Ok(None);
            };
            let catalog_subject = match first.subject {
                NamedOrBlankNode::NamedNode(node) => node,
                NamedOrBlankNode::BlankNode(_) => {
                    return Err(StoreError::Backend(
                        "catalog subject must be a named node".to_string(),
                    ));
                }
            };
            let catalog_id = strip_prefix_decode(catalog_subject.as_str(), &format!("{base}/catalogs/"))?;

            let participant_id = self
                .first_object(&catalog_subject, &participant_id_pred(), graph)?
                .as_ref()
                .map(term_as_string)
                .transpose()?;

            let dataset_pred = dcat_dataset_pred();
            let service_pred = dcat_service_pred();

            let reserved_catalog_preds = [
                type_pred.clone(),
                participant_id_pred(),
                dataset_pred.clone(),
                service_pred.clone(),
            ];
            let mut properties = BTreeMap::new();
            for quad in self.quads(Some(&catalog_subject), None, None, graph)? {
                if reserved_catalog_preds.contains(&quad.predicate) {
                    continue;
                }
                properties.insert(decode_property_key(&quad.predicate), term_as_string(&quad.object)?);
            }

            let mut dataset_entries = Vec::new();
            for quad in self.quads(Some(&catalog_subject), Some(&dataset_pred), None, graph)? {
                let dataset_subject = expect_named_node(quad.object, "a dcat:dataset reference")?;
                dataset_entries.push(self.load_dataset(&base, &dataset_subject, graph)?);
            }
            dataset_entries.sort_by_key(|(index, _)| *index);
            let datasets = dataset_entries.into_iter().map(|(_, dataset)| dataset).collect();

            let mut service_entries = Vec::new();
            for quad in self.quads(Some(&catalog_subject), Some(&service_pred), None, graph)? {
                let service_subject = expect_named_node(quad.object, "a dcat:service reference")?;
                service_entries.push(self.load_data_service(&base, &service_subject, graph)?);
            }
            service_entries.sort_by_key(|(index, _)| *index);
            let data_services = service_entries.into_iter().map(|(_, service)| service).collect();

            Ok(Some(Catalog {
                id: catalog_id,
                origin_node: node.clone(),
                participant_id,
                datasets,
                data_services,
                properties,
            }))
        }

        fn load_dataset(
            &self,
            base: &str,
            subject: &NamedNode,
            graph: &NamedNode,
        ) -> StoreResult<(usize, Dataset)> {
            let id = strip_prefix_decode(subject.as_str(), &format!("{base}/datasets/"))?;
            let index = self.sequence_index(subject, graph)?;
            let distribution_pred = dcat_distribution_pred();

            let mut distribution_entries = Vec::new();
            for quad in self.quads(Some(subject), Some(&distribution_pred), None, graph)? {
                let distribution_subject =
                    expect_named_node(quad.object, "a dcat:distribution reference")?;
                distribution_entries.push(self.load_distribution(base, &distribution_subject, graph)?);
            }
            distribution_entries.sort_by_key(|(index, _)| *index);
            let distributions = distribution_entries
                .into_iter()
                .map(|(_, distribution)| distribution)
                .collect();

            let reserved = [rdf_type(), sequence_index_pred(), distribution_pred];
            let mut properties = BTreeMap::new();
            for quad in self.quads(Some(subject), None, None, graph)? {
                if reserved.contains(&quad.predicate) {
                    continue;
                }
                properties.insert(decode_property_key(&quad.predicate), term_as_string(&quad.object)?);
            }

            Ok((
                index,
                Dataset {
                    id,
                    properties,
                    distributions,
                },
            ))
        }

        fn load_distribution(
            &self,
            base: &str,
            subject: &NamedNode,
            graph: &NamedNode,
        ) -> StoreResult<(usize, Distribution)> {
            let index = self.sequence_index(subject, graph)?;
            let format = self
                .first_object(subject, &dct_format_pred(), graph)?
                .as_ref()
                .map(term_as_string)
                .transpose()?
                .ok_or_else(|| {
                    StoreError::Backend(format!("{} is missing dct:format", subject.as_str()))
                })?;
            let access_service_term = self
                .first_object(subject, &dcat_access_service_pred(), graph)?
                .ok_or_else(|| {
                    StoreError::Backend(format!("{} is missing dcat:accessService", subject.as_str()))
                })?;
            let access_service_node =
                expect_named_node(access_service_term, "dcat:accessService's object")?;
            let access_service =
                strip_prefix_decode(access_service_node.as_str(), &format!("{base}/services/"))?;

            Ok((index, Distribution { format, access_service }))
        }

        fn load_data_service(
            &self,
            base: &str,
            subject: &NamedNode,
            graph: &NamedNode,
        ) -> StoreResult<(usize, DataService)> {
            let id = strip_prefix_decode(subject.as_str(), &format!("{base}/services/"))?;
            let index = self.sequence_index(subject, graph)?;
            let endpoint_url = self
                .first_object(subject, &dcat_endpoint_url_pred(), graph)?
                .as_ref()
                .map(term_as_string)
                .transpose()?
                .ok_or_else(|| {
                    StoreError::Backend(format!("{} is missing dcat:endpointURL", subject.as_str()))
                })?;
            let endpoint_description = self
                .first_object(subject, &dcat_endpoint_description_pred(), graph)?
                .as_ref()
                .map(term_as_string)
                .transpose()?;

            Ok((
                index,
                DataService {
                    id,
                    endpoint_url,
                    endpoint_description,
                },
            ))
        }

        /// Evaluate an arbitrary, caller-supplied SPARQL query and return
        /// the result serialized as
        /// [`application/sparql-results+json`](https://www.w3.org/TR/sparql11-results-json/)
        /// bytes - the HTTP surface in `ds-catalog-broker-rs` (gap analysis
        /// §3.3) writes these bytes straight through as the response body.
        ///
        /// ## Why this lives here, not on the `CatalogCache` trait
        ///
        /// SPARQL evaluation is an Oxigraph-specific capability with no
        /// equivalent in [`memory::InMemoryCatalogCache`] (a plain
        /// `HashMap`, not an RDF store at all) - forcing every backend to
        /// implement it would mean either a panic/`Err` stub on the
        /// in-memory side or inventing a query language the in-memory
        /// backend could actually serve, neither of which is worth it for
        /// a backend that exists only to unblock tests and the
        /// no-crawler-configured default (see this crate's module doc).
        /// So this is an inherent method on the concrete
        /// [`OxigraphCatalogCache`] type instead - additive, doesn't touch
        /// the trait's signature at all. The HTTP layer holds an
        /// `Option<Arc<OxigraphCatalogCache>>` alongside its
        /// `Arc<dyn CatalogCache>` and answers "SPARQL not available" (501)
        /// when it's `None`, i.e. whenever the in-memory backend is
        /// running.
        ///
        /// ## Why the whole store, not one named graph, by default
        ///
        /// A crawled catalog's triples live in a per-origin-node named
        /// graph (this module's own "Named graph" mapping above), not the
        /// default graph - so a plain `SELECT * WHERE { ?s ?p ?o }` with no
        /// `GRAPH` clause would, under SPARQL's normal rules, match only
        /// the (always-empty) default graph and never see any harvested
        /// data at all. That would silently defeat "search everything I've
        /// harvested", the primary use case the gap analysis calls out.
        /// Instead, whenever the query itself does not already specify its
        /// own dataset (no `FROM`/`FROM NAMED`, checked via
        /// `QueryDataset::is_default_dataset`), this method sets the
        /// query's default graph to the union of every named graph in the
        /// store (`QueryDataset::set_default_graph_as_union`) before
        /// executing it - so a plain triple pattern with no `GRAPH` clause
        /// searches every harvested participant's graph at once, which is
        /// what "the whole store" should mean here.
        ///
        /// A caller that wants to scope to one participant still can,
        /// without any bespoke query-param feature, via SPARQL's own
        /// `GRAPH <iri>` clause (the exact graph IRI scheme is documented
        /// above, under "Resource IRIs") - or via the query's own
        /// `FROM`/`FROM NAMED`, which this method leaves untouched when
        /// present (`is_default_dataset()` is only true when the query
        /// didn't specify one itself). That satisfies the gap analysis's
        /// stretch goal ("via SPARQL's own GRAPH clause... rather than a
        /// bespoke query-param feature") without any extra code here.
        ///
        /// ## Why this is inherently read-only
        ///
        /// This method only ever calls [`SparqlEvaluator::parse_query`],
        /// which parses the SPARQL 1.1 **Query** grammar
        /// (`SELECT`/`ASK`/`CONSTRUCT`/`DESCRIBE`) - never
        /// `SparqlEvaluator::parse_update` or `Store::update`, which is
        /// the only code path in `oxigraph` that can mutate a store via
        /// SPARQL. A SPARQL Update string (`INSERT DATA { ... }`,
        /// `DELETE ...`, `LOAD`, `CLEAR`, ...) simply fails to parse as a
        /// Query - it is not reachable through this method at all, not
        /// merely rejected after being recognized. See
        /// `sparql_update_operation_is_rejected_not_silently_ignored`
        /// below for a test proving this.
        ///
        /// ## Result shape
        ///
        /// - `ASK` -> `{"head":{},"boolean":<bool>}`.
        /// - `SELECT` -> `{"head":{"vars":[...]},"results":{"bindings":[...]}}`,
        ///   using `oxigraph`'s own `sparesults`-backed serializer, so IRI
        ///   vs. literal vs. blank node, datatypes, and language tags all
        ///   come out exactly per the W3C JSON Results spec - this method
        ///   never hand-rolls that format.
        /// - `CONSTRUCT`/`DESCRIBE` -> `Err(SparqlError::UnsupportedGraphResult)`,
        ///   see that variant's own doc comment.
        pub fn sparql_query_json(&self, query: &str) -> SparqlQueryResult<Vec<u8>> {
            let mut prepared = SparqlEvaluator::new()
                .parse_query(query)
                .map_err(|err| SparqlError::Parse(err.to_string()))?;

            if prepared.dataset().is_default_dataset() {
                prepared.dataset_mut().set_default_graph_as_union();
            }

            let results = prepared
                .on_store(self.store.inner())
                .execute()
                .map_err(|err| SparqlError::Evaluation(err.to_string()))?;

            let serializer = QueryResultsSerializer::from_format(QueryResultsFormat::Json);
            match results {
                QueryResults::Boolean(value) => serializer
                    .serialize_boolean_to_writer(Vec::new(), value)
                    .map_err(|err| SparqlError::Serialize(err.to_string())),
                QueryResults::Solutions(solutions) => {
                    let variables = solutions.variables().to_vec();
                    let mut writer = serializer
                        .serialize_solutions_to_writer(Vec::new(), variables)
                        .map_err(|err| SparqlError::Serialize(err.to_string()))?;
                    for solution in solutions {
                        let solution =
                            solution.map_err(|err| SparqlError::Evaluation(err.to_string()))?;
                        writer
                            .serialize(&solution)
                            .map_err(|err| SparqlError::Serialize(err.to_string()))?;
                    }
                    writer
                        .finish()
                        .map_err(|err| SparqlError::Serialize(err.to_string()))
                }
                QueryResults::Graph(_) => Err(SparqlError::UnsupportedGraphResult),
            }
        }
    }

    #[async_trait]
    impl CatalogCache for OxigraphCatalogCache {
        async fn upsert(&self, catalog: Catalog) -> StoreResult<()> {
            let graph = node_iri(&catalog.origin_node);
            // Insert-or-replace: clear any prior graph for this node first,
            // matching the in-memory impl's `HashMap::insert` overwrite
            // semantics (and EDC's upsert-by-origin-node-url behavior).
            self.clear_named_graph(&graph)?;
            self.write_catalog(&catalog, &graph)?;
            Ok(())
        }

        async fn query(&self, query: CatalogQuery) -> StoreResult<Vec<Catalog>> {
            let mut results: Vec<Catalog> = Vec::new();

            match &query.origin_node {
                Some(node) => {
                    let graph = node_iri(node);
                    if let Some(catalog) = self.load_catalog(node, &graph)? {
                        results.push(catalog);
                    }
                }
                None => {
                    let graph_names: Vec<NamedOrBlankNode> = self
                        .store
                        .inner()
                        .named_graphs()
                        .collect::<Result<_, _>>()?;
                    for graph in graph_names {
                        let NamedOrBlankNode::NamedNode(graph_iri) = graph else {
                            // This backend never writes blank-node graphs.
                            continue;
                        };
                        let node = decode_node_id(&graph_iri)?;
                        if let Some(catalog) = self.load_catalog(&node, &graph_iri)? {
                            results.push(catalog);
                        }
                    }
                }
            }

            // Same deterministic ordering + pagination as `memory`'s
            // implementation, so the two backends are behavior-equivalent.
            results.sort_by(|a, b| a.id.cmp(&b.id));

            let skipped = results.into_iter().skip(query.offset);
            let limited: Vec<Catalog> = match query.limit {
                Some(limit) => skipped.take(limit).collect(),
                None => skipped.collect(),
            };
            Ok(limited)
        }

        async fn delete(&self, node: &NodeId) -> StoreResult<bool> {
            let graph = node_iri(node);
            let existed = self.graph_nonempty(&graph)?;
            if existed {
                self.clear_named_graph(&graph)?;
            }
            Ok(existed)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sample_catalog(node: &str, id: &str) -> Catalog {
            Catalog::new(id, NodeId::new(node))
        }

        fn cache() -> OxigraphCatalogCache {
            OxigraphCatalogCache::in_memory().unwrap()
        }

        /// A catalog exercising every field the domain model has: nested
        /// datasets with properties and distributions, a data service, a
        /// participant id, and catalog-level properties. Used by the
        /// round-trip and real-decomposition tests below.
        fn rich_catalog() -> Catalog {
            let mut catalog = Catalog::new("cat-rich", NodeId::new("node-rich"));
            catalog.participant_id = Some("did:example:rich-participant".to_string());
            catalog
                .properties
                .insert("http://www.w3.org/ns/dcat#keyword".to_string(), "logistics".to_string());
            catalog
                .properties
                .insert("internalLabel".to_string(), "demo".to_string());

            let mut ds1_properties = BTreeMap::new();
            ds1_properties.insert("assetType".to_string(), "data.rest".to_string());
            catalog.datasets.push(Dataset {
                id: "ds-1".to_string(),
                properties: ds1_properties,
                distributions: vec![
                    Distribution {
                        format: "application/json".to_string(),
                        access_service: "svc-1".to_string(),
                    },
                    Distribution {
                        format: "application/xml".to_string(),
                        access_service: "svc-1".to_string(),
                    },
                ],
            });
            catalog.datasets.push(Dataset {
                id: "ds-2".to_string(),
                properties: BTreeMap::new(),
                distributions: vec![Distribution {
                    format: "text/csv".to_string(),
                    access_service: "svc-2".to_string(),
                }],
            });

            catalog.data_services.push(DataService {
                id: "svc-1".to_string(),
                endpoint_url: "https://example.org/dsp".to_string(),
                endpoint_description: Some("dataspace-protocol-http:1.0".to_string()),
            });
            catalog.data_services.push(DataService {
                id: "svc-2".to_string(),
                endpoint_url: "https://example.org/other-dsp".to_string(),
                endpoint_description: None,
            });

            catalog
        }

        #[tokio::test]
        async fn upsert_then_query_all_returns_it() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-1");
        }

        #[tokio::test]
        async fn upsert_replaces_prior_catalog_for_same_node() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-1", "cat-2"))
                .await
                .unwrap();

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-2");
        }

        #[tokio::test]
        async fn query_for_node_filters_by_origin() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-2", "cat-2"))
                .await
                .unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-2")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-2");
        }

        #[tokio::test]
        async fn query_respects_offset_and_limit() {
            let cache = cache();
            for i in 0..5 {
                cache
                    .upsert(sample_catalog(&format!("node-{i}"), &format!("cat-{i}")))
                    .await
                    .unwrap();
            }

            let results = cache
                .query(CatalogQuery {
                    origin_node: None,
                    offset: 2,
                    limit: Some(2),
                })
                .await
                .unwrap();
            assert_eq!(
                results.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
                vec!["cat-2", "cat-3"]
            );
        }

        #[tokio::test]
        async fn delete_removes_catalog_and_reports_result() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-1", "cat-1"))
                .await
                .unwrap();

            let removed = cache.delete(&NodeId::new("node-1")).await.unwrap();
            assert!(removed);

            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert!(results.is_empty());

            let removed_again = cache.delete(&NodeId::new("node-1")).await.unwrap();
            assert!(!removed_again);
        }

        /// The correctness bar from gap analysis §3.2: round-tripping a
        /// catalog that exercises every field (nested datasets, properties
        /// with both an already-IRI key and a plain key, distributions,
        /// data services, participant id) through real triples must
        /// reproduce the exact same domain value, order included.
        #[tokio::test]
        async fn round_trips_a_catalog_exercising_every_field_exactly() {
            let cache = cache();
            let original = rich_catalog();
            cache.upsert(original.clone()).await.unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-rich")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0], original);
        }

        /// Proves real decomposition happened: a direct quad-pattern query
        /// against the store, using the real `dct:format` predicate IRI,
        /// finds a specific distribution's format. This is impossible
        /// against the old JSON-blob representation, where the entire
        /// catalog was one opaque literal object and no predicate other
        /// than `fcns:catalogJson` ever existed in the store.
        #[tokio::test]
        async fn a_direct_quad_pattern_query_finds_a_distribution_format_by_its_real_dcat_predicate() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let graph = node_iri(&NodeId::new("node-rich"));
            let matches = cache
                .quads(
                    None,
                    Some(&dct_format_pred()),
                    Some(&Term::from(Literal::from("application/xml".to_string()))),
                    &graph,
                )
                .unwrap();
            assert_eq!(matches.len(), 1, "expected exactly one distribution with this format");

            // And the subject that carries it really is a dcat:Distribution
            // reachable from ds-1 via the real dcat:distribution property -
            // not just a coincidentally-matching literal floating in the
            // graph.
            let distribution_subject = match &matches[0].subject {
                NamedOrBlankNode::NamedNode(n) => n.clone(),
                other => panic!("expected a named node subject, got {other:?}"),
            };
            let type_matches = cache
                .quads(
                    Some(&distribution_subject),
                    Some(&rdf_type()),
                    Some(&Term::from(dcat_distribution_class())),
                    &graph,
                )
                .unwrap();
            assert_eq!(type_matches.len(), 1);
        }

        /// Same proof as above, but via a real SPARQL ASK through
        /// `contreforts_kg::QueryEngine` (the "SPARQL ASK" option gap
        /// analysis §3.2 calls out), scoped to one named graph.
        #[tokio::test]
        async fn sparql_ask_finds_a_dataset_via_the_real_dcat_dataset_link() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let engine = contreforts_kg::QueryEngine::new(&cache.store);
            let found = engine
                .ask(&format!(
                    "PREFIX dcat: <{DCAT_NS}> ASK {{ GRAPH <{}> {{ \
                         ?catalog a dcat:Catalog ; dcat:dataset ?dataset . \
                         ?dataset a dcat:Dataset . \
                         ?dataset dcat:distribution ?distribution . \
                         ?distribution dcat:accessService ?service . \
                         ?service a dcat:DataService \
                     }} }}",
                    node_iri(&NodeId::new("node-rich")).as_str()
                ))
                .unwrap();
            assert!(found, "expected the real dcat:dataset/distribution/accessService chain to be queryable");
        }

        /// A property whose key is already a real vocabulary IRI is stored
        /// under that exact predicate, not this project's fallback
        /// namespace - proving "reuse the term when one genuinely fits"
        /// actually happens, not just documented.
        #[tokio::test]
        async fn a_property_keyed_by_a_real_vocabulary_iri_is_stored_under_that_predicate() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let graph = node_iri(&NodeId::new("node-rich"));
            let keyword_pred = iri("http://www.w3.org/ns/dcat#keyword");
            let matches = cache.quads(None, Some(&keyword_pred), None, &graph).unwrap();
            assert_eq!(matches.len(), 1);
            assert_eq!(term_as_string(&matches[0].object).unwrap(), "logistics");
        }

        /// `upsert` replacing a node's graph wholesale must also drop the
        /// old catalog's decomposed triples, not just its top-level
        /// resource - otherwise a re-crawl with fewer datasets would leak
        /// orphaned dataset/distribution triples forever.
        #[tokio::test]
        async fn upsert_wholesale_replacement_drops_the_prior_catalogs_decomposed_triples() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let mut smaller = Catalog::new("cat-smaller", NodeId::new("node-rich"));
            smaller.datasets.push(Dataset {
                id: "only-dataset".to_string(),
                properties: BTreeMap::new(),
                distributions: vec![],
            });
            cache.upsert(smaller.clone()).await.unwrap();

            let results = cache
                .query(CatalogQuery::for_node(NodeId::new("node-rich")))
                .await
                .unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0], smaller);

            // No leftover triples from `rich_catalog`'s ds-1/ds-2/svc-1/svc-2.
            let graph = node_iri(&NodeId::new("node-rich"));
            let all_quads = cache.quads(None, None, None, &graph).unwrap();
            let leaked_old_dataset = all_quads.iter().any(|q| {
                matches!(&q.subject, NamedOrBlankNode::NamedNode(n) if n.as_str().contains("ds-1") || n.as_str().contains("ds-2"))
            });
            assert!(!leaked_old_dataset, "old catalog's dataset triples must not survive a wholesale upsert");
        }

        // --- `sparql_query_json` (gap analysis §3.3) --------------------------

        /// A plain `SELECT` with no `GRAPH`/`FROM` clause at all must still
        /// find data crawled from two *different* origin nodes (two
        /// separate named graphs) - proving the "whole store by default"
        /// union-graph behavior documented on `sparql_query_json`, not just
        /// that the method returns something.
        #[tokio::test]
        async fn sparql_query_json_select_with_no_graph_clause_searches_every_named_graph() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-a", "cat-a"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-b", "cat-b"))
                .await
                .unwrap();

            let bytes = cache
                .sparql_query_json(&format!(
                    "PREFIX dcat: <{DCAT_NS}> SELECT ?catalog WHERE {{ ?catalog a dcat:Catalog }}"
                ))
                .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

            assert_eq!(parsed["head"]["vars"], serde_json::json!(["catalog"]));
            let bindings = parsed["results"]["bindings"].as_array().unwrap();
            assert_eq!(bindings.len(), 2, "expected one dcat:Catalog per origin node, got {parsed}");
            let mut catalog_iris: Vec<&str> = bindings
                .iter()
                .map(|b| b["catalog"]["value"].as_str().unwrap())
                .collect();
            catalog_iris.sort_unstable();
            assert!(catalog_iris[0].contains("node-a") && catalog_iris[0].contains("cat-a"));
            assert!(catalog_iris[1].contains("node-b") && catalog_iris[1].contains("cat-b"));
            // And the JSON Results type/value shape is real, not
            // hand-rolled: a resource binding must come back as a `uri`.
            assert_eq!(bindings[0]["catalog"]["type"], serde_json::json!("uri"));
        }

        /// The `GRAPH <iri>` clause (the documented stretch-goal way to
        /// scope a query to one participant) finds only that participant's
        /// data, even though the store as a whole holds two.
        #[tokio::test]
        async fn sparql_query_json_graph_clause_scopes_to_one_participant() {
            let cache = cache();
            cache
                .upsert(sample_catalog("node-a", "cat-a"))
                .await
                .unwrap();
            cache
                .upsert(sample_catalog("node-b", "cat-b"))
                .await
                .unwrap();

            let scoped_graph = node_iri(&NodeId::new("node-b"));
            let bytes = cache
                .sparql_query_json(&format!(
                    "PREFIX dcat: <{DCAT_NS}> SELECT ?catalog WHERE {{ GRAPH <{}> {{ ?catalog a dcat:Catalog }} }}",
                    scoped_graph.as_str()
                ))
                .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let bindings = parsed["results"]["bindings"].as_array().unwrap();
            assert_eq!(bindings.len(), 1);
            assert!(bindings[0]["catalog"]["value"].as_str().unwrap().contains("node-b"));
        }

        /// A real `ASK` query, through the same HTTP-facing method,
        /// against real harvested-looking data (the "rich" catalog fixture
        /// used elsewhere in this module).
        #[tokio::test]
        async fn sparql_query_json_ask_returns_the_spec_shaped_boolean_result() {
            let cache = cache();
            cache.upsert(rich_catalog()).await.unwrap();

            let bytes = cache
                .sparql_query_json(&format!(
                    "PREFIX dcat: <{DCAT_NS}> ASK {{ ?d a dcat:Dataset ; dcat:distribution ?dist . ?dist dcat:accessService ?svc }}"
                ))
                .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed, serde_json::json!({"head": {}, "boolean": true}));
        }

        /// A SPARQL **Update** operation (`INSERT DATA`) must never be
        /// reachable through this method - proving the "read-only by
        /// construction" claim in `sparql_query_json`'s own doc comment,
        /// not just documenting it.
        #[tokio::test]
        async fn sparql_update_operation_is_rejected_not_silently_ignored() {
            let cache = cache();
            cache.upsert(sample_catalog("node-1", "cat-1")).await.unwrap();

            let attempted_injection = format!(
                "PREFIX dcat: <{DCAT_NS}> INSERT DATA {{ GRAPH <{}> {{ <urn:x> a dcat:Catalog }} }}",
                node_iri(&NodeId::new("node-1")).as_str()
            );
            let outcome = cache.sparql_query_json(&attempted_injection);
            assert!(
                matches!(outcome, Err(SparqlError::Parse(_))),
                "expected an Update operation to fail to parse as a Query, got {outcome:?}"
            );

            // And, just as importantly, nothing was actually inserted -
            // the store is unaffected by the attempt.
            let results = cache.query(CatalogQuery::all()).await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].id, "cat-1");
        }

        /// `CONSTRUCT` is a well-formed Query, just not one this method
        /// serializes (see `SparqlError::UnsupportedGraphResult`'s own doc
        /// comment) - it must fail cleanly, not panic or silently return
        /// an empty/wrong result.
        #[tokio::test]
        async fn sparql_query_json_rejects_construct_queries_cleanly() {
            let cache = cache();
            cache.upsert(sample_catalog("node-1", "cat-1")).await.unwrap();

            let outcome = cache.sparql_query_json("CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }");
            assert!(matches!(outcome, Err(SparqlError::UnsupportedGraphResult)));
        }

        /// A syntactically invalid query string is a `Parse` error, not a
        /// panic and not silently empty results.
        #[tokio::test]
        async fn sparql_query_json_rejects_malformed_query_syntax() {
            let cache = cache();
            let outcome = cache.sparql_query_json("this is not sparql at all");
            assert!(matches!(outcome, Err(SparqlError::Parse(_))));
        }
    }
}
