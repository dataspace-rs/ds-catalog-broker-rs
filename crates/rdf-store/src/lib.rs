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
//! The quad mapping is still the "first cut" blob-JSON bridge this doc
//! comment originally proposed, not full RDF decomposition: one named
//! graph per origin node, one triple per graph, subject = predicate =
//! object all handled as plain Oxigraph terms rather than a real
//! vocabulary of dataset/offer/distribution classes. See
//! [`oxigraph_backend`]'s module doc for the exact IRI scheme. Modeling
//! `Catalog`/`Dataset`/`DataService` as real RDF triples remains future
//! work, tracked the same way as before: an ADR-equivalent record in the
//! `dataspace` study repo's `docs/adr/` when that decomposition is
//! designed.

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
/// ## Quad mapping (first cut - see the crate-level doc comment)
///
/// For an origin node whose [`NodeId`] is `<node>`:
///
/// - **Subject and named graph IRI** (the same IRI is reused for both):
///   `https://federated-catalog-rs.internal/nodes/<percent-encoded node>`.
///   Percent-encoding the node id guarantees a valid IRI regardless of what
///   characters the id contains.
/// - **Predicate**: the fixed vocabulary IRI
///   `https://federated-catalog-rs.internal/ns#catalogJson`.
/// - **Object**: a plain (untyped) string [`oxigraph::model::Literal`]
///   holding the node's [`Catalog`] serialized as JSON via `serde_json`.
///
/// So each origin node's named graph holds exactly one triple: its own IRI
/// as subject, `catalogJson` as predicate, and the whole crawled catalog as
/// a JSON blob object. This is deliberately not a real RDF decomposition of
/// `Catalog`/`Dataset`/`DataService` into their own triples - it is a
/// bridge that gets a real Oxigraph store under the trait now, with actual
/// per-dataset/per-offer RDF modeling left as future work.
pub mod oxigraph_backend {
    use super::*;
    use contreforts_kg::GraphError;
    use contreforts_kg::store::GraphStore;
    use oxigraph::model::{Literal, NamedNode, NamedOrBlankNode, Term};
    use oxigraph::store::StorageError;
    use std::path::Path;

    const NODE_NS: &str = "https://federated-catalog-rs.internal/nodes/";
    const CATALOG_JSON_PREDICATE: &str = "https://federated-catalog-rs.internal/ns#catalogJson";

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

    /// The fixed `catalogJson` predicate. Constructed on demand rather than
    /// cached in a `static` - it's cheap to build and this keeps the module
    /// free of `lazy_static`/`OnceLock` machinery for a single constant IRI.
    fn catalog_json_predicate() -> NamedNode {
        NamedNode::new(CATALOG_JSON_PREDICATE).expect("constant IRI is valid")
    }

    /// The subject / named-graph IRI for `node`, percent-encoding the node
    /// id so the result is always a valid IRI.
    fn node_iri(node: &NodeId) -> StoreResult<NamedNode> {
        let iri = format!("{NODE_NS}{}", urlencoding::encode(&node.0));
        NamedNode::new(iri).map_err(|e| StoreError::Backend(format!("invalid node IRI: {e}")))
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

        /// Load the catalog stored in `graph_iri`'s named graph, if any.
        fn load_graph(&self, graph_iri: &NamedNode) -> StoreResult<Option<Catalog>> {
            let predicate = catalog_json_predicate();
            let mut quads = self.store.inner().quads_for_pattern(
                Some(graph_iri.into()),
                Some((&predicate).into()),
                None,
                Some(graph_iri.into()),
            );
            let Some(quad) = quads.next() else {
                return Ok(None);
            };
            let quad = quad?;
            let json = match quad.object {
                Term::Literal(lit) => lit.value().to_string(),
                other => {
                    return Err(StoreError::Backend(format!(
                        "expected a literal catalogJson object, got {other:?}"
                    )));
                }
            };
            let catalog: Catalog = serde_json::from_str(&json)
                .map_err(|e| StoreError::Backend(format!("failed to deserialize catalog: {e}")))?;
            Ok(Some(catalog))
        }

        /// Whether `subject`'s named graph currently holds any quad.
        fn has_subject(&self, subject: &NamedNode) -> StoreResult<bool> {
            let mut quads = self.store.inner().quads_for_pattern(
                Some(subject.into()),
                None,
                None,
                Some(subject.into()),
            );
            match quads.next() {
                Some(quad) => {
                    quad?;
                    Ok(true)
                }
                None => Ok(false),
            }
        }
    }

    #[async_trait]
    impl CatalogCache for OxigraphCatalogCache {
        async fn upsert(&self, catalog: Catalog) -> StoreResult<()> {
            let subject = node_iri(&catalog.origin_node)?;
            let predicate = catalog_json_predicate();
            let json = serde_json::to_string(&catalog)
                .map_err(|e| StoreError::Backend(format!("failed to serialize catalog: {e}")))?;
            let object = Term::from(Literal::from(json));

            // Insert-or-replace: remove any existing triple for this
            // subject/graph first, matching the in-memory impl's
            // `HashMap::insert` overwrite semantics.
            self.store
                .remove_subject_from_named_graph(&subject, &subject)?;
            self.store
                .insert_in_named_graph(&subject, &predicate, &object, &subject)?;
            Ok(())
        }

        async fn query(&self, query: CatalogQuery) -> StoreResult<Vec<Catalog>> {
            let mut results: Vec<Catalog> = Vec::new();

            match &query.origin_node {
                Some(node) => {
                    let subject = node_iri(node)?;
                    if let Some(catalog) = self.load_graph(&subject)? {
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
                        if let Some(catalog) = self.load_graph(&graph_iri)? {
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
            let subject = node_iri(node)?;
            let existed = self.has_subject(&subject)?;
            if existed {
                self.store
                    .remove_subject_from_named_graph(&subject, &subject)?;
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
    }
}
