//! Minimal domain types for the federated catalog rewrite.
//!
//! Modeled loosely on Eclipse EDC's `federated-catalog-spi` / `catalog-spi`
//! Java modules, but deliberately smaller: only what the `rdf-store` cache
//! trait needs to operate on. This is not a port - fields and shapes are a
//! from-scratch Rust design, not a transliteration of the Java classes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Identifier of a dataspace participant / crawl target node.
///
/// Corresponds to the `id` field of EDC's `TargetNode` record
/// (spi/crawler-spi).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A participant known to the crawler: enough to address it and pick a
/// protocol to speak.
///
/// Analogous to EDC's `TargetNode` record (spi/crawler-spi).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetNode {
    pub id: NodeId,
    pub name: String,
    pub target_url: String,
    pub supported_protocols: Vec<String>,
}

/// One unit of crawl work: a target node plus how many times it has
/// already been retried in the current cycle.
///
/// EDC has no standalone `WorkItem` type at v0.18.0 - the equivalent is a
/// private `TargetNodeRetryCount` record local to `CatalogCrawlerManager`,
/// scoped to a single crawl attempt. It's promoted to a first-class,
/// public type here because a from-scratch design is free to name it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlWorkItem {
    pub node: TargetNode,
    pub retries: u32,
}

impl CrawlWorkItem {
    pub fn new(node: TargetNode) -> Self {
        Self { node, retries: 0 }
    }
}

/// One concrete access method for a dataset: a data-plane endpoint plus
/// the format it serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distribution {
    pub format: String,
    pub access_service: String,
}

/// A dataspace protocol-facing description of a data service (e.g. a
/// connector's DSP endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataService {
    pub id: String,
    pub endpoint_url: String,
    #[serde(default)]
    pub endpoint_description: Option<String>,
}

/// The ODRL `@type` of a [`Policy`]: how binding it currently is.
///
/// Mirrors ODRL's three policy subclasses (<https://www.w3.org/TR/odrl-model/#policy>).
/// A catalog broker only ever *harvests* policies attached to a crawled
/// participant's `dcat:Dataset` via `odrl:hasPolicy` - it never negotiates,
/// so in practice every policy this crate constructs from a crawl is an
/// `Offer` (the pre-negotiation ODRL type DSP catalogs advertise). `Set` and
/// `Agreement` are modeled anyway because they are valid ODRL policy types
/// and a faithful cache must not reject or coerce a participant that (contrary
/// to typical DSP usage) advertises one of the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PolicyKind {
    #[default]
    Set,
    Offer,
    Agreement,
}

/// One atomic ODRL constraint: `leftOperand operator rightOperand`, e.g.
/// `odrl:dateTime lteq "2027-01-01T00:00:00Z"`.
///
/// This models only *atomic* constraints
/// (<https://www.w3.org/TR/odrl-model/#constraint-atomic>). ODRL also allows
/// *logical constraints* - `odrl:and` / `odrl:or` / `odrl:andSequence` /
/// `odrl:xone` groups nesting further constraints
/// (<https://www.w3.org/TR/odrl-model/#constraint-logical>) - and those are
/// **not modeled here**. This is a deliberate, known scope cut for the
/// gap-analysis §3.4 work, not an oversight: a crawled constraint that turns
/// out to be a logical-group node rather than an atomic
/// leftOperand/operator/rightOperand triple is skipped (that one constraint
/// only, not the enclosing policy or rule) by the crawler/rdf-store parsing
/// path, with the skip surfaced as a tracing warning rather than silently
/// dropped - see the "Known limitation" notes in `crawler::parse_catalog_response`
/// and `rdf_store`'s module doc for where that happens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    pub left_operand: String,
    pub operator: String,
    pub right_operand: String,
}

/// One ODRL rule entry: a single `permission`, `prohibition`, or
/// `obligation` inside a [`Policy`].
///
/// ODRL gives permission/prohibition/obligation the same shape (an `action`
/// plus zero or more `constraint`s
/// (<https://www.w3.org/TR/odrl-model/#rule>)), so one type covers all
/// three; which list a given `Rule` lives in (see [`Policy::permissions`],
/// [`Policy::prohibitions`], [`Policy::obligations`]) is what distinguishes
/// them, exactly as in the ODRL JSON-LD serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub action: String,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
}

/// A harvested ODRL policy, as faithfully preserved from a crawled
/// participant's `dcat:Dataset` / `odrl:hasPolicy` triples.
///
/// This is real policy data derived from what a crawled participant
/// actually advertised - not the hardcoded placeholder the now-removed
/// http-api DSP layer used to emit (see gap analysis §3.4). A read-only
/// catalog broker has no negotiation capability of its own, so "honoring"
/// a harvested policy here means: preserve it faithfully end to end
/// (crawl -> semantic cache -> management API), and make it available to
/// callers rather than inventing or dropping it. Whether the broker should
/// also *filter* what it re-serves based on policy content (e.g. hide a
/// dataset from a caller not entitled under its policy) is an open design
/// question this type intentionally does not answer - see gap analysis
/// §3.4 for why that's flagged rather than guessed at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub kind: PolicyKind,
    #[serde(default)]
    pub assigner: Option<String>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub permissions: Vec<Rule>,
    #[serde(default)]
    pub prohibitions: Vec<Rule>,
    #[serde(default)]
    pub obligations: Vec<Rule>,
}

/// One offered dataset: its id, arbitrary properties, the distributions
/// it's available through, and the ODRL policies a crawled participant
/// attached to it.
///
/// EDC's `Dataset` carries `offers: Map<String, Policy>`; the equivalent
/// here is `policies`, harvested faithfully from a crawled participant's
/// `odrl:hasPolicy` triples rather than invented - see [`Policy`]'s doc
/// comment and gap analysis §3.4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dataset {
    pub id: String,
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
    #[serde(default)]
    pub distributions: Vec<Distribution>,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

/// A crawled catalog: one participant's advertised datasets and data
/// services, as fetched by a single crawl of `origin_node`.
///
/// Modeled after EDC's `Catalog extends Dataset` (spi/control-plane/catalog-spi),
/// flattened here rather than inheriting from `Dataset` since Rust has no
/// class inheritance and the cache only ever stores whole catalogs, never
/// a bare `Dataset` standing in for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    pub id: String,
    pub origin_node: NodeId,
    #[serde(default)]
    pub participant_id: Option<String>,
    #[serde(default)]
    pub datasets: Vec<Dataset>,
    #[serde(default)]
    pub data_services: Vec<DataService>,
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
}

impl Catalog {
    pub fn new(id: impl Into<String>, origin_node: NodeId) -> Self {
        Self {
            id: id.into(),
            origin_node,
            participant_id: None,
            datasets: Vec::new(),
            data_services: Vec::new(),
            properties: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_new_has_empty_collections() {
        let cat = Catalog::new("cat-1", NodeId::new("node-1"));
        assert_eq!(cat.id, "cat-1");
        assert_eq!(cat.origin_node, NodeId::new("node-1"));
        assert!(cat.datasets.is_empty());
        assert!(cat.data_services.is_empty());
    }

    #[test]
    fn crawl_work_item_starts_at_zero_retries() {
        let node = TargetNode {
            id: NodeId::new("node-1"),
            name: "node-1".into(),
            target_url: "https://example.org/dsp".into(),
            supported_protocols: vec!["dataspace-protocol-http".into()],
        };
        let item = CrawlWorkItem::new(node);
        assert_eq!(item.retries, 0);
    }

    #[test]
    fn node_id_display_matches_inner_string() {
        let id = NodeId::new("abc");
        assert_eq!(id.to_string(), "abc");
    }

    #[test]
    fn policy_kind_defaults_to_set() {
        assert_eq!(PolicyKind::default(), PolicyKind::Set);
    }

    #[test]
    fn dataset_with_no_policies_round_trips_via_serde_default() {
        // Older/simpler JSON (predating this field) must still deserialize:
        // `policies` is #[serde(default)] precisely so a Dataset with no
        // `policies` key at all comes back as an empty Vec, not an error.
        let json = serde_json::json!({
            "id": "ds-1",
            "properties": {},
            "distributions": [],
        });
        let dataset: Dataset = serde_json::from_value(json).expect("deserializes");
        assert!(dataset.policies.is_empty());

        let round_tripped: Dataset =
            serde_json::from_str(&serde_json::to_string(&dataset).unwrap()).unwrap();
        assert_eq!(round_tripped, dataset);
    }

    #[test]
    fn policy_with_full_shape_round_trips_through_json() {
        let policy = Policy {
            id: Some("policy-1".into()),
            kind: PolicyKind::Offer,
            assigner: Some("did:example:provider".into()),
            assignee: Some("did:example:consumer".into()),
            permissions: vec![Rule {
                action: "use".into(),
                constraints: vec![Constraint {
                    left_operand: "odrl:dateTime".into(),
                    operator: "lteq".into(),
                    right_operand: "2027-01-01T00:00:00Z".into(),
                }],
            }],
            prohibitions: vec![Rule {
                action: "distribute".into(),
                constraints: Vec::new(),
            }],
            obligations: Vec::new(),
        };

        let json = serde_json::to_string(&policy).expect("serializes");
        let round_tripped: Policy = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(round_tripped, policy);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["kind"], "Offer");
        assert_eq!(value["id"], "policy-1");
        assert_eq!(value["permissions"][0]["action"], "use");
        assert_eq!(
            value["permissions"][0]["constraints"][0]["right_operand"],
            "2027-01-01T00:00:00Z"
        );
        // obligations was empty - #[serde(default)] means it's fine either
        // way whether present-and-empty or omitted, but our derive always
        // emits it (no skip_serializing_if), so assert it's there and empty.
        assert!(value["obligations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn dataset_with_policies_round_trips() {
        let dataset = Dataset {
            id: "ds-1".into(),
            properties: BTreeMap::new(),
            distributions: Vec::new(),
            policies: vec![Policy {
                id: None,
                kind: PolicyKind::Offer,
                assigner: None,
                assignee: None,
                permissions: vec![Rule {
                    action: "use".into(),
                    constraints: Vec::new(),
                }],
                prohibitions: Vec::new(),
                obligations: Vec::new(),
            }],
        };

        let round_tripped: Dataset =
            serde_json::from_str(&serde_json::to_string(&dataset).unwrap()).unwrap();
        assert_eq!(round_tripped, dataset);
        assert_eq!(round_tripped.policies[0].kind, PolicyKind::Offer);
    }
}
