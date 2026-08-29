# OID4VP as an alternative credential-presentation protocol for harvesting

**Date:** 2026-08-28
**Status:** in progress — this document is written first and updated as the
corresponding TDD implementation pass lands, tracked in
[PR #2](https://github.com/ds-labs-org/ds-catalog-broker-rs/pull/2) on
branch `feature/oid4vc-holder` (branched from `feature/oauth2-bearer-gating`,
which added OAuth2 Bearer gating to this connector's own *inbound* serving
surfaces — unrelated to this document, which is about the crawler's
*outbound* credential presentation when harvesting a gated participant).

## Why this exists

`crates/crawler`'s DCP holder role (`dcp_core::HolderIdentity`,
`ParticipantEntry::requires_dcp`) lets this crawler present its own
credential to a remote Catalog Service that gates access — a legitimate
Consumer-side concern this project keeps (see the gap analysis §2). DCP is
one real protocol for that; it isn't the only one a dataspace participant
might require. **OpenID for Verifiable Presentations (OID4VP)** is a
broader, OpenID-Foundation-standardized alternative some participants may
gate on instead, and this document scopes adding it *alongside* DCP — a
second `credential_protocol` a participant can be configured for, not a
replacement.

## What DCP's own flow actually does (so the contrast below is accurate)

Read `dcp_core::HolderIdentity::mint_self_issued_token` and
`crawler::crawl_one` closely before assuming DCP here is a simple bearer
token: it's a two-hop, callback-based exchange modeled on SIOPv2. `crawl_one`
proactively mints a self-issued JWS ("T1", `aud` = the target participant's
own DID) and sends it as `Authorization: Bearer` on the *same* catalog-request
call — no challenge round trip on the outbound leg. What makes this DCP and
not a bare bearer token is what the **provider** is expected to do with T1
once it has it (`ds_catalog_broker_rs::dcp::verify_dcp_bearer_token`, before
its removal per gap analysis §1.2, is the reference for this): resolve T1's
`iss` DID, then call back that holder's own `/dsp/holder/presentations/query`
route to obtain a real `VerifiablePresentation` ("T3") wrapping the holder's
actual credential — the crawler's own `answer_presentation_query` handler is
the receiving half of that callback. So DCP here is bidirectional: both
sides must expose an HTTP endpoint the other calls into.

## OID4VP v1 scope: single-shot, no callback

Real interactive OID4VP is also a two-hop protocol (Verifier sends an
Authorization Request naming a `presentation_definition`, `nonce`, and
`response_uri`; Wallet answers with `vp_token` + `presentation_submission`).
Implementing that full negotiation would mean this crawler's *harvester*
role also standing up a Wallet-side request handler — real work, but not
what "catalog harvesting" needs on its own, and a materially larger scope
than this pass. **v1 here is deliberately single-shot**, matching the same
simplification this codebase already made for DCP's own outbound leg (no
provider-issued challenge there either): the crawler builds a complete
OID4VP Authorization *Response* on its own initiative — `vp_token` +
`presentation_submission` — and POSTs it `direct_post`-style straight to a
per-participant `oid4vp_response_uri`, without ever having received a
matching Authorization *Request*. This is a real, spec-shaped wire format
(the response side is byte-for-byte what a real Verifier would receive from
a real interactive exchange), just without the live negotiation that would
normally produce the `nonce`/`presentation_definition` it's answering.

**Consequence, stated plainly (not glossed over):** the `nonce` this
crawler puts in its `vp_token` is self-generated (a fresh UUID) rather than
verifier-issued, so full replay protection — the verifier proving *it*
picked this exact nonce for *this* exchange — does not hold in v1. `exp`
still bounds the token's validity window (5 minutes, matching DCP's own
T1/T2 lifetime), which limits (does not eliminate) the exposure. Closing
this gap for real needs the interactive request/response round trip
described above — left as explicit future work, not silently assumed away.

## What's reused vs. new

**Reused, unchanged:** `dcp_core::DcpKeyPair` (ES256 key generation,
`did:web` identity, JWS sign/verify) and `dcp_core::{sign_jws, b64_encode,
now_secs}`. OID4VP's wire *messages* differ from DCP's, but the underlying
"sign this JSON with my P-256 key, publish a `did:web` document so someone
can resolve the matching key" primitives are identical — `dcp-core`'s own
module doc already says it's role- and protocol-agnostic on this point, and
this is exactly the case that claim was written for. No second key-pair
type, no second `did:web` resolver.

**New, in a new module (`crates/crawler/src/oid4vp.rs` — kept in
`crawler`, not a new crate: this is a single-consumer harvesting concern
today, same footprint decision `ds-catalog-broker-rs/src/oauth2.rs` made for
its own single-consumer feature; revisit only if a second consumer shows
up):**

- `build_vp_token(key_pair: &DcpKeyPair, credential_jws: &str, audience: &str) -> String`
  — a JWT-VP: header `{"alg":"ES256","kid":"<own_did>#dsp-key"}`, payload
  `{"iss":<own_did>, "sub":<own_did>, "aud":<audience>, "nonce":<fresh uuid>,
  "iat","exp" (+300s), "vp": {"@context":["https://www.w3.org/2018/credentials/v1"],
  "type":["VerifiablePresentation"], "verifiableCredential":[<credential_jws>]}}`
  — a JWT enveloping the existing W3C VC-JWT `credential_jws` as its `vp`
  claim, the standard nesting for `vp_formats: jwt_vp_json`.
- `build_presentation_submission(definition_id: &str) -> Value` — the DIF
  Presentation Exchange `presentation_submission` object DIF/OID4VP
  requires alongside `vp_token`, referencing one fixed, well-known
  `descriptor_map` entry (`id: "federated-catalog-access-credential"`,
  `format: "jwt_vp_json"`, `path: "$"`) — this project defines and expects
  one specific credential type per participant (mirroring DCP's own single
  `EXPECTED_CREDENTIAL_TYPE`), not a general Presentation-Exchange client
  capable of satisfying an arbitrary requested definition. A participant
  requiring a different `presentation_definition` shape is out of scope for
  v1 and would show up as a verification failure on their end, not a crash
  on this side.
- `present(http: &reqwest::Client, key_pair: &DcpKeyPair, credential_jws: &str, response_uri: &str) -> Result<String, Oid4VpError>`
  — builds both of the above, POSTs `application/x-www-form-urlencoded`
  (`vp_token=...&presentation_submission=...`) to `response_uri`, and
  expects a `200` JSON body containing an `access_token` string — the
  short-lived credential this crawler then attaches as `Authorization:
  Bearer` on the real `catalog_request_url` call, exactly parallel to how
  the DCP path attaches its self-issued T1. A non-2xx response, a missing
  `access_token`, or a transport error is a per-participant crawl failure
  (`CrawlSummary.failures`), never a panic — matching every other
  participant-crawl failure mode already in `crawl_one`.

## Config

`ParticipantEntry.requires_dcp: bool` becomes
`ParticipantEntry.credential_protocol: CredentialProtocol` — a
`#[serde(rename_all = "snake_case")]` enum: `None` (default,
today's unauthenticated case), `Dcp` (today's `requires_dcp = true`,
`provider_did` required, unchanged behavior), `Oid4Vp` (new: requires a new
`oid4vp_response_uri: String` field on the entry instead of `provider_did`).
This is a breaking rename of an existing field, not an additive one —
deliberately: this project has no external users of its own config format
yet (a hand-maintained local TOML file, per `crawler::config`'s own module
doc), so a bool that can no longer express a second real protocol should
just become the enum it always should have been, not grow a second
parallel `requires_oid4vp` bool alongside it. Every existing test/example
TOML in `crawler::config` gets updated to the new field name as part of
this change, not left on a deprecated alias.

`[holder]`'s existing fields (`own_did_host`, `insecure_http`,
`credential_jws`, `required_scope`) are reused as-is for OID4VP too — same
key pair, same credential, different presentation protocol. `validate()`
gains the equivalent OID4VP checks: a `credential_protocol = "oid4vp"`
participant needs `oid4vp_response_uri` set and the file's `[holder]`
section present, mirroring the existing DCP checks exactly.

## What this does *not* change

- `ds-catalog-broker-rs`'s own inbound `/dsp/holder/*` routes
  (`HolderIdentity::answer_presentation_query`) — those answer a DCP
  presentation *query* from a remote relying party querying *this*
  connector's own credential. Nothing here adds an inbound OID4VP verifier
  role to `ds-catalog-broker-rs` itself; that would be the reciprocal of
  this document (gating this connector's own `/catalog`/`/sparql` via
  OID4VP instead of/alongside the OAuth2 Bearer gate `feature/oauth2-bearer-gating`
  added) and is a separate, not-yet-scoped decision.
- The DCP path (`credential_protocol = "dcp"`) is untouched — same
  `mint_self_issued_token` call, same wire shape, same tests, still the
  default recommendation for a participant this crawler and its provider
  both control end to end (it doesn't need OID4VP's broader,
  more-standard-but-heavier machinery).

## Status

Landed via real RED/GREEN TDD on `feature/oid4vc-holder`:

- RED: `365cca7` - "RED: OID4VP holder-presentation tests for crawl_one
  (fails to compile against 5cbe1d1)". Confirmed failing: `cargo test -p
  crawler` failed to compile (`error[E0432]: unresolved import
  config::CredentialProtocol`, plus every other new symbol these tests
  reference) before any production code existed.
- GREEN: `51d5886` - "GREEN: implement OID4VP holder presentation
  alongside DCP". `cargo test --workspace`: **541 passed, 0 failed, 1
  ignored** (the pre-existing `#[ignore]`d real-EDC integration test,
  untouched by this change). `cargo test -p crawler` alone: 28 unit tests
  (13 in `config`, 8 in `oid4vp`, 7 in `lib::tests`) + 4 real-mock-server
  integration tests in `multi_participant_crawl.rs` + 1 ignored.
- This docs commit.

### What actually landed, vs. this document's plan

All field/function/type names match the plan above exactly, with one
addition and one clarification not spelled out above:

- `CredentialProtocol::Oid4Vp`'s TOML wire value is `"oid4vp"`, not the
  `#[serde(rename_all = "snake_case")]` default of `"oid4_vp"` (splitting
  the digit/letter boundary) - needed an explicit `#[serde(rename =
  "oid4vp")]` on that one variant to get the value this document (and
  every example TOML) actually uses.
- `present()`'s `vp_token` `aud` claim is `response_uri` itself.
  `present()`'s signature (deliberately, per this document) has no
  separate `audience`/`client_id` parameter, so `response_uri` - the only
  identifier of "who this presentation is for" this crawler actually has
  in v1's non-interactive flow - is what gets passed as `build_vp_token`'s
  `audience` argument. Not a deviation from the design (nothing above
  specified an alternative), just the concrete choice made where the doc
  left it implicit.
- `ConfigError::MissingHolderSection`'s message was generalized from
  "has requires_dcp = true but this config file has no [holder] section"
  to protocol-neutral wording, since it's now returned for both `Dcp` and
  `Oid4Vp` participants (the underlying need - a holder identity to sign
  with - is identical either way, exactly as this document's Config
  section says). The variant name and the check's behavior are unchanged.

### Confirmed: the DCP path is unmodified in behavior

`CredentialProtocol::Dcp`'s `crawl_one` arm is the same code as the old
`if participant.requires_dcp` branch, reading the new enum instead of the
old bool - same `mint_self_issued_token` call, same
`bearer_auth`/`provider_did`/holder-identity checks, same error message
text (`"... requires_dcp but no holder identity is configured"` /
`"... requires_dcp but has no provider_did"` - left as-is deliberately;
renaming them was out of scope and would have been a gratuitous,
unrequested string change). Every pre-existing DCP-path test passes
unmodified: `crates/dcp-core/src/lib.rs`'s own 2 unit tests, and all 4
tests in `crates/crawler/tests/multi_participant_crawl.rs` (only its
`ParticipantEntry` field-literal fixtures and `clone_entry` helper needed
updating for the field rename - no test assertion changed).

### `requires_dcp` grep, workspace-wide

```
$ grep -rn "requires_dcp" --include="*.rs" --include="*.toml" .
crates/crawler/src/config.rs:69:/// old `requires_dcp`.
crates/crawler/src/config.rs:111:    /// `CredentialProtocol::None`, matching how `requires_dcp` used to
crates/crawler/src/config.rs:130:/// `requires_dcp`.
crates/crawler/src/lib.rs:134:                format!("participant '{}' requires_dcp but no holder identity is configured", participant.id)
crates/crawler/src/lib.rs:137:                format!("participant '{}' requires_dcp but has no provider_did", participant.id)
```

Every remaining hit is an intentional exception, not a missed call site:
the three in `config.rs` are doc-comment prose explicitly contrasting the
new enum with the field it replaced ("matching how `requires_dcp` used to
default to..."); the two in `lib.rs` are the `Dcp` arm's own error message
text, kept byte-for-byte per this section's "DCP path is unmodified"
point above. No `ParticipantEntry` field, `bool`, or TOML key named
`requires_dcp` exists anywhere in the workspace any more - `cargo build
--workspace` and `cargo test --workspace` both confirmed green (see
above), so nothing outside `crates/crawler` referenced the old field
either.

### `crawl_one` behavior per `CredentialProtocol` variant (final)

- `None`: unchanged - the fixed, non-secret
  `OPEN_PARTICIPANT_PLACEHOLDER_AUTH` header, no credential involved.
- `Dcp`: unchanged - mints and sends a self-issued DCP token (T1) as
  `Authorization: Bearer`, requiring `provider_did` and a holder identity.
- `Oid4Vp`: requires `oid4vp_response_uri` and a holder identity (both
  defensive per-participant-failure checks, matching `Dcp`'s own
  posture); calls `oid4vp::present(http, &holder.key_pair,
  &holder.credential_jws, oid4vp_response_uri)`, then attaches the
  returned `access_token` via `.bearer_auth(...)` on the *same*
  `catalog_request_url` call `crawl_one` already makes - exactly one extra
  outbound request (`present`'s own POST), never a second catalog fetch.
