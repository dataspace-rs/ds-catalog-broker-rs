# OAuth2 Bearer gating for the non-DSP serving surfaces

**Date:** 2026-08-28
**Status:** landed, tracked in
[PR #1](https://github.com/ds-labs-org/ds-catalog-broker-rs/pull/1) on
branch `feature/oauth2-bearer-gating`. Implemented via TDD in two commits:
`RED: OAuth2 Bearer gate tests for /catalog and /sparql` (fails to
compile) followed by `GREEN: implement the OAuth2 Bearer gate for
/catalog and /sparql`.

## Why this exists

`GET /catalog` and `GET`/`POST /sparql` (this product's only two serving
surfaces, per the gap analysis and `README.md`'s "Role" section) currently
answer any caller with no authentication at all. The old `DspAuthMode`
gating system (`Disabled`/`Bearer`/`Dcp`) that used to protect the
now-removed DSP catalog-serving endpoint was deleted along with that
endpoint (gap analysis §1.1/§1.3) — it existed only to gate a Provider-role
surface this product no longer has. This document scopes a new, purpose-
built gate for the two surfaces that actually remain: a standard OAuth2
Bearer resource-server check (JWT access token, verified against a
configured JWKS), opt-in the same way the SPARQL backend and the DCP
holder role are (absent config, behavior is unchanged).

This is **not** a revival of the removed `DspAuthMode::Bearer` (a bare
shared-secret string compare) or `DspAuthMode::Dcp` (a self-issued-token
verifier for a different, now-gone use case). It's a real OAuth2
resource-server check: the caller presents an access token minted by some
external OAuth2/OIDC authorization server, and this connector verifies it
against that authorization server's published JWKS — the standard shape
for gating a machine-to-machine API, and independent of DCP (which stays
scoped to the crawler's own holder role, per gap analysis §2).

## Scope

Gated when configured:
- `GET /catalog`
- `GET`/`POST /sparql`

Never gated by this mechanism: `/health` (liveness only, no data), and
`/dsp/holder/did.json` / `/dsp/holder/presentations/query` (already
protected by their own DCP-based check, unrelated to this one).

## Config (opt-in, mirrors the `sparql`/`holder` pattern)

| Env var | Required to enable | Meaning |
|---|---|---|
| `OAUTH2_JWKS_URI` | yes | JWKS endpoint of the authorization server. Unset → gating stays off, both routes behave exactly as before. |
| `OAUTH2_ISSUER` | no | Expected `iss` claim; checked only if set. |
| `OAUTH2_AUDIENCE` | no | Expected `aud` claim; checked only if set. |
| `OAUTH2_REQUIRED_SCOPE` | no | One scope that must appear in the token's space-delimited `scope` claim; checked only if set. |

The JWKS is fetched once, eagerly, at startup (same failure posture as
`CRAWLER_CONFIG_PATH`: a bad `OAUTH2_JWKS_URI` panics on boot rather than
silently starting unauthenticated). **Known limitation, flagged rather than
silently glossed over:** no background refresh or key-rotation handling
yet — a JWKS rotated after startup requires a restart. Revisit if/when this
connector runs long enough for that to matter in practice.

## Verification

Uses the `jsonwebtoken` crate (new dependency) against the fetched JWKS,
rather than hand-rolling JWT parsing the way `dcp-core` hand-rolls compact
JWS for its own, narrower use case (a single self-issued ES256 token type
with a known shape — see that crate's module doc for why hand-rolling was
the right call *there*). Here, the token comes from an arbitrary external
authorization server whose signing algorithm and claim shape aren't
controlled by this project, which is exactly the case a maintained,
spec-tested JWT library is for.

- Key selection: the token's header `kid` selects a JWK from the fetched
  JWKS (server-controlled data, fetched from a trusted, operator-configured
  URI — not attacker input).
- Algorithm: taken from the *matched JWK itself* (its `alg`, or inferred
  from `kty`/`crv` when absent), never from the caller's own JWT header —
  this is what actually prevents an algorithm-confusion downgrade, not the
  `kid` lookup by itself.
- Symmetric (`oct`) keys are rejected: an OAuth2 Bearer resource server
  should never be configured with a shared HMAC secret it would need to
  keep as confidential as the authorization server's own signing key.
- Standard claim checks: `exp` (and `nbf` if present) always; `iss`/`aud`
  when configured; `scope` contains `OAUTH2_REQUIRED_SCOPE` when
  configured.

## Response shape

- No `Authorization: Bearer ...` header, or a token that fails
  verification: `401`, with a `WWW-Authenticate: Bearer` header (RFC 6750).
- Valid token, missing required scope: `403`.
- Gating not configured at all: unchanged behavior (no auth required).

## Status

Landed exactly as scoped above, with one clarification and one addition
found during implementation, neither a behavior change:

- `OAUTH2_AUDIENCE` unset must mean "don't check `aud` at all" (as this
  document already said), not "reject any token that happens to carry an
  `aud` claim" — `jsonwebtoken::Validation` defaults to the latter once no
  expected audience is set, so `OAuth2Verifier::verify` explicitly sets
  `validation.validate_aud = false` in that case. Covered by
  `oauth2::tests::verify_accepts_a_token_with_an_aud_claim_when_audience_is_not_configured`.
- `OAuth2Verifier` needed a hand-written `Debug` impl (`jsonwebtoken::DecodingKey`
  doesn't derive one) that prints the config and the loaded `kid`s only —
  never key material.

A follow-up adversarial security review pass (two independent lenses —
crypto correctness, route coverage) found the algorithm-confusion guard,
key selection, `exp`/`nbf` handling, and route wiring all sound, but the
fix pass it triggered caught one real gap the reviewers themselves missed:
`OAuth2Verifier::verify` called `set_issuer`/`set_audience` when
`OAUTH2_ISSUER`/`OAUTH2_AUDIENCE` were configured, but `jsonwebtoken` only
checks those claims *if present* on the token — it never required them to
be present at all. A validly-signed token from the configured JWKS that
simply omitted `iss`/`aud` sailed through unchecked, defeating the point of
setting those env vars. Reproduced RED first
(`verify_rejects_a_token_with_no_{aud,iss}_claim_at_all_when_{audience,issuer}_is_configured`),
then fixed by adding `"iss"`/`"aud"` to `validation.required_spec_claims`
whenever the corresponding config is set — commit `95290e9`.

**Module:** `crates/ds-catalog-broker-rs/src/oauth2.rs` —
`OAuth2Config { jwks_uri, issuer, audience, required_scope }`,
`OAuth2Verifier::fetch(&reqwest::Client, OAuth2Config) -> Result<Self, JwksError>`,
`OAuth2Verifier::verify(&self, token: &str) -> Result<serde_json::Value, VerifyError>`.
`JwksError` (`Fetch`, `Parse`, `NoUsableKeys`) covers construction;
`VerifyError` (`UnknownKid`, `InvalidToken`, `InsufficientScope`) covers
verification, with `InsufficientScope` kept distinct precisely so the
router can answer `403` instead of `401`.

**Wiring:** `AppState` gained `oauth2: Option<Arc<OAuth2Verifier>>` and a
`with_oauth2` builder (mirrors `with_sparql`/`with_holder`).
`check_oauth2_bearer` gates `GET /catalog` and `GET`/`POST /sparql` only;
`/health` and the two `/dsp/holder/*` routes are untouched. `main.rs`'s
`load_oauth2_config` reads the four `OAUTH2_*` env vars from the config
table above and fetches the verifier eagerly, before `AppState` is built;
a configured-but-bad JWKS panics at boot with a clear message (same
posture as `CRAWLER_CONFIG_PATH`).

**Response/status-code shapes, exactly as implemented** (both gated
routes, identical behavior):

| Condition | Status | Notes |
|---|---|---|
| `AppState::oauth2` is `None` (env var unset) | unchanged | Every pre-existing test for both routes passes unmodified. |
| No `Authorization` header, or not a `Bearer` token | `401` | `WWW-Authenticate: Bearer` header set (RFC 6750). |
| Token fails to parse/verify (bad signature, unknown `kid`, expired, wrong `iss`/`aud` when configured) | `401` | Same `WWW-Authenticate: Bearer` header. |
| Token verifies, but its `scope` claim doesn't contain `OAUTH2_REQUIRED_SCOPE` | `403` | No `WWW-Authenticate` header — this is an authorization failure, not an authentication one. |
| Token verifies and (if configured) carries the required scope | route's normal response | e.g. `200` with the real catalog/SPARQL body. |

**Tests:** the `ds-catalog-broker-rs` crate's own unit test binary grew
from 13 tests (before this branch) to 41 — 18 new unit tests in
`oauth2.rs` (JWKS fetch/parse, `kid` lookup, oct-key and unsupported-curve
skipping, algorithm inference from both `alg` and `kty`/`crv`, `exp`,
`iss`, `aud` — including the "aud claim present but unconfigured" guard
above — and `scope`) plus 10 new router-level integration tests in `lib.rs`
(both `/catalog` and `/sparql`, real `oneshot` requests through
`build_router`, a real mock JWKS HTTP server per
`crates/crawler/tests/multi_participant_crawl.rs`'s established pattern,
and confirmation that `/health` stays reachable with no token even when
gating is configured), plus 2 further regression tests from the security
fix above (`43` total in this crate's own `--lib` binary as of `95290e9`).
`cargo test --workspace`: all suites `ok`, 0 failed, 1
ignored (an unrelated test requiring three real running EDC instances).

**Deviations from the initial design doc:** none in scope or shape — the
only two adjustments are the `validate_aud` clarification and the
`Debug` impl noted above, both implementation details invisible to a
caller of this API.
