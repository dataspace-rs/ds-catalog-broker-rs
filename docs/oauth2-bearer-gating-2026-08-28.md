# OAuth2 Bearer gating for the non-DSP serving surfaces

**Date:** 2026-08-28
**Status:** in progress — this document is written first and updated as the
corresponding TDD implementation pass lands, tracked in
[PR TBD](.) on branch `feature/oauth2-bearer-gating`.

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

Implementation, tests, and the final verified response/error shapes will
be filled in here as the TDD pass lands — this section is the one part of
this document expected to change after initial commit.
