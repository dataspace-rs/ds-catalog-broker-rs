#!/usr/bin/env python3
"""Correctness check for compliance/harvest-benchmark-2026-08-27.md: query
either system's own catalog-serving endpoint and assert the aggregated
result contains exactly the 10 expected harvested dataset ids
(HARVEST-D-01..03, HARVEST-E-01..07).

Usage:
  check_catalog.py edc  <management-api-base-url>
  check_catalog.py rust <dsp-catalog-request-url>

Exits 0 and prints "OK <sorted-ids>" on success, exits 1 and prints
"MISMATCH expected=... got=..." otherwise. Always prints the raw
observed id set so a failure is legible without re-running anything.
"""
import json
import sys
import urllib.request

EXPECTED = {f"HARVEST-D-{i:02d}" for i in range(1, 4)} | {f"HARVEST-E-{i:02d}" for i in range(1, 8)}


def post(url, body, headers=None):
    req = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def dataset_ids_from_catalog(catalog_obj):
    """Collect dataset ids from a DSP Catalog object, recursing into any
    nested `catalog[]` entries. ds-catalog-broker-rs's crate (crates/ds-catalog-broker-rs,
    formerly crates/http-api) nests one
    `DspCatalog` per origin node under a top-level `catalog[]` (with the
    outer document's own `dataset`/`service` left empty) whenever the
    cache holds 2+ distinct origin nodes - see crates/ds-catalog-broker-rs/src/lib.rs's
    `catalog_request`. EDC's own Management API response (a flat top-level
    `dataset` per Catalog, one Catalog per crawled participant, no nested
    `catalog` field on either) is unaffected - the recursion is a no-op
    when `catalog` is absent or empty."""
    ids = {ds.get("@id") for ds in catalog_obj.get("dataset", [])}
    for nested in catalog_obj.get("catalog", []):
        ids |= dataset_ids_from_catalog(nested)
    return ids


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    mode, url = sys.argv[1], sys.argv[2]

    if mode == "edc":
        body = '{"@type":"https://w3id.org/edc/v0.0.1/ns/QuerySpec"}'
        catalogs = post(url, body)
        ids = set()
        for catalog in catalogs:
            ids |= dataset_ids_from_catalog(catalog)
    elif mode == "rust":
        body = json.dumps({
            "@context": ["https://w3id.org/dspace/2025/1/context.jsonld"],
            "@type": "CatalogRequestMessage",
        })
        catalog = post(url, body)
        ids = dataset_ids_from_catalog(catalog)
    else:
        print(f"unknown mode {mode!r}, expected 'edc' or 'rust'")
        sys.exit(2)

    if ids == EXPECTED:
        print(f"OK {sorted(ids)}")
        sys.exit(0)
    else:
        print(f"MISMATCH expected={sorted(EXPECTED)} got={sorted(ids)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
