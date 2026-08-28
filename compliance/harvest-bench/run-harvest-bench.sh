#!/usr/bin/env bash
# End-to-end driver for compliance/harvest-benchmark-2026-08-27.md: measures
# EDC's own federated-catalog crawler and this project's crates/crawler +
# ds-catalog-broker-rs under the SAME condition - a background harvesting
# loop actively re-crawling two real EDC 0.18.0 participants (3 + 7
# datasets) WHILE the system's own catalog-serving endpoint is under k6
# load - not harvesting in isolation, and not serving in isolation. See
# the report for why this combination matters and for the actual numbers
# this run produced. ds-catalog-broker-rs serves its aggregated catalog at
# `GET /catalog`, not a DSP `POST /catalog/request` - it stopped answering
# the DSP catalog protocol as a provider once that surface was removed
# (see ../../docs/gap-analysis-2026-08-27.md).
#
# Reuses, unchanged: ../crawler-edc-fixture/run-instance.sh (the two new
# "harvest" EDC participants), the k6/RSS-CPU-sampling methodology from
# ../benchmark-2026-08-27.md and ../benchmark-dcp-2026-08-27.md.
#
# Port scheme (all fresh, none overlapping the existing EDC-A/B/C fixture
# instances at 18901-18961/19001-19061/19101-19161):
#   HARVEST-D   BASE_PORT=19201  (DSP protocol port 19221)
#   HARVEST-E   BASE_PORT=19301  (DSP protocol port 19321)
#   EDC crawler BASE_PORT=19401  (Management API port 19411)
#   Rust http-api  127.0.0.1:19501
#
# Usage: ./run-harvest-bench.sh
# Output: ./results/ (created fresh each run) - k6 summaries, RSS/CPU CSVs,
# correctness-check output, EDC/Rust process logs.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/../crawler-edc-fixture"
FEDCAT_DIR="$SCRIPT_DIR/edc-fedcat-runtime"
REPO_ROOT="$SCRIPT_DIR/../.."
RESULTS_DIR="$SCRIPT_DIR/results"

HARVEST_D_BASE_PORT=19201
HARVEST_E_BASE_PORT=19301
FEDCAT_BASE_PORT=19401
RUST_ADDR="127.0.0.1:19501"

HARVEST_D_DSP="http://127.0.0.1:$((HARVEST_D_BASE_PORT + 20))/api/dsp/2025-1"
HARVEST_E_DSP="http://127.0.0.1:$((HARVEST_E_BASE_PORT + 20))/api/dsp/2025-1"
FEDCAT_MGMT_PORT=$((FEDCAT_BASE_PORT + 10))
FEDCAT_MGMT_URL="http://127.0.0.1:$FEDCAT_MGMT_PORT/api/management/v3/catalogs/request"

ALL_PORTS_PATTERN="19201|19211|19221|19231|19241|19251|19261|19301|19311|19321|19331|19341|19351|19361|19401|19411|19421|19431|19451|19461|19501"

PIDS_TO_CLEAN=()

log() { echo "[run-harvest-bench] $*" >&2; }

cleanup() {
  log "cleanup: killing any tracked PIDs and sweeping ports $ALL_PORTS_PATTERN"
  for p in "${PIDS_TO_CLEAN[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
  sleep 2
  for p in "${PIDS_TO_CLEAN[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
  sleep 1
  log "post-cleanup port sweep:"
  ss -tlnp 2>/dev/null | grep -E "$ALL_PORTS_PATTERN" || log "  (clean - no listeners in this benchmark's port range)"
}
trap cleanup EXIT

mkdir -p "$RESULTS_DIR"
mkdir -p "$FIXTURE_DIR/logs"
mkdir -p "$FEDCAT_DIR/logs"

# --- Pre-flight: build everything needed -----------------------------------
log "building crawler-edc-fixture classpath (if not already built)"
( cd "$FIXTURE_DIR" && ./gradlew --console=plain printClasspath ) || { log "FATAL: fixture build failed"; exit 1; }

log "building edc-fedcat-runtime classpath (if not already built)"
( cd "$FEDCAT_DIR" && ./gradlew --console=plain printClasspath ) || { log "FATAL: edc-fedcat-runtime build failed"; exit 1; }

log "building ds-catalog-broker-rs release binary (if not already built)"
( cd "$REPO_ROOT" && cargo build --release -p ds-catalog-broker-rs ) || { log "FATAL: cargo build failed"; exit 1; }

# --- Start the two new HARVEST EDC participants (shared by both phases) ---
log "starting HARVEST-D (3 datasets, BASE_PORT=$HARVEST_D_BASE_PORT)"
( cd "$FIXTURE_DIR" && INSTANCE_NAME=harvest-d BASE_PORT=$HARVEST_D_BASE_PORT \
    FIXTURE_PARTICIPANT_ID=HARVEST-D FIXTURE_ASSET_IDS="HARVEST-D-01,HARVEST-D-02,HARVEST-D-03" \
    nohup ./run-instance.sh > "$RESULTS_DIR/harvest-d-stdout.log" 2>&1 & )
log "starting HARVEST-E (7 datasets, BASE_PORT=$HARVEST_E_BASE_PORT)"
( cd "$FIXTURE_DIR" && INSTANCE_NAME=harvest-e BASE_PORT=$HARVEST_E_BASE_PORT \
    FIXTURE_PARTICIPANT_ID=HARVEST-E FIXTURE_ASSET_IDS="HARVEST-E-01,HARVEST-E-02,HARVEST-E-03,HARVEST-E-04,HARVEST-E-05,HARVEST-E-06,HARVEST-E-07" \
    nohup ./run-instance.sh > "$RESULTS_DIR/harvest-e-stdout.log" 2>&1 & )

sleep 10
D_PID=$(ss -tlnp 2>/dev/null | grep ":$((HARVEST_D_BASE_PORT + 20)) " | grep -oP 'pid=\K[0-9]+' | head -1)
E_PID=$(ss -tlnp 2>/dev/null | grep ":$((HARVEST_E_BASE_PORT + 20)) " | grep -oP 'pid=\K[0-9]+' | head -1)
if [ -z "$D_PID" ] || [ -z "$E_PID" ]; then
  log "FATAL: HARVEST-D or HARVEST-E did not come up (D_PID=$D_PID E_PID=$E_PID)"
  log "--- harvest-d.log tail ---"; tail -n 40 "$FIXTURE_DIR/logs/harvest-d.log" 2>&1
  log "--- harvest-e.log tail ---"; tail -n 40 "$FIXTURE_DIR/logs/harvest-e.log" 2>&1
  exit 1
fi
PIDS_TO_CLEAN+=("$D_PID" "$E_PID")
log "HARVEST-D pid=$D_PID HARVEST-E pid=$E_PID - both listening"

curl -s -o /dev/null -w "HARVEST-D direct curl HTTP_STATUS:%{http_code}\n" -X POST "$HARVEST_D_DSP/catalog/request" \
  -H "Content-Type: application/json" -H "Authorization: harvest-bench-placeholder" \
  -d '{"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"], "@type": "CatalogRequestMessage"}'
curl -s -o /dev/null -w "HARVEST-E direct curl HTTP_STATUS:%{http_code}\n" -X POST "$HARVEST_E_DSP/catalog/request" \
  -H "Content-Type: application/json" -H "Authorization: harvest-bench-placeholder" \
  -d '{"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"], "@type": "CatalogRequestMessage"}'

# =========================== PHASE 1: EDC's own federated-catalog crawler ===
log "=== PHASE 1: EDC's own federated-catalog crawler ==="
HARVEST_TARGET_NODES="harvest-d=Harvest D=$HARVEST_D_DSP;harvest-e=Harvest E=$HARVEST_E_DSP"
( cd "$FEDCAT_DIR" && BASE_PORT=$FEDCAT_BASE_PORT HARVEST_TARGET_NODES="$HARVEST_TARGET_NODES" CRAWL_PERIOD_SECONDS=5 \
    nohup ./run-fedcat-crawler.sh > "$RESULTS_DIR/edc-fedcat-stdout.log" 2>&1 & )

sleep 8
FEDCAT_PID=$(ss -tlnp 2>/dev/null | grep ":$FEDCAT_MGMT_PORT " | grep -oP 'pid=\K[0-9]+' | head -1)
if [ -z "$FEDCAT_PID" ]; then
  log "FATAL: EDC federated-catalog crawler did not come up"
  tail -n 60 "$FEDCAT_DIR/logs/fedcat-crawler.log" 2>&1
  exit 1
fi
PIDS_TO_CLEAN+=("$FEDCAT_PID")
log "EDC federated-catalog crawler pid=$FEDCAT_PID, waiting for first crawl cycle to complete"
sleep 8

log "correctness check #1 (early, before load)"
python3 "$SCRIPT_DIR/check_catalog.py" edc "$FEDCAT_MGMT_URL" | tee "$RESULTS_DIR/edc-correctness-early.txt"
EDC_EARLY_STATUS=$?

log "starting RSS/CPU sampler on EDC crawler pid=$FEDCAT_PID for 35s (background)"
bash "$SCRIPT_DIR/sample-rss-cpu.sh" "$FEDCAT_PID" 35 "$RESULTS_DIR/edc-rss-cpu.csv" &
SAMPLER_PID=$!

log "running k6 against EDC crawler's Management API endpoint ($FEDCAT_MGMT_URL) while crawl loop keeps running"
EDC_QUERYSPEC_BODY='{"@type":"https://w3id.org/edc/v0.0.1/ns/QuerySpec"}'
k6 run -e TARGET_URL="$FEDCAT_MGMT_URL" -e BODY="$EDC_QUERYSPEC_BODY" \
    "$SCRIPT_DIR/catalog-request.k6.js" 2>&1 | tee "$RESULTS_DIR/edc-k6.log"

log "correctness check #2 (immediately after load)"
python3 "$SCRIPT_DIR/check_catalog.py" edc "$FEDCAT_MGMT_URL" | tee "$RESULTS_DIR/edc-correctness-late.txt"
EDC_LATE_STATUS=$?

wait "$SAMPLER_PID" 2>/dev/null || true

log "stopping EDC federated-catalog crawler pid=$FEDCAT_PID"
kill "$FEDCAT_PID" 2>/dev/null || true
sleep 3
kill -0 "$FEDCAT_PID" 2>/dev/null && { log "still alive, force killing"; kill -9 "$FEDCAT_PID"; } || log "EDC crawler stopped cleanly"
cp "$FEDCAT_DIR/logs/fedcat-crawler.log" "$RESULTS_DIR/edc-fedcat-crawler.log" 2>/dev/null || true

# =========================== PHASE 2: this project's crates/crawler + ds-catalog-broker-rs ===
log "=== PHASE 2: ds-catalog-broker-rs (crates/crawler + ds-catalog-broker-rs) ==="
( cd "$REPO_ROOT" && HTTP_API_ADDR="$RUST_ADDR" CRAWLER_CONFIG_PATH="$SCRIPT_DIR/participants.toml" \
    nohup ./target/release/ds-catalog-broker-rs > "$RESULTS_DIR/rust-http-api.log" 2>&1 & )

sleep 5
RUST_PID=$(ss -tlnp 2>/dev/null | grep ":19501 " | grep -oP 'pid=\K[0-9]+' | head -1)
if [ -z "$RUST_PID" ]; then
  log "FATAL: ds-catalog-broker-rs did not come up"
  tail -n 60 "$RESULTS_DIR/rust-http-api.log" 2>&1
  exit 1
fi
PIDS_TO_CLEAN+=("$RUST_PID")
log "ds-catalog-broker-rs pid=$RUST_PID, waiting for first crawl cycle to complete"
sleep 8

RUST_URL="http://$RUST_ADDR/catalog"
log "correctness check #1 (early, before load)"
python3 "$SCRIPT_DIR/check_catalog.py" rust "$RUST_URL" | tee "$RESULTS_DIR/rust-correctness-early.txt"
RUST_EARLY_STATUS=$?

log "starting RSS/CPU sampler on ds-catalog-broker-rs pid=$RUST_PID for 35s (background)"
bash "$SCRIPT_DIR/sample-rss-cpu.sh" "$RUST_PID" 35 "$RESULTS_DIR/rust-rss-cpu.csv" &
SAMPLER_PID=$!

log "running k6 against ds-catalog-broker-rs's catalog-serving endpoint ($RUST_URL) while crawl loop keeps running"
k6 run -e TARGET_URL="$RUST_URL" -e METHOD=GET \
    "$SCRIPT_DIR/catalog-request.k6.js" 2>&1 | tee "$RESULTS_DIR/rust-k6.log"

log "correctness check #2 (immediately after load)"
python3 "$SCRIPT_DIR/check_catalog.py" rust "$RUST_URL" | tee "$RESULTS_DIR/rust-correctness-late.txt"
RUST_LATE_STATUS=$?

wait "$SAMPLER_PID" 2>/dev/null || true

log "stopping ds-catalog-broker-rs pid=$RUST_PID"
kill "$RUST_PID" 2>/dev/null || true
sleep 2
kill -0 "$RUST_PID" 2>/dev/null && { log "still alive, force killing"; kill -9 "$RUST_PID"; } || log "ds-catalog-broker-rs stopped cleanly"

log "=== SUMMARY ==="
log "EDC   correctness: early=$([ $EDC_EARLY_STATUS -eq 0 ] && echo OK || echo FAIL)  late=$([ $EDC_LATE_STATUS -eq 0 ] && echo OK || echo FAIL)"
log "Rust  correctness: early=$([ $RUST_EARLY_STATUS -eq 0 ] && echo OK || echo FAIL)  late=$([ $RUST_LATE_STATUS -eq 0 ] && echo OK || echo FAIL)"
log "results saved under $RESULTS_DIR"
log "(cleanup of HARVEST-D/E and any stray processes happens in the EXIT trap below)"
