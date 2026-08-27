#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Validates the OTLP JSONL produced by the e2e-otel-jsonl CI job against the
# guarantees the reducer -> otelcol pipeline is expected to uphold for
# tcp.bytes metrics. Fails (non-zero exit) when:
#   (a) no tcp.bytes data points are present at all;
#   (b) a tcp.bytes data point is missing one of the required label keys;
#   (c) any tcp.bytes data point's value is negative, NaN, or otherwise not a
#       finite number (tcp.bytes is a counter: 0 is legitimate for flows the
#       test does not control, e.g. runner instance-metadata traffic - only
#       the sign/finiteness invariant holds universally);
#   (d) the known e2e traffic-generator flow (dest.namespace.name=e2e-kind,
#       dest.workload.name=e2e-wget - the wget-to-example.com pod this job
#       deploys) reports a non-positive value. This is the one flow the test
#       actually drives, so the pipeline guarantees it transferred >0 bytes;
#       a zero here means the reducer lost/miscounted the generated traffic.
#
# This is intentionally a "smoke-plus" gate (existence + labels + scoped
# positivity), not a value-band check: see D8 in the reducer test-suite spec.
#
# Usage: validate-otel-jsonl.sh [path/to/otel.jsonl]

set -euo pipefail

FILE="${1:-e2e-out/otel.jsonl}"
REQUIRED_LABELS='["sf_product","source.namespace.name","source.pod"]'
EXPECTED_SF_PRODUCT="network-explorer"
# The e2e traffic-generator flow this job deploys (see build-and-test.yaml's
# e2e-wget Deployment in namespace e2e-kind): the only flow the pipeline is
# guaranteed to report a positive tcp.bytes value for, since we control the
# traffic (wget to example.com). Other flows (e.g. runner instance-metadata
# traffic) may legitimately report 0 bytes in a given interval.
SMOKE_DEST_NAMESPACE="e2e-kind"
SMOKE_DEST_WORKLOAD="e2e-wget"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found; attempting to install"
  sudo apt-get update && sudo apt-get install -y jq
fi

if [ ! -f "$FILE" ]; then
  echo "::error::$FILE not found - collector produced no output"
  exit 1
fi

echo "=== Validating reducer output: $FILE ==="

DATAPOINTS=$(jq -s -c '
  [ .[]
    | .resourceMetrics[]?
    | .scopeMetrics[]?
    | .metrics[]?
    | select(.name == "tcp.bytes")
    | (.sum.dataPoints // [])[]
  ]
' "$FILE")

COUNT=$(jq 'length' <<<"$DATAPOINTS")
echo "tcp.bytes data points found: $COUNT"

if [ "$COUNT" -eq 0 ]; then
  echo "::error::no tcp.bytes data points found in $FILE - reducer produced no TCP metrics"
  exit 1
fi

VIOLATIONS=$(jq --argjson required "$REQUIRED_LABELS" --arg expected_product "$EXPECTED_SF_PRODUCT" \
  --arg smoke_ns "$SMOKE_DEST_NAMESPACE" --arg smoke_workload "$SMOKE_DEST_WORKLOAD" '
  def label_keys: (.attributes // []) | map(.key);
  def label_value(k):
    (.attributes // []) | map(select(.key == k)) | (.[0].value // {})
    | (.stringValue // .intValue // .doubleValue // .boolValue // null);
  def numeric_value:
    (.asInt // .asDouble // null) as $v
    | if $v == null then null
      else (try ($v | tostring | tonumber) catch null) end;

  [ .[]
    | . as $dp
    | ($dp | label_keys) as $keys
    | ($required - $keys) as $missing
    | ($dp | numeric_value) as $val
    | (($dp | label_value("dest.namespace.name")) == $smoke_ns
       and ($dp | label_value("dest.workload.name")) == $smoke_workload) as $is_smoke_flow
    | {
        missing_labels: $missing,
        bad_product: (($dp | label_value("sf_product")) != $expected_product),
        value: $val,
        is_smoke_flow: $is_smoke_flow
      }
    | select(
        ($missing | length) > 0
        or .bad_product
        or (.value == null)
        or (.value != .value)
        or (.value < 0)
        or (.is_smoke_flow and .value <= 0)
      )
    | {missing_labels, bad_product, value, is_smoke_flow, attributes: $dp.attributes}
  ]
' <<<"$DATAPOINTS")

VIOLATION_COUNT=$(jq 'length' <<<"$VIOLATIONS")

if [ "$VIOLATION_COUNT" -gt 0 ]; then
  echo "::error::$VIOLATION_COUNT tcp.bytes data point(s) failed validation (missing required labels, wrong sf_product, negative/NaN value, or non-positive value on the e2e-wget smoke flow)"
  echo "$VIOLATIONS" | jq '.'
  exit 1
fi

echo "OK: $COUNT tcp.bytes data point(s) all have required labels, non-negative/finite values, and the e2e-wget smoke flow reports positive bytes"
