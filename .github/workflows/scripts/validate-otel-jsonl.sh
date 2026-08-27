#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Validates the OTLP JSONL produced by the e2e-otel-jsonl CI job against the
# guarantees the reducer -> otelcol pipeline is expected to uphold for
# tcp.bytes metrics. Fails (non-zero exit) when:
#   (a) no tcp.bytes data points are present at all;
#   (b) a tcp.bytes data point is missing one of the required label keys;
#   (c) a tcp.bytes data point's value is non-positive, NaN, or otherwise not
#       a finite number, where the pipeline guarantees positivity.
#
# This is intentionally a "smoke-plus" gate (existence + labels + positivity),
# not a value-band check: see D8 in the reducer test-suite spec.
#
# Usage: validate-otel-jsonl.sh [path/to/otel.jsonl]

set -euo pipefail

FILE="${1:-e2e-out/otel.jsonl}"
REQUIRED_LABELS='["sf_product","source.namespace.name","source.pod"]'
EXPECTED_SF_PRODUCT="network-explorer"

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

VIOLATIONS=$(jq --argjson required "$REQUIRED_LABELS" --arg expected_product "$EXPECTED_SF_PRODUCT" '
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
    | {
        missing_labels: $missing,
        bad_product: (($dp | label_value("sf_product")) != $expected_product),
        value: $val
      }
    | select(
        ($missing | length) > 0
        or .bad_product
        or ($val == null)
        or ($val <= 0)
        or ($val != $val)
      )
    | {missing_labels, bad_product, value: $val, attributes: $dp.attributes}
  ]
' <<<"$DATAPOINTS")

VIOLATION_COUNT=$(jq 'length' <<<"$VIOLATIONS")

if [ "$VIOLATION_COUNT" -gt 0 ]; then
  echo "::error::$VIOLATION_COUNT tcp.bytes data point(s) failed validation (missing required labels, wrong sf_product, or non-positive/NaN value)"
  echo "$VIOLATIONS" | jq '.'
  exit 1
fi

echo "OK: $COUNT tcp.bytes data point(s) all have required labels and positive values"
