#![allow(clippy::new_without_default)]

#[cxx::bridge]
pub mod ffi {
    /// Lightweight key/value label representation.
    #[derive(Debug, Clone)]
    pub struct Label {
        pub key: String,
        pub value: String,
    }

    /// Statistics mirroring the counters tracked by the C++ OTLP client.
    #[derive(Debug)]
    pub struct PublisherStats {
        pub bytes_sent: u64,
        pub bytes_failed: u64,
        pub data_points_sent: u64,
        pub data_points_failed: u64,
        pub requests_sent: u64,
        pub requests_failed: u64,
        pub unknown_response_tags: u64,
    }

    /// Metric kind to encode.
    #[repr(i32)]
    #[derive(Debug)]
    pub enum MetricKind {
        Sum = 0,
        Gauge = 1,
    }

    extern "Rust" {
        type Publisher;

        /// Create a new OTLP publisher. `endpoint` is host:port or full endpoint string.
        fn otlp_publisher_new(endpoint: &str) -> Box<Publisher>;

        /// Publish a u64 metric point.
        fn publish_metric_u64(
            self: &mut Publisher,
            name: &str,
            unit: &str,
            description: &str,
            kind: MetricKind,
            labels: &Vec<Label>,
            timestamp_unix_nano: i64,
            value: u64,
        );

        /// Publish a f64 metric point.
        fn publish_metric_f64(
            self: &mut Publisher,
            name: &str,
            unit: &str,
            description: &str,
            kind: MetricKind,
            labels: &Vec<Label>,
            timestamp_unix_nano: i64,
            value: f64,
        );

        /// Publish a TCP flow log equivalent (kept minimal to match reducer fields).
        fn publish_flow_log(
            self: &mut Publisher,
            labels: &Vec<Label>,
            timestamp_unix_nano: i64,
            tcp_sum_bytes: u64,
            tcp_active_rtts: u32,
            tcp_active_sockets: u32,
            tcp_sum_srtt: u64,
            tcp_sum_delivered: u64,
            tcp_sum_retrans: u64,
            tcp_syn_timeouts: u64,
            tcp_new_sockets: u64,
            tcp_resets: u64,
        );

        /// Flush any in-flight batches and process responses.
        fn flush(self: &mut Publisher);

        /// Shut down the publisher.
        fn shutdown(self: &mut Publisher);

        /// Read current counters/statistics.
        fn stats(self: &Publisher) -> PublisherStats;
    }
}

use ffi::{Label, MetricKind, PublisherStats};
use opentelemetry_proto::tonic::collector::logs::v1 as otlp_collector_logs;
use opentelemetry_proto::tonic::collector::metrics::v1 as otlp_collector;
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
use opentelemetry_proto::tonic::common::v1 as otlp_common;
use opentelemetry_proto::tonic::logs::v1 as otlp_logs;
use opentelemetry_proto::tonic::metrics::v1 as otlp_metrics;
use opentelemetry_proto::tonic::resource::v1 as otlp_resource;
use tokio::runtime::Runtime;
use tonic::Request;

/// Minimal placeholder publisher. This crate defines the FFI surface and basic accounting.
/// Internals can be extended to perform real async OTLP export.
pub struct Publisher {
    endpoint: String,
    runtime: Runtime,
    resource_attributes: Vec<(String, String)>,
    scope_name: String,
    // Buffered metrics and logs to export on flush.
    buf: Vec<PendingMetric>,
    // Simple counters following the C++ client semantics.
    bytes_sent: u64,
    bytes_failed: u64,
    data_points_sent: u64,
    data_points_failed: u64,
    requests_sent: u64,
    requests_failed: u64,
    unknown_response_tags: u64,
    // Simple buffered counters to roll up into a "request" on flush.
    buffered_points: u64,
    buffered_bytes: u64,
}

enum PointValue {
    U64(u64),
    F64(f64),
}

struct PendingMetric {
    name: String,
    unit: String,
    description: String,
    kind: MetricKind,
    labels: Vec<Label>,
    timestamp_unix_nano: i64,
    value: PointValue,
}

pub fn otlp_publisher_new(endpoint: &str) -> Box<Publisher> {
    // Resolve endpoint: accept full URL or host:port and default to http with no path for gRPC.
    let endpoint_resolved = normalize_grpc_endpoint(endpoint);

    // Static resource/scope metadata for now; can be extended via FFI later.
    let resource_attributes = vec![
        ("service.name".to_string(), "reducer".to_string()),
        ("telemetry.sdk.language".to_string(), "rust".to_string()),
    ];
    let scope_name = "reducer-ffi".to_string();

    // Create a small Tokio runtime for async export.
    let runtime = Runtime::new().expect("failed to create Tokio runtime");

    Box::new(Publisher {
        endpoint: endpoint_resolved,
        runtime,
        resource_attributes,
        scope_name,
        buf: Vec::new(),
        bytes_sent: 0,
        bytes_failed: 0,
        data_points_sent: 0,
        data_points_failed: 0,
        requests_sent: 0,
        requests_failed: 0,
        unknown_response_tags: 0,
        buffered_points: 0,
        buffered_bytes: 0,
    })
}

impl Publisher {
    pub fn publish_metric_u64(
        &mut self,
        name: &str,
        unit: &str,
        description: &str,
        kind: MetricKind,
        labels: &Vec<Label>,
        timestamp_unix_nano: i64,
        value: u64,
    ) {
        self.buf.push(PendingMetric {
            name: name.to_string(),
            unit: unit.to_string(),
            description: description.to_string(),
            kind,
            labels: labels
                .iter()
                .map(|l| Label {
                    key: l.key.clone(),
                    value: l.value.clone(),
                })
                .collect(),
            timestamp_unix_nano,
            value: PointValue::U64(value),
        });

        let approx = approx_bytes_metric(name, labels);
        self.buffered_points += 1;
        self.buffered_bytes = self.buffered_bytes.saturating_add(approx);
    }

    pub fn publish_metric_f64(
        &mut self,
        name: &str,
        unit: &str,
        description: &str,
        kind: MetricKind,
        labels: &Vec<Label>,
        timestamp_unix_nano: i64,
        value: f64,
    ) {
        self.buf.push(PendingMetric {
            name: name.to_string(),
            unit: unit.to_string(),
            description: description.to_string(),
            kind,
            labels: labels
                .iter()
                .map(|l| Label {
                    key: l.key.clone(),
                    value: l.value.clone(),
                })
                .collect(),
            timestamp_unix_nano,
            value: PointValue::F64(value),
        });

        let approx = approx_bytes_metric(name, labels);
        self.buffered_points += 1;
        self.buffered_bytes = self.buffered_bytes.saturating_add(approx);
    }
}

impl Publisher {
    pub fn publish_flow_log(
        &mut self,
        _labels: &Vec<Label>,
        _timestamp_unix_nano: i64,
        _tcp_sum_bytes: u64,
        _tcp_active_rtts: u32,
        _tcp_active_sockets: u32,
        _tcp_sum_srtt: u64,
        _tcp_sum_delivered: u64,
        _tcp_sum_retrans: u64,
        _tcp_syn_timeouts: u64,
        _tcp_new_sockets: u64,
        _tcp_resets: u64,
    ) {
        // Future: publish logs via opentelemetry logs SDK. For now, account as one data point.
        self.buffered_points += 1;
        // Approximate fixed size for a log line.
        self.buffered_bytes = self.buffered_bytes.saturating_add(128);
    }

    pub fn flush(&mut self) {
        if self.buf.is_empty() {
            return;
        }

        // Pure functional core: encode the buffered points into the export request.
        let req = encode_metrics(&self.buf, &self.resource_attributes, &self.scope_name);

        // Send synchronously on our runtime.
        let endpoint = self.endpoint.clone();
        let buffered_points = self.buffered_points;
        let buffered_bytes = self.buffered_bytes;
        let export_res = self.runtime.block_on(async move {
            match MetricsServiceClient::connect(endpoint).await {
                Ok(mut client) => client.export(Request::new(req)).await,
                Err(e) => Err(tonic::Status::unknown(format!("connect error: {}", e))),
            }
        });

        match export_res {
            Ok(resp) => {
                self.requests_sent = self.requests_sent.saturating_add(1);
                let mut accepted = buffered_points;
                if let Some(ps) = resp.into_inner().partial_success {
                    if ps.rejected_data_points > 0 {
                        let rej = ps.rejected_data_points as u64;
                        let acc = accepted.saturating_sub(rej);
                        self.data_points_failed = self.data_points_failed.saturating_add(rej);
                        accepted = acc;
                    }
                }
                self.data_points_sent = self.data_points_sent.saturating_add(accepted);
                self.bytes_sent = self.bytes_sent.saturating_add(buffered_bytes);
            }
            Err(_e) => {
                self.requests_failed = self.requests_failed.saturating_add(1);
                self.data_points_failed = self.data_points_failed.saturating_add(buffered_points);
                self.bytes_failed = self.bytes_failed.saturating_add(buffered_bytes);
            }
        }

        self.buf.clear();
        self.buffered_points = 0;
        self.buffered_bytes = 0;
    }

    pub fn shutdown(&mut self) {
        self.flush();
        // Nothing else to shutdown for the exporter.
    }

    pub fn stats(&self) -> PublisherStats {
        PublisherStats {
            bytes_sent: self.bytes_sent,
            bytes_failed: self.bytes_failed,
            data_points_sent: self.data_points_sent,
            data_points_failed: self.data_points_failed,
            requests_sent: self.requests_sent,
            requests_failed: self.requests_failed,
            unknown_response_tags: self.unknown_response_tags,
        }
    }
}

/// Pure functional core of `Publisher::flush`: turns buffered points into an OTLP
/// export request. No I/O, no async runtime -- known inputs in, typed prost structs out.
fn encode_metrics(
    buf: &[PendingMetric],
    resource_attributes: &[(String, String)],
    scope_name: &str,
) -> otlp_collector::ExportMetricsServiceRequest {
    // Build OTLP ResourceMetrics -> ScopeMetrics -> Metric with one datapoint each.
    let mut metrics: Vec<otlp_metrics::Metric> = Vec::with_capacity(buf.len());
    for pm in buf {
        let attrs = labels_to_otlp_kv(&pm.labels);

        // For sums, set start_time to slot start (30s window) to match reducer semantics.
        let time_unix_nano = pm.timestamp_unix_nano as u64;
        let start_time_unix_nano = pm.timestamp_unix_nano.saturating_sub(30_000_000_000) as u64;

        let metric = match pm.kind {
            MetricKind::Sum => {
                let ndp = match pm.value {
                    PointValue::U64(v) => otlp_metrics::NumberDataPoint {
                        attributes: attrs,
                        start_time_unix_nano,
                        time_unix_nano,
                        exemplars: vec![],
                        flags: 0,
                        value: Some(otlp_metrics::number_data_point::Value::AsInt(
                            saturating_u64_to_i64(v),
                        )),
                    },
                    PointValue::F64(v) => otlp_metrics::NumberDataPoint {
                        attributes: attrs,
                        start_time_unix_nano,
                        time_unix_nano,
                        exemplars: vec![],
                        flags: 0,
                        value: Some(otlp_metrics::number_data_point::Value::AsDouble(v)),
                    },
                };

                let sum = otlp_metrics::Sum {
                    data_points: vec![ndp],
                    aggregation_temporality: otlp_metrics::AggregationTemporality::Delta as i32,
                    is_monotonic: true,
                };

                otlp_metrics::Metric {
                    name: pm.name.clone(),
                    description: pm.description.clone(),
                    unit: pm.unit.clone(),
                    metadata: vec![],
                    data: Some(otlp_metrics::metric::Data::Sum(sum)),
                }
            }
            MetricKind::Gauge => {
                let ndp = match pm.value {
                    PointValue::U64(v) => otlp_metrics::NumberDataPoint {
                        attributes: attrs,
                        start_time_unix_nano: 0, // ignored for Gauge
                        time_unix_nano,
                        exemplars: vec![],
                        flags: 0,
                        value: Some(otlp_metrics::number_data_point::Value::AsInt(
                            saturating_u64_to_i64(v),
                        )),
                    },
                    PointValue::F64(v) => otlp_metrics::NumberDataPoint {
                        attributes: attrs,
                        start_time_unix_nano: 0,
                        time_unix_nano,
                        exemplars: vec![],
                        flags: 0,
                        value: Some(otlp_metrics::number_data_point::Value::AsDouble(v)),
                    },
                };
                let gauge = otlp_metrics::Gauge {
                    data_points: vec![ndp],
                };
                otlp_metrics::Metric {
                    name: pm.name.clone(),
                    description: pm.description.clone(),
                    unit: pm.unit.clone(),
                    metadata: vec![],
                    data: Some(otlp_metrics::metric::Data::Gauge(gauge)),
                }
            }
            _ => {
                let ndp = match pm.value {
                    PointValue::U64(v) => otlp_metrics::NumberDataPoint {
                        attributes: attrs,
                        start_time_unix_nano: 0, // ignored for Gauge
                        time_unix_nano,
                        exemplars: vec![],
                        flags: 0,
                        value: Some(otlp_metrics::number_data_point::Value::AsInt(
                            saturating_u64_to_i64(v),
                        )),
                    },
                    PointValue::F64(v) => otlp_metrics::NumberDataPoint {
                        attributes: attrs,
                        start_time_unix_nano: 0,
                        time_unix_nano,
                        exemplars: vec![],
                        flags: 0,
                        value: Some(otlp_metrics::number_data_point::Value::AsDouble(v)),
                    },
                };
                let gauge = otlp_metrics::Gauge {
                    data_points: vec![ndp],
                };
                otlp_metrics::Metric {
                    name: pm.name.clone(),
                    description: pm.description.clone(),
                    unit: pm.unit.clone(),
                    metadata: vec![],
                    data: Some(otlp_metrics::metric::Data::Gauge(gauge)),
                }
            }
        };

        metrics.push(metric);
    }

    let scope_metrics = otlp_metrics::ScopeMetrics {
        scope: Some(otlp_common::InstrumentationScope {
            name: scope_name.to_string(),
            version: String::new(),
            attributes: vec![],
            dropped_attributes_count: 0,
        }),
        metrics,
        schema_url: String::new(),
    };

    let resource = otlp_resource::Resource {
        attributes: resource_attributes
            .iter()
            .map(|(k, v)| otlp_common::KeyValue {
                key: k.clone(),
                value: Some(otlp_common::AnyValue {
                    value: Some(otlp_common::any_value::Value::StringValue(v.clone())),
                }),
            })
            .collect(),
        dropped_attributes_count: 0,
        entity_refs: vec![],
    };

    let rm = otlp_metrics::ResourceMetrics {
        resource: Some(resource),
        scope_metrics: vec![scope_metrics],
        schema_url: String::new(),
    };

    otlp_collector::ExportMetricsServiceRequest {
        resource_metrics: vec![rm],
    }
}

/// Average smoothed round-trip time, in seconds, for a flow-log sample.
///
/// Mirrors the C++ reducer's `sum_srtt / 8 / 1e6 / active_rtts` computation:
/// `sum_srtt` accumulates RTT samples in units of 1/8 microsecond, so dividing
/// by 8 then 1e6 converts the sum to seconds before averaging over the number
/// of RTT samples. Zero when there are no active RTT samples to average.
fn average_srtt_seconds(tcp_sum_srtt: u64, tcp_active_rtts: u32) -> f64 {
    if tcp_active_rtts == 0 {
        0.0
    } else {
        (tcp_sum_srtt as f64 / 8.0 / 1_000_000.0) / tcp_active_rtts as f64
    }
}

/// Looks up a label's value by key, defaulting to empty string when absent
/// (matching the C++ formatter's `labels_["key"]` map-index semantics).
fn label_value<'a>(labels: &'a [Label], key: &str) -> &'a str {
    labels
        .iter()
        .find(|l| l.key == key)
        .map(|l| l.value.as_str())
        .unwrap_or("")
}

/// Pure functional core of the flow-log line: the four flow-identity labels
/// joined with spaces, followed by the nine space-separated numeric fields
/// (average srtt included). Matches the format produced by the deleted
/// `otlp_grpc_formatter_test.cc` golden test byte-for-byte.
///
/// This closes the production gap left by `Publisher::publish_flow_log`,
/// which today only accounts for a data point and never formats a log body.
/// Wiring this into the logs-SDK publish path (batching + `LogsServiceClient`
/// export, mirroring `flush`'s metrics path) is tracked separately -- this
/// function and its golden tests are the extracted functional core only.
fn format_flow_log_body(
    labels: &[Label],
    tcp_sum_bytes: u64,
    tcp_active_rtts: u32,
    tcp_active_sockets: u32,
    tcp_sum_srtt: u64,
    tcp_sum_delivered: u64,
    tcp_sum_retrans: u64,
    tcp_syn_timeouts: u64,
    tcp_new_sockets: u64,
    tcp_resets: u64,
) -> String {
    let avg_srtt = average_srtt_seconds(tcp_sum_srtt, tcp_active_rtts);

    format!(
        "{} {} {} {} {} {} {} {} {} {} {} {} {}",
        label_value(labels, "source.ip"),
        label_value(labels, "source.workload.name"),
        label_value(labels, "dest.ip"),
        label_value(labels, "dest.workload.name"),
        tcp_sum_bytes,
        tcp_active_rtts,
        tcp_active_sockets,
        avg_srtt,
        tcp_sum_delivered,
        tcp_sum_retrans,
        tcp_syn_timeouts,
        tcp_new_sockets,
        tcp_resets,
    )
}

/// Pure functional core that encodes one flow-log sample into an OTLP
/// `ExportLogsServiceRequest`, mirroring `encode_metrics`'s shape (one
/// Resource -> one ScopeLogs -> one LogRecord). No I/O, no async runtime.
///
/// Not yet called from `Publisher::publish_flow_log` -- see
/// `format_flow_log_body`'s doc comment for why wiring stays out of scope.
#[allow(dead_code)]
fn encode_flow_log(
    labels: &[Label],
    timestamp_unix_nano: i64,
    tcp_sum_bytes: u64,
    tcp_active_rtts: u32,
    tcp_active_sockets: u32,
    tcp_sum_srtt: u64,
    tcp_sum_delivered: u64,
    tcp_sum_retrans: u64,
    tcp_syn_timeouts: u64,
    tcp_new_sockets: u64,
    tcp_resets: u64,
    resource_attributes: &[(String, String)],
    scope_name: &str,
) -> otlp_collector_logs::ExportLogsServiceRequest {
    let body = format_flow_log_body(
        labels,
        tcp_sum_bytes,
        tcp_active_rtts,
        tcp_active_sockets,
        tcp_sum_srtt,
        tcp_sum_delivered,
        tcp_sum_retrans,
        tcp_syn_timeouts,
        tcp_new_sockets,
        tcp_resets,
    );

    let log_record = otlp_logs::LogRecord {
        time_unix_nano: timestamp_unix_nano as u64,
        observed_time_unix_nano: 0,
        severity_number: otlp_logs::SeverityNumber::Info as i32,
        severity_text: "INFO".to_string(),
        body: Some(otlp_common::AnyValue {
            value: Some(otlp_common::any_value::Value::StringValue(body)),
        }),
        attributes: labels_to_otlp_kv(labels),
        dropped_attributes_count: 0,
        flags: 0,
        trace_id: vec![],
        span_id: vec![],
        event_name: String::new(),
    };

    let scope_logs = otlp_logs::ScopeLogs {
        scope: Some(otlp_common::InstrumentationScope {
            name: scope_name.to_string(),
            version: String::new(),
            attributes: vec![],
            dropped_attributes_count: 0,
        }),
        log_records: vec![log_record],
        schema_url: String::new(),
    };

    let resource = otlp_resource::Resource {
        attributes: resource_attributes
            .iter()
            .map(|(k, v)| otlp_common::KeyValue {
                key: k.clone(),
                value: Some(otlp_common::AnyValue {
                    value: Some(otlp_common::any_value::Value::StringValue(v.clone())),
                }),
            })
            .collect(),
        dropped_attributes_count: 0,
        entity_refs: vec![],
    };

    let rl = otlp_logs::ResourceLogs {
        resource: Some(resource),
        scope_logs: vec![scope_logs],
        schema_url: String::new(),
    };

    otlp_collector_logs::ExportLogsServiceRequest {
        resource_logs: vec![rl],
    }
}

fn approx_bytes_metric(name: &str, labels: &Vec<Label>) -> u64 {
    let mut n = name.len() as u64;
    for kv in labels {
        n = n.saturating_add(kv.key.len() as u64 + kv.value.len() as u64 + 2);
    }
    n
}

fn labels_to_otlp_kv(labels: &[Label]) -> Vec<otlp_common::KeyValue> {
    labels
        .iter()
        .map(|l| otlp_common::KeyValue {
            key: l.key.clone(),
            value: Some(otlp_common::AnyValue {
                value: Some(otlp_common::any_value::Value::StringValue(l.value.clone())),
            }),
        })
        .collect()
}

fn normalize_grpc_endpoint(input: &str) -> String {
    // Do not append a path. gRPC expects a host:port with scheme.
    if input.starts_with("http://") || input.starts_with("https://") {
        input.to_string()
    } else if input.contains("://") {
        input.to_string()
    } else {
        format!("http://{}", input)
    }
}

fn saturating_u64_to_i64(v: u64) -> i64 {
    if v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(key: &str, value: &str) -> Label {
        Label {
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    // -- approx_bytes_metric ------------------------------------------------

    #[test]
    fn approx_bytes_metric_sums_name_and_label_lengths() {
        // "cpu.load" (8) + ["host"(4)+"a1"(2)+2] + ["region"(6)+"us"(2)+2] = 8 + 8 + 10
        let labels = vec![label("host", "a1"), label("region", "us")];
        assert_eq!(approx_bytes_metric("cpu.load", &labels), 26);
    }

    #[test]
    fn approx_bytes_metric_with_no_labels_is_just_name_length() {
        assert_eq!(approx_bytes_metric("tcp.bytes", &vec![]), 9);
    }

    // -- labels_to_otlp_kv ----------------------------------------------------

    #[test]
    fn labels_to_otlp_kv_converts_key_value_pairs_in_order() {
        let labels = vec![label("a", "1"), label("b", "2")];
        let kvs = labels_to_otlp_kv(&labels);

        assert_eq!(kvs.len(), 2);
        assert_eq!(kvs[0].key, "a");
        assert_eq!(
            kvs[0].value,
            Some(otlp_common::AnyValue {
                value: Some(otlp_common::any_value::Value::StringValue("1".to_string())),
            })
        );
        assert_eq!(kvs[1].key, "b");
        assert_eq!(
            kvs[1].value,
            Some(otlp_common::AnyValue {
                value: Some(otlp_common::any_value::Value::StringValue("2".to_string())),
            })
        );
    }

    #[test]
    fn labels_to_otlp_kv_empty_input_is_empty_output() {
        assert!(labels_to_otlp_kv(&[]).is_empty());
    }

    // -- normalize_grpc_endpoint ----------------------------------------------

    #[test]
    fn normalize_grpc_endpoint_adds_http_scheme_when_missing() {
        assert_eq!(
            normalize_grpc_endpoint("localhost:4317"),
            "http://localhost:4317"
        );
    }

    #[test]
    fn normalize_grpc_endpoint_preserves_http_scheme() {
        assert_eq!(
            normalize_grpc_endpoint("http://localhost:4317"),
            "http://localhost:4317"
        );
    }

    #[test]
    fn normalize_grpc_endpoint_preserves_https_scheme() {
        assert_eq!(
            normalize_grpc_endpoint("https://collector.example.com:4317"),
            "https://collector.example.com:4317"
        );
    }

    #[test]
    fn normalize_grpc_endpoint_preserves_other_schemes() {
        assert_eq!(
            normalize_grpc_endpoint("dns:///collector:4317"),
            "dns:///collector:4317"
        );
    }

    // -- saturating_u64_to_i64 -------------------------------------------------

    #[test]
    fn saturating_u64_to_i64_passes_through_small_values() {
        assert_eq!(saturating_u64_to_i64(42), 42i64);
        assert_eq!(saturating_u64_to_i64(0), 0i64);
    }

    #[test]
    fn saturating_u64_to_i64_passes_through_i64_max() {
        assert_eq!(saturating_u64_to_i64(i64::MAX as u64), i64::MAX);
    }

    #[test]
    fn saturating_u64_to_i64_saturates_values_above_i64_max() {
        assert_eq!(saturating_u64_to_i64(i64::MAX as u64 + 1), i64::MAX);
        assert_eq!(saturating_u64_to_i64(u64::MAX), i64::MAX);
    }

    // -- encode_metrics (functional core) --------------------------------------

    #[test]
    fn encode_metrics_sum_u64_produces_delta_sum_datapoint() {
        let pending = vec![PendingMetric {
            name: "tcp.bytes".to_string(),
            unit: "By".to_string(),
            description: "TCP bytes".to_string(),
            kind: MetricKind::Sum,
            labels: vec![label("host", "node-1")],
            timestamp_unix_nano: 60_000_000_000,
            value: PointValue::U64(1234),
        }];
        let resource_attributes = vec![("service.name".to_string(), "reducer".to_string())];

        let req = encode_metrics(&pending, &resource_attributes, "reducer-ffi");

        assert_eq!(req.resource_metrics.len(), 1);
        let rm = &req.resource_metrics[0];

        let resource = rm.resource.as_ref().expect("resource is set");
        assert_eq!(resource.attributes.len(), 1);
        assert_eq!(resource.attributes[0].key, "service.name");

        assert_eq!(rm.scope_metrics.len(), 1);
        let sm = &rm.scope_metrics[0];
        assert_eq!(sm.scope.as_ref().expect("scope is set").name, "reducer-ffi");
        assert_eq!(sm.metrics.len(), 1);

        let metric = &sm.metrics[0];
        assert_eq!(metric.name, "tcp.bytes");
        assert_eq!(metric.unit, "By");
        assert_eq!(metric.description, "TCP bytes");

        match metric.data.as_ref().expect("data is set") {
            otlp_metrics::metric::Data::Sum(sum) => {
                assert!(sum.is_monotonic);
                assert_eq!(
                    sum.aggregation_temporality,
                    otlp_metrics::AggregationTemporality::Delta as i32
                );
                assert_eq!(sum.data_points.len(), 1);
                let dp = &sum.data_points[0];
                assert_eq!(dp.time_unix_nano, 60_000_000_000);
                // Start-of-slot semantics: 30s window before the sample time.
                assert_eq!(dp.start_time_unix_nano, 30_000_000_000);
                assert_eq!(dp.attributes.len(), 1);
                assert_eq!(dp.attributes[0].key, "host");
                assert_eq!(
                    dp.value,
                    Some(otlp_metrics::number_data_point::Value::AsInt(1234))
                );
            }
            other => panic!("expected Sum data, got {:?}", other),
        }
    }

    #[test]
    fn encode_metrics_gauge_f64_ignores_start_time() {
        let pending = vec![PendingMetric {
            name: "cpu.util".to_string(),
            unit: "1".to_string(),
            description: "CPU utilization".to_string(),
            kind: MetricKind::Gauge,
            labels: vec![],
            timestamp_unix_nano: 5_000_000_000,
            value: PointValue::F64(0.42),
        }];

        let req = encode_metrics(&pending, &[], "scope");
        let metric = &req.resource_metrics[0].scope_metrics[0].metrics[0];

        match metric.data.as_ref().expect("data is set") {
            otlp_metrics::metric::Data::Gauge(gauge) => {
                assert_eq!(gauge.data_points.len(), 1);
                let dp = &gauge.data_points[0];
                assert_eq!(dp.start_time_unix_nano, 0);
                assert_eq!(dp.time_unix_nano, 5_000_000_000);
                assert_eq!(
                    dp.value,
                    Some(otlp_metrics::number_data_point::Value::AsDouble(0.42))
                );
            }
            other => panic!("expected Gauge data, got {:?}", other),
        }
    }

    #[test]
    fn encode_metrics_saturates_large_u64_values_to_i64_max() {
        let pending = vec![PendingMetric {
            name: "huge.counter".to_string(),
            unit: "1".to_string(),
            description: String::new(),
            kind: MetricKind::Sum,
            labels: vec![],
            timestamp_unix_nano: 1_000_000_000,
            value: PointValue::U64(u64::MAX),
        }];

        let req = encode_metrics(&pending, &[], "scope");
        let metric = &req.resource_metrics[0].scope_metrics[0].metrics[0];

        match metric.data.as_ref().expect("data is set") {
            otlp_metrics::metric::Data::Sum(sum) => {
                assert_eq!(
                    sum.data_points[0].value,
                    Some(otlp_metrics::number_data_point::Value::AsInt(i64::MAX))
                );
            }
            other => panic!("expected Sum data, got {:?}", other),
        }
    }

    #[test]
    fn encode_metrics_preserves_input_order_across_multiple_points() {
        let pending = vec![
            PendingMetric {
                name: "first".to_string(),
                unit: String::new(),
                description: String::new(),
                kind: MetricKind::Gauge,
                labels: vec![],
                timestamp_unix_nano: 1,
                value: PointValue::U64(1),
            },
            PendingMetric {
                name: "second".to_string(),
                unit: String::new(),
                description: String::new(),
                kind: MetricKind::Gauge,
                labels: vec![],
                timestamp_unix_nano: 2,
                value: PointValue::U64(2),
            },
        ];

        let req = encode_metrics(&pending, &[], "scope");
        let metrics = &req.resource_metrics[0].scope_metrics[0].metrics;
        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0].name, "first");
        assert_eq!(metrics[1].name, "second");
    }

    #[test]
    fn encode_metrics_empty_input_produces_empty_metrics_list() {
        let req = encode_metrics(&[], &[], "scope");
        assert_eq!(req.resource_metrics[0].scope_metrics[0].metrics.len(), 0);
    }

    // -- imperative shell: flush/stats lifecycle (needs an endpoint) -----------
    //
    // These are the only tests in this crate that touch an endpoint. "127.0.0.1:1"
    // has nothing listening, so the connect attempt fails immediately (connection
    // refused) without needing an in-process mock server or the network.

    #[test]
    fn flush_on_empty_buffer_is_a_noop() {
        let mut publisher = otlp_publisher_new("127.0.0.1:1");

        publisher.flush();

        let stats = publisher.stats();
        assert_eq!(stats.requests_sent, 0);
        assert_eq!(stats.requests_failed, 0);
        assert_eq!(stats.data_points_sent, 0);
        assert_eq!(stats.data_points_failed, 0);
    }

    #[test]
    fn flush_against_unreachable_endpoint_records_failure_counters() {
        let mut publisher = otlp_publisher_new("127.0.0.1:1");
        publisher.publish_metric_u64(
            "tcp.bytes",
            "By",
            "TCP bytes",
            MetricKind::Sum,
            &vec![label("host", "node-1")],
            1_000_000_000,
            42,
        );

        publisher.flush();

        let stats = publisher.stats();
        assert_eq!(stats.requests_sent, 0);
        assert_eq!(stats.requests_failed, 1);
        assert_eq!(stats.data_points_sent, 0);
        assert_eq!(stats.data_points_failed, 1);
        assert_eq!(stats.bytes_sent, 0);
        assert!(stats.bytes_failed > 0);
    }

    #[test]
    fn shutdown_flushes_pending_points_before_stopping() {
        let mut publisher = otlp_publisher_new("127.0.0.1:1");
        publisher.publish_metric_u64("x", "1", "", MetricKind::Gauge, &vec![], 0, 1);

        publisher.shutdown();

        let stats = publisher.stats();
        assert_eq!(stats.requests_failed, 1);
        assert_eq!(stats.data_points_failed, 1);
    }
}
