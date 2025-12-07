//! OpenTelemetry integration for registry-firewall
//!
//! This module provides observability through OpenTelemetry, including
//! tracing, metrics, and optional logging export to OTLP endpoints.

use crate::config::OtelConfig;
use opentelemetry::{
    global,
    metrics::{Counter, Histogram, Meter, MeterProvider as _},
    trace::TracerProvider as TracerProviderTrait,
    KeyValue,
};
use opentelemetry_sdk::{metrics::SdkMeterProvider, trace::TracerProvider, Resource};
use thiserror::Error;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// OpenTelemetry error types
#[derive(Debug, Error)]
pub enum OtelError {
    /// Failed to initialize tracer
    #[error("Failed to initialize tracer: {0}")]
    TracerInit(String),

    /// Failed to initialize meter
    #[error("Failed to initialize meter: {0}")]
    MeterInit(String),

    /// Failed to shutdown
    #[error("Failed to shutdown: {0}")]
    Shutdown(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
}

/// OpenTelemetry provider for registry-firewall
///
/// Manages tracing and metrics providers with OTLP export capability.
pub struct OtelProvider {
    tracer_provider: Option<TracerProvider>,
    meter_provider: SdkMeterProvider,
    config: OtelConfig,
}

impl OtelProvider {
    /// Create a new OtelProvider with the given configuration
    pub fn new(config: &OtelConfig) -> Result<Self, OtelError> {
        let resource = Resource::new(vec![KeyValue::new(
            "service.name",
            config.service_name.clone(),
        )]);

        let (tracer_provider, meter_provider) = if config.enabled {
            let endpoint = config.endpoint.as_ref().ok_or_else(|| {
                OtelError::Config("OTLP endpoint is required when enabled".into())
            })?;

            // Initialize tracer provider with OTLP exporter
            let tracer_provider = Self::init_tracer_provider(endpoint, &resource)?;

            // Initialize meter provider with OTLP exporter
            let meter_provider = Self::init_meter_provider(endpoint, &resource)?;

            (Some(tracer_provider), meter_provider)
        } else {
            // Use no-op meter provider when disabled
            let meter_provider = SdkMeterProvider::builder().with_resource(resource).build();
            (None, meter_provider)
        };

        // Set global tracer provider
        if let Some(ref tp) = tracer_provider {
            global::set_tracer_provider(tp.clone());
        }

        Ok(Self {
            tracer_provider,
            meter_provider,
            config: config.clone(),
        })
    }

    /// Initialize the tracer provider with OTLP exporter
    fn init_tracer_provider(
        endpoint: &str,
        resource: &Resource,
    ) -> Result<TracerProvider, OtelError> {
        use opentelemetry_otlp::WithExportConfig;
        use opentelemetry_sdk::runtime;
        use opentelemetry_sdk::trace::{Config, Sampler};

        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint)
            .build_span_exporter()
            .map_err(|e| OtelError::TracerInit(e.to_string()))?;

        let trace_config = Config::default()
            .with_sampler(Sampler::AlwaysOn)
            .with_resource(resource.clone());

        let tracer_provider = TracerProvider::builder()
            .with_batch_exporter(exporter, runtime::Tokio)
            .with_config(trace_config)
            .build();

        Ok(tracer_provider)
    }

    /// Initialize the meter provider with OTLP exporter
    fn init_meter_provider(
        endpoint: &str,
        resource: &Resource,
    ) -> Result<SdkMeterProvider, OtelError> {
        use opentelemetry_otlp::{MetricsExporterBuilder, WithExportConfig};
        use opentelemetry_sdk::metrics::reader::{
            DefaultAggregationSelector, DefaultTemporalitySelector,
        };
        use opentelemetry_sdk::{metrics::PeriodicReader, runtime};

        let exporter = MetricsExporterBuilder::from(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint),
        )
        .build_metrics_exporter(
            Box::new(DefaultTemporalitySelector::new()),
            Box::new(DefaultAggregationSelector::new()),
        )
        .map_err(|e| OtelError::MeterInit(e.to_string()))?;

        let reader = PeriodicReader::builder(exporter, runtime::Tokio).build();

        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_reader(reader)
            .build();

        Ok(meter_provider)
    }

    /// Get a tracer from the provider
    pub fn tracer(&self, name: &'static str) -> opentelemetry_sdk::trace::Tracer {
        if let Some(ref tp) = self.tracer_provider {
            tp.tracer(name)
        } else {
            // Return a no-op tracer when disabled
            TracerProvider::builder().build().tracer(name)
        }
    }

    /// Get the meter for creating metrics
    pub fn meter(&self) -> Meter {
        self.meter_provider.meter(self.config.service_name.clone())
    }

    /// Check if OpenTelemetry is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Shutdown the OpenTelemetry providers gracefully
    pub fn shutdown(&self) -> Result<(), OtelError> {
        // Shutdown meter provider
        if let Err(e) = self.meter_provider.shutdown() {
            return Err(OtelError::Shutdown(format!(
                "Meter shutdown failed: {:?}",
                e
            )));
        }

        // Force flush any remaining spans
        if let Some(ref tp) = self.tracer_provider {
            for result in tp.force_flush() {
                if let Err(e) = result {
                    return Err(OtelError::Shutdown(format!("Tracer flush failed: {:?}", e)));
                }
            }
        }

        Ok(())
    }
}

impl Drop for OtelProvider {
    fn drop(&mut self) {
        // Best-effort shutdown on drop
        let _ = self.shutdown();
    }
}

/// Application metrics for registry-firewall
///
/// Provides pre-defined metrics for monitoring the proxy's performance and behavior.
pub struct Metrics {
    /// Total number of requests received
    pub requests_total: Counter<u64>,

    /// Total number of blocked requests
    pub blocked_total: Counter<u64>,

    /// Total number of cache hits
    pub cache_hits_total: Counter<u64>,

    /// Total number of cache misses
    pub cache_misses_total: Counter<u64>,

    /// Request processing duration in seconds
    pub request_duration: Histogram<f64>,

    /// Upstream request duration in seconds
    pub upstream_duration: Histogram<f64>,
}

impl Metrics {
    /// Create new metrics with the given meter
    pub fn new(meter: &Meter) -> Self {
        let requests_total = meter
            .u64_counter("registry_firewall_requests_total")
            .with_description("Total number of requests received")
            .init();

        let blocked_total = meter
            .u64_counter("registry_firewall_blocked_total")
            .with_description("Total number of blocked requests")
            .init();

        let cache_hits_total = meter
            .u64_counter("registry_firewall_cache_hits_total")
            .with_description("Total number of cache hits")
            .init();

        let cache_misses_total = meter
            .u64_counter("registry_firewall_cache_misses_total")
            .with_description("Total number of cache misses")
            .init();

        let request_duration = meter
            .f64_histogram("registry_firewall_request_duration_seconds")
            .with_description("Request processing duration in seconds")
            .init();

        let upstream_duration = meter
            .f64_histogram("registry_firewall_upstream_duration_seconds")
            .with_description("Upstream request duration in seconds")
            .init();

        Self {
            requests_total,
            blocked_total,
            cache_hits_total,
            cache_misses_total,
            request_duration,
            upstream_duration,
        }
    }

    /// Create an observable gauge for cache size
    pub fn create_cache_size_gauge(meter: &Meter) -> opentelemetry::metrics::ObservableGauge<u64> {
        meter
            .u64_observable_gauge("registry_firewall_cache_size_bytes")
            .with_description("Current cache size in bytes")
            .init()
    }

    /// Create an observable gauge for blocked packages count
    pub fn create_blocked_packages_gauge(
        meter: &Meter,
    ) -> opentelemetry::metrics::ObservableGauge<u64> {
        meter
            .u64_observable_gauge("registry_firewall_blocked_packages_count")
            .with_description("Number of blocked packages in database")
            .init()
    }

    /// Record a request with the given attributes
    pub fn record_request(&self, ecosystem: &str, status: &str) {
        self.requests_total.add(
            1,
            &[
                KeyValue::new("ecosystem", ecosystem.to_string()),
                KeyValue::new("status", status.to_string()),
            ],
        );
    }

    /// Record a blocked request
    pub fn record_blocked(&self, ecosystem: &str, source: &str) {
        self.blocked_total.add(
            1,
            &[
                KeyValue::new("ecosystem", ecosystem.to_string()),
                KeyValue::new("source", source.to_string()),
            ],
        );
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self, ecosystem: &str) {
        self.cache_hits_total
            .add(1, &[KeyValue::new("ecosystem", ecosystem.to_string())]);
    }

    /// Record a cache miss
    pub fn record_cache_miss(&self, ecosystem: &str) {
        self.cache_misses_total
            .add(1, &[KeyValue::new("ecosystem", ecosystem.to_string())]);
    }

    /// Record request duration
    pub fn record_request_duration(&self, ecosystem: &str, duration_secs: f64) {
        self.request_duration.record(
            duration_secs,
            &[KeyValue::new("ecosystem", ecosystem.to_string())],
        );
    }

    /// Record upstream request duration
    pub fn record_upstream_duration(&self, ecosystem: &str, duration_secs: f64) {
        self.upstream_duration.record(
            duration_secs,
            &[KeyValue::new("ecosystem", ecosystem.to_string())],
        );
    }
}

/// Initialize tracing subscriber with OpenTelemetry integration
pub fn init_tracing(otel: &OtelProvider, log_level: &str) -> Result<(), OtelError> {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" | "warning" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let filter = tracing_subscriber::filter::LevelFilter::from_level(level);

    if otel.is_enabled() {
        // With OpenTelemetry layer
        let tracer = otel.tracer("registry-firewall");
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()
            .map_err(|e| OtelError::TracerInit(e.to_string()))?;
    } else {
        // Without OpenTelemetry layer
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()
            .map_err(|e| OtelError::TracerInit(e.to_string()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: OtelProvider initialization with disabled config
    #[test]
    fn test_otel_provider_disabled() {
        let config = OtelConfig {
            enabled: false,
            endpoint: None,
            insecure: false,
            service_name: "test-service".to_string(),
        };

        let provider = OtelProvider::new(&config);
        assert!(provider.is_ok());

        let provider = provider.unwrap();
        assert!(!provider.is_enabled());
        assert!(provider.tracer_provider.is_none());
    }

    // Test 2: OtelProvider requires endpoint when enabled
    #[test]
    fn test_otel_provider_requires_endpoint_when_enabled() {
        let config = OtelConfig {
            enabled: true,
            endpoint: None, // Missing endpoint
            insecure: false,
            service_name: "test-service".to_string(),
        };

        let result = OtelProvider::new(&config);
        assert!(result.is_err());

        match result {
            Err(OtelError::Config(msg)) => {
                assert!(msg.contains("endpoint is required"));
            }
            _ => panic!("Expected OtelError::Config"),
        }
    }

    // Test 3: Get meter from provider
    #[test]
    fn test_otel_provider_get_meter() {
        let config = OtelConfig {
            enabled: false,
            endpoint: None,
            insecure: false,
            service_name: "test-service".to_string(),
        };

        let provider = OtelProvider::new(&config).unwrap();
        let meter = provider.meter();

        // Meter should be usable for creating instruments
        let counter = meter.u64_counter("test_counter").init();
        counter.add(1, &[]);
    }

    // Test 4: Metrics creation
    #[test]
    fn test_metrics_creation() {
        let config = OtelConfig {
            enabled: false,
            endpoint: None,
            insecure: false,
            service_name: "test-service".to_string(),
        };

        let provider = OtelProvider::new(&config).unwrap();
        let meter = provider.meter();
        let metrics = Metrics::new(&meter);

        // All metrics should be created
        metrics.requests_total.add(1, &[]);
        metrics.blocked_total.add(1, &[]);
        metrics.cache_hits_total.add(1, &[]);
        metrics.cache_misses_total.add(1, &[]);
        metrics.request_duration.record(0.5, &[]);
        metrics.upstream_duration.record(0.3, &[]);
    }

    // Test 5: Record request with attributes
    #[test]
    fn test_metrics_record_request() {
        let config = OtelConfig::default();
        let provider = OtelProvider::new(&config).unwrap();
        let meter = provider.meter();
        let metrics = Metrics::new(&meter);

        // Should not panic
        metrics.record_request("pypi", "success");
        metrics.record_request("go", "error");
        metrics.record_request("cargo", "blocked");
    }

    // Test 6: Record blocked request
    #[test]
    fn test_metrics_record_blocked() {
        let config = OtelConfig::default();
        let provider = OtelProvider::new(&config).unwrap();
        let meter = provider.meter();
        let metrics = Metrics::new(&meter);

        // Should not panic
        metrics.record_blocked("pypi", "osv");
        metrics.record_blocked("go", "openssf");
        metrics.record_blocked("cargo", "custom");
    }

    // Test 7: Record cache operations
    #[test]
    fn test_metrics_record_cache_operations() {
        let config = OtelConfig::default();
        let provider = OtelProvider::new(&config).unwrap();
        let meter = provider.meter();
        let metrics = Metrics::new(&meter);

        // Should not panic
        metrics.record_cache_hit("pypi");
        metrics.record_cache_miss("go");
        metrics.record_cache_hit("cargo");
        metrics.record_cache_miss("docker");
    }

    // Test 8: Record duration metrics
    #[test]
    fn test_metrics_record_durations() {
        let config = OtelConfig::default();
        let provider = OtelProvider::new(&config).unwrap();
        let meter = provider.meter();
        let metrics = Metrics::new(&meter);

        // Should not panic
        metrics.record_request_duration("pypi", 0.050);
        metrics.record_request_duration("go", 0.100);
        metrics.record_upstream_duration("cargo", 0.200);
        metrics.record_upstream_duration("docker", 0.150);
    }

    // Test 9: Provider shutdown
    #[test]
    fn test_otel_provider_shutdown() {
        let config = OtelConfig {
            enabled: false,
            endpoint: None,
            insecure: false,
            service_name: "test-service".to_string(),
        };

        let provider = OtelProvider::new(&config).unwrap();
        let result = provider.shutdown();
        assert!(result.is_ok());
    }

    // Test 10: Create observable gauges
    #[test]
    fn test_create_observable_gauges() {
        let config = OtelConfig::default();
        let provider = OtelProvider::new(&config).unwrap();
        let meter = provider.meter();

        // Create cache size gauge
        let _gauge = Metrics::create_cache_size_gauge(&meter);

        // Create blocked packages gauge
        let _gauge2 = Metrics::create_blocked_packages_gauge(&meter);
    }

    // Test 11: OtelError display
    #[test]
    fn test_otel_error_display() {
        let err = OtelError::Config("test error".to_string());
        assert_eq!(err.to_string(), "Configuration error: test error");

        let err = OtelError::TracerInit("tracer error".to_string());
        assert_eq!(err.to_string(), "Failed to initialize tracer: tracer error");

        let err = OtelError::MeterInit("meter error".to_string());
        assert_eq!(err.to_string(), "Failed to initialize meter: meter error");

        let err = OtelError::Shutdown("shutdown error".to_string());
        assert_eq!(err.to_string(), "Failed to shutdown: shutdown error");
    }

    // Test 12: Default OtelConfig
    #[test]
    fn test_default_otel_config() {
        let config = OtelConfig::default();

        assert!(!config.enabled);
        assert!(config.endpoint.is_none());
        assert!(!config.insecure);
        assert_eq!(config.service_name, "registry-firewall");
    }

    // Test 13: OtelProvider is_enabled reflects config
    #[test]
    fn test_otel_provider_is_enabled() {
        let config = OtelConfig {
            enabled: false,
            endpoint: None,
            insecure: false,
            service_name: "test".to_string(),
        };

        let provider = OtelProvider::new(&config).unwrap();
        assert!(!provider.is_enabled());
    }
}
