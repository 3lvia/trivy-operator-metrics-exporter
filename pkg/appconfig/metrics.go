package appconfig

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	meter "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

type ApplicationMetrics struct {
	httpRequestsReceivedTotal  meter.Int64Counter     // required
	httpRequestDurationSeconds meter.Float64Histogram // required
	RuntimeErrorsTotal         meter.Int64Counter     // required
	RuntimeWarningsTotal       meter.Int64Counter     // required
	Vulnerabilities            meter.Int64Gauge       // required
	ExposedSecrets             meter.Int64Gauge       // required
	ConfigAudits               meter.Int64Gauge       // required
}

const SERVICE_NAME = "trivy-operator-metrics-exporter"

func configureMetrics() (*ApplicationMetrics, error) {
	metricExporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create Prometheus exporter: %v", err)
	}

	resource, err := resource.New(
		context.Background(),
		resource.WithAttributes(semconv.ServiceNameKey.String(SERVICE_NAME)),
		resource.WithAttributes(semconv.ServiceNamespaceKey.String("core")),
		resource.WithSchemaURL(semconv.SchemaURL),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %v", err)
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metricExporter),
		metric.WithResource(resource),
	)
	otel.SetMeterProvider(meterProvider)

	metrics := meterProvider.Meter(SERVICE_NAME)

	httpRequestsReceivedTotal, err := metrics.Int64Counter(
		"http_requests_received_total",
		meter.WithDescription("Total number of HTTP requests received"),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create counter: %s", err)
	}

	httpRequestDurationSeconds, err := metrics.Float64Histogram(
		"http_request_duration_seconds",
		meter.WithDescription("The duration of HTTP requests processed by Gin, in seconds."),
		meter.WithExplicitBucketBoundaries(
			0.001,
			0.002,
			0.005,
			0.01,
			0.02,
			0.05,
			0.1,
			0.2,
			0.5,
			1,
			2,
			5,
			10,
			20,
			60,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create histogram: %s", err)
	}

	runtimeErrorsTotal, err := metrics.Int64Counter(
		"runtime_errors_total",
		meter.WithDescription("Total number of runtime errors."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create counter: %s", err)
	}

	runtimeWarningsTotal, err := metrics.Int64Counter(
		"runtime_warnings_total",
		meter.WithDescription("Total number of runtime warnings."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create counter: %s", err)
	}

	vulnerabilities, err := metrics.Int64Gauge(
		"trivy_image_vulnerabilities",
		meter.WithDescription("Vulnerabilities found by Trivy Operator."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create gauge: %s", err)
	}

	exposedSecrets, err := metrics.Int64Gauge(
		"trivy_exposed_secrets",
		meter.WithDescription("Exposed secrets found by Trivy Operator."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create gauge: %s", err)
	}

	configAudits, err := metrics.Int64Gauge(
		"trivy_config_audits",
		meter.WithDescription("Config audits found by Trivy Operator."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create gauge: %s", err)
	}

	return &ApplicationMetrics{
		httpRequestsReceivedTotal:  httpRequestsReceivedTotal,
		httpRequestDurationSeconds: httpRequestDurationSeconds,
		RuntimeErrorsTotal:         runtimeErrorsTotal,
		RuntimeWarningsTotal:       runtimeWarningsTotal,
		Vulnerabilities:            vulnerabilities,
		ExposedSecrets:             exposedSecrets,
		ConfigAudits:               configAudits,
	}, nil
}

func Metrics(config Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		c.Next()

		latency := time.Since(t)
		statusCode := c.Writer.Status()
		method := c.Request.Method
		endpoint := c.Request.URL.Path

		meterAttributes := []attribute.KeyValue{
			attribute.Key("code").Int(statusCode),
			attribute.Key("method").String(method),
			attribute.Key("endpoint").String(endpoint),
			// TODO: this shouldn't be needed, we don't have controllers
			attribute.Key("controller").String("gin"),
		}

		config.ApplicationMetrics.httpRequestDurationSeconds.Record(
			c.Request.Context(),
			latency.Seconds(),
			meter.WithAttributes(meterAttributes...),
		)

		config.ApplicationMetrics.httpRequestsReceivedTotal.Add(
			c.Request.Context(),
			1,
			meter.WithAttributes(meterAttributes...),
		)
	}
}
