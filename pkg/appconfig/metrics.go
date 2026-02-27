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
	httpRequestsReceivedTotal  meter.Int64Counter         // required
	httpRequestDurationSeconds meter.Float64Histogram     // required
	Vulnerabilities            meter.Int64ObservableGauge // required
	ExposedSecrets             meter.Int64ObservableGauge // required
	ConfigAudits               meter.Int64ObservableGauge // required
}

const (
	SERVICE_NAME      = "trivy-operator-metrics-exporter"
	SERVICE_NAMESPACE = "trivy-system"
)

func configureMetrics() (*ApplicationMetrics, error) {
	metricExporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create Prometheus exporter: %v", err)
	}

	resource, err := resource.New(
		context.Background(),
		resource.WithAttributes(semconv.ServiceNameKey.String(SERVICE_NAME)),
		resource.WithAttributes(semconv.ServiceNamespaceKey.String(SERVICE_NAMESPACE)),
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

	meter_ := meterProvider.Meter(SERVICE_NAME)

	httpRequestsReceivedTotal, err := meter_.Int64Counter(
		"http_requests_received_total",
		meter.WithDescription("Total number of HTTP requests received"),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create counter: %s", err)
	}

	httpRequestDurationSeconds, err := meter_.Float64Histogram(
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

	vulnerabilities, err := meter_.Int64ObservableGauge(
		"trivy_image_vulnerabilities",
		meter.WithDescription("Vulnerabilities found by Trivy Operator."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create vulnerabilities gauge: %s", err)
	}

	exposedSecrets, err := meter_.Int64ObservableGauge(
		"trivy_exposed_secrets",
		meter.WithDescription("Exposed secrets found by Trivy Operator."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create exposed secrets gauge: %s", err)
	}

	configAudits, err := meter_.Int64ObservableGauge(
		"trivy_config_audits",
		meter.WithDescription("Config audits found by Trivy Operator."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create config audits gauge: %s", err)
	}

	return &ApplicationMetrics{
		httpRequestsReceivedTotal:  httpRequestsReceivedTotal,
		httpRequestDurationSeconds: httpRequestDurationSeconds,
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
