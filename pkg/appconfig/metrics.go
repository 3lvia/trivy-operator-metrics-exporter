package appconfig

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/log/global"
	meter "go.opentelemetry.io/otel/metric"
	otelLog "go.opentelemetry.io/otel/sdk/log"
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

func configureOpenTelemetry(ctx context.Context) (*ApplicationMetrics, error) {
	otelResource, err := resource.New(
		ctx,
		resource.WithAttributes(semconv.ServiceNameKey.String(SERVICE_NAME)),
		resource.WithAttributes(semconv.ServiceNamespaceKey.String(SERVICE_NAMESPACE)),
		resource.WithSchemaURL(semconv.SchemaURL),
	)
	if err != nil {
		return nil, err
	}

	if err := configureLogs(ctx, otelResource); err != nil {
		return nil, err
	}

	applicationMetrics, err := configureMetrics(otelResource)
	if err != nil {
		return nil, err
	}

	return applicationMetrics, nil
}

func configureLogs(ctx context.Context, otelResource *resource.Resource) error {
	logExporter, err := otlploggrpc.New(ctx)
	if err != nil {
		return err
	}

	processor := otelLog.NewBatchProcessor(logExporter)
	loggerProvider := otelLog.NewLoggerProvider(
		otelLog.WithResource(otelResource),
		otelLog.WithProcessor(processor),
	)

	global.SetLoggerProvider(loggerProvider)

	hook := otellogrus.NewHook(
		SERVICE_NAME,
		otellogrus.WithLoggerProvider(loggerProvider),
	)
	log.AddHook(hook)

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if err := loggerProvider.Shutdown(shutdownCtx); err != nil {
			log.Errorf("failed to shutdown OpenTelemetry logger provider: %v", err)
		}
	}()

	return nil
}

func configureMetrics(otelResource *resource.Resource) (*ApplicationMetrics, error) { //nolint:funlen
	metricExporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metricExporter),
		metric.WithResource(otelResource),
	)
	otel.SetMeterProvider(meterProvider)

	metrics := meterProvider.Meter(SERVICE_NAME)

	httpRequestsReceivedTotal, err := metrics.Int64Counter(
		"http_requests_received_total",
		meter.WithDescription("Total number of HTTP requests received"),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create counter: %w", err)
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
		return nil, fmt.Errorf("could not create histogram: %w", err)
	}

	vulnerabilities, err := metrics.Int64ObservableGauge(
		"trivy_image_vulnerabilities",
		meter.WithDescription("Vulnerabilities found by Trivy Operator."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create vulnerabilities gauge: %w", err)
	}

	exposedSecrets, err := metrics.Int64ObservableGauge(
		"trivy_exposed_secrets",
		meter.WithDescription("Exposed secrets found by Trivy Operator."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create exposed secrets gauge: %w", err)
	}

	configAudits, err := metrics.Int64ObservableGauge(
		"trivy_config_audits",
		meter.WithDescription("Config audits found by Trivy Operator."),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create config audits gauge: %w", err)
	}

	return &ApplicationMetrics{
		httpRequestsReceivedTotal:  httpRequestsReceivedTotal,
		httpRequestDurationSeconds: httpRequestDurationSeconds,
		Vulnerabilities:            vulnerabilities,
		ExposedSecrets:             exposedSecrets,
		ConfigAudits:               configAudits,
	}, nil
}

func APIMetrics(config Config) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		t := time.Now()

		ctx.Next()

		latency := time.Since(t)
		statusCode := ctx.Writer.Status()
		method := ctx.Request.Method
		endpoint := ctx.Request.URL.Path

		meterAttributes := []attribute.KeyValue{
			attribute.Key("code").Int(statusCode),
			attribute.Key("method").String(method),
			attribute.Key("endpoint").String(endpoint),
		}

		config.ApplicationMetrics.httpRequestDurationSeconds.Record(
			ctx.Request.Context(),
			latency.Seconds(),
			meter.WithAttributes(meterAttributes...),
		)

		config.ApplicationMetrics.httpRequestsReceivedTotal.Add(
			ctx.Request.Context(),
			1,
			meter.WithAttributes(meterAttributes...),
		)
	}
}
