package appconfig

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/otel"
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
	Vulnerabilities meter.Int64ObservableGauge // required
	ExposedSecrets  meter.Int64ObservableGauge // required
	ConfigAudits    meter.Int64ObservableGauge // required
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

func configureMetrics(otelResource *resource.Resource) (*ApplicationMetrics, error) {
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
		Vulnerabilities: vulnerabilities,
		ExposedSecrets:  exposedSecrets,
		ConfigAudits:    configAudits,
	}, nil
}
