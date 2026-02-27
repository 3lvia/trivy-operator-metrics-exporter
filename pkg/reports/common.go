package reports

import (
	"context"
	"fmt"

	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/appconfig"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	meter "go.opentelemetry.io/otel/metric"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ForEachNamespace calls fn(namespaceName) for every namespace in the cluster.
func ForEachNamespace(
	ctx context.Context,
	config appconfig.Config,
	fn func(ctx context.Context, namespace string) error,
) error {
	nsList, err := config.KubernetesClient.CoreV1().Namespaces().List(ctx, v1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range nsList.Items {
		if err := fn(ctx, ns.Name); err != nil {
			return err
		}
	}

	return nil
}

// registerObservableGaugeCallback is a small helper to DRY up registration
// for vulnerabilities, exposed secrets and config audits.
func registerObservableGaugeCallback(
	logService string,
	instrument meter.Int64ObservableGauge,
	config appconfig.Config,
	callback func(ctx context.Context, observer meter.Observer) error,
) error {
	logger := log.WithField("service", logService)

	m := otel.GetMeterProvider().Meter(appconfig.SERVICE_NAME)

	_, err := m.RegisterCallback(
		func(ctx context.Context, observer meter.Observer) error {
			return callback(ctx, observer)
		},
		instrument,
	)
	if err != nil {
		return fmt.Errorf("failed to register callback for %s: %w", logService, err)
	}

	logger.Info("Registered observable gauge callback")

	return nil
}
