package reports

import (
	"context"
	"fmt"

	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/appconfig"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	meter "go.opentelemetry.io/otel/metric"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

type DynamicInformer struct {
	Informer cache.SharedIndexInformer
	StopCh   chan struct{}
}

// setupDynamicInformer sets up a shared dynamic informer for the given GVR,
// wires generic add/update/delete handlers that delegate to the provided functions,
// starts the factory, and returns the informer + stopCh.
func setupDynamicInformer( //nolint:cyclop,funlen
	config appconfig.Config,
	gvr schema.GroupVersionResource,
	logService string,
	addOrUpdate func(u *unstructured.Unstructured) error,
	deleteFn func(u *unstructured.Unstructured),
) (*DynamicInformer, error) {
	logger := log.WithField("service", logService)

	dynClient, err := dynamic.NewForConfig(config.KubernetesConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		dynClient,
		0, // no resync
		metav1.NamespaceAll,
		nil,
	)

	informer := factory.ForResource(gvr).Informer()

	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if unstructured_, ok := obj.(*unstructured.Unstructured); ok {
				err := addOrUpdate(unstructured_)
				if err != nil {
					logger.Errorf("Error processing added object: %v", err)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if unstructured_, ok := newObj.(*unstructured.Unstructured); ok {
				err := addOrUpdate(unstructured_)
				if err != nil {
					logger.Errorf("Error processing updated object: %v", err)
				}
			}
		},
		DeleteFunc: func(obj any) {
			unstructuredFst, ok := obj.(*unstructured.Unstructured)
			if !ok {
				// tombstone case
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
					if unstructuredSnd, ok2 := tombstone.Obj.(*unstructured.Unstructured); ok2 {
						unstructuredFst = unstructuredSnd
					}
				}
			}

			if unstructuredFst != nil {
				deleteFn(unstructuredFst)
			}
		},
	})
	if err != nil {
		return nil,
			fmt.Errorf("failed to add event handler to informer for %s: %w", gvr.Resource, err)
	}

	stopCh := make(chan struct{})

	// Start informer in background
	go factory.Start(stopCh)

	logger.Infof("%s informer started", gvr.Resource)

	return &DynamicInformer{
		Informer: informer,
		StopCh:   stopCh,
	}, nil
}

// Tiny helper to DRY the OTel callback registration too.
func registerObservableGaugeCallback(
	logService string,
	instrument meter.Int64ObservableGauge,
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
