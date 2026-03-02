package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/appconfig"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	meter "go.opentelemetry.io/otel/metric"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

type ExposedSecretReportList struct {
	APIVersion string                `json:"apiVersion"` // required
	Items      []ExposedSecretReport `json:"items"`      // required
	Kind       string                `json:"kind"`       // required
}

type ExposedSecretReport struct {
	APIVersion string `json:"apiVersion"` // required
	Kind       string `json:"kind"`       // required
	Metadata   struct {
		Name            string `json:"name"`      // required
		Namespace       string `json:"namespace"` // required
		OwnerReferences []struct {
			ApiVersion string `json:"apiVersion"` // required
			Kind       string `json:"kind"`       // required
			Name       string `json:"name"`       // required
			UID        string `json:"uid"`        // required
		} `json:"ownerReferences"` // required
		ResourceVersion string `json:"resourceVersion"` // required
		UID             string `json:"uid"`             // required
	} `json:"metadata"` // required
	Report struct {
		Registry struct {
			Server string `json:"server"` // required
		} `json:"registry"` // required
		Summary struct {
			CriticalCount int `json:"criticalCount"` // required
			HighCount     int `json:"highCount"`     // required
			LowCount      int `json:"lowCount"`      // required
			MediumCount   int `json:"mediumCount"`   // required
		} `json:"summary"` // required
		Artifact struct {
			Repository string `json:"repository"` // required
			Tag        string `json:"tag"`        // required
		} `json:"artifact"` // required
		UpdateTimestamp string          `json:"updateTimestamp"` // required
		Secrets         []ExposedSecret `json:"secrets"`         // required
	} `json:"report"` // required
}

type ExposedSecret struct {
	Category string `json:"category"` // required
	Match    string `json:"match"`    // required
	RuleID   string `json:"ruleID"`   // required
	Severity string `json:"severity"` // required
	Target   string `json:"target"`   // required
	Title    string `json:"title"`    // required
}

type ExposedSecretExported struct {
	Namespace     string        `json:"namespace"`     // required
	ExposedSecret ExposedSecret `json:"exposedSecret"` // required
	ImageName     string        `json:"imageName"`     // required
	ImageTag      string        `json:"imageTag"`      // required
}

func (exposedSecretReportList ExposedSecretReportList) ToExposedSecretExportedList() []ExposedSecretExported {
	var exposedSecrets []ExposedSecretExported

	for _, report := range exposedSecretReportList.Items {
		for _, exposedSecret := range report.Report.Secrets {
			exposedSecrets = append(exposedSecrets, ExposedSecretExported{
				Namespace:     report.Metadata.Namespace,
				ExposedSecret: exposedSecret,
				ImageName:     report.Report.Artifact.Repository,
				ImageTag:      report.Report.Artifact.Tag,
			})
		}
	}

	return exposedSecrets
}

func (report ExposedSecretReport) ToExposedSecretExportedList() []ExposedSecretExported {
	var exposedSecrets []ExposedSecretExported
	for _, exposedSecret := range report.Report.Secrets {
		exposedSecrets = append(exposedSecrets, ExposedSecretExported{
			Namespace:     report.Metadata.Namespace,
			ExposedSecret: exposedSecret,
			ImageName:     report.Report.Artifact.Repository,
			ImageTag:      report.Report.Artifact.Tag,
		})
	}

	return exposedSecrets
}

type ExposedSecretStore struct {
	mutex sync.RWMutex
	data  map[string][]ExposedSecretExported // key: namespace/name
}

func NewExposedSecretStore() *ExposedSecretStore {
	return &ExposedSecretStore{
		mutex: sync.RWMutex{},
		data:  make(map[string][]ExposedSecretExported),
	}
}

func (store *ExposedSecretStore) Upsert(unstruct *unstructured.Unstructured) error {
	// Convert unstructured → ExposedSecretReport
	reportBytes, err := json.Marshal(unstruct.Object)
	if err != nil {
		return err
	}

	var report ExposedSecretReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return err
	}

	exports := report.ToExposedSecretExportedList()
	key := unstruct.GetNamespace() + "/" + unstruct.GetName()

	store.mutex.Lock()
	defer store.mutex.Unlock()

	store.data[key] = exports

	return nil
}

func (store *ExposedSecretStore) Delete(unstruct *unstructured.Unstructured) {
	key := unstruct.GetNamespace() + "/" + unstruct.GetName()

	store.mutex.Lock()
	defer store.mutex.Unlock()

	delete(store.data, key)
}

func (store *ExposedSecretStore) ForEach(fn func(key string, exposedSecrets []ExposedSecretExported)) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()

	for key, exposedSecrets := range store.data {
		fn(key, exposedSecrets)
	}
}

func SetupExposedSecretMetrics(ctx context.Context, config appconfig.Config) error {
	logger := log.WithField("service", "exposedSecretInformer")

	store := NewExposedSecretStore()

	exposedSecretGVR := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "exposedsecretreports",
	}

	dynamicInformer, err := setupDynamicInformer(
		ctx,
		config,
		exposedSecretGVR,
		"exposedSecretInformer",
		store.Upsert,
		store.Delete,
	)
	if err != nil {
		return err
	}

	// Wait for sync before we start serving metrics.
	// This will unblock either when the cache is synced or when ctx is canceled (Stop closes the channel).
	if !cache.WaitForCacheSync(dynamicInformer.stopCh, dynamicInformer.Informer.HasSynced) {
		return errors.New("failed to sync exposedsecretreport informer cache")
	}

	logger.Info("Exposedsecretreport informer cache synced")

	// Register OTel callback that reads from store
	err = registerObservableGaugeCallback(
		"exposedSecretMetrics",
		config.ApplicationMetrics.ExposedSecrets,
		func(_ context.Context, observer meter.Observer) error {
			observeExposedSecretsFromStore(observer, config, store)

			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("failed to register exposed secret metrics callback: %w", err)
	}

	return nil
}

func observeExposedSecretsFromStore(
	observer meter.Observer,
	config appconfig.Config,
	store *ExposedSecretStore,
) {
	logger := log.WithField("service", "observeExposedSecretMetrics")
	logger.Debug("Observing exposed secret metrics from store")

	store.ForEach(func(_ string, exposedSecrets []ExposedSecretExported) {
		for _, exposedSecret := range exposedSecrets {
			observer.ObserveInt64(
				config.ApplicationMetrics.ExposedSecrets,
				1,
				meter.WithAttributes(
					attribute.String("namespace", exposedSecret.Namespace),
					attribute.String("image_name", exposedSecret.ImageName),
					attribute.String("image_tag", exposedSecret.ImageTag),
					attribute.String("category", exposedSecret.ExposedSecret.Category),
					attribute.String("match", exposedSecret.ExposedSecret.Match),
					attribute.String("rule_id", exposedSecret.ExposedSecret.RuleID),
					attribute.String("severity", exposedSecret.ExposedSecret.Severity),
					attribute.String("target", exposedSecret.ExposedSecret.Target),
					attribute.String("title", exposedSecret.ExposedSecret.Title),
				),
			)
		}
	})
}
