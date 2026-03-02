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

type ConfigAuditReportList struct {
	APIVersion string              `json:"apiVersion"` // required
	Items      []ConfigAuditReport `json:"items"`      // required
	Kind       string              `json:"kind"`       // required
}

type ConfigAuditReport struct {
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
		Checks []ConfigAudit `json:"checks"` // required
	} `json:"report"` // required
}

type ConfigAudit struct {
	Category    string   `json:"category"`    // required
	CheckID     string   `json:"checkID"`     // required
	Description string   `json:"description"` // required
	Messages    []string `json:"messages"`    // required
	Remediation string   `json:"remediation"` // required
	Severity    string   `json:"severity"`    // required
	Success     bool     `json:"success"`     // required
	Title       string   `json:"title"`       // required
}

type ConfigAuditExported struct {
	Namespace    string      `json:"namespace"`    // required
	ConfigAudit  ConfigAudit `json:"configAudit"`  // required
	ResourceName string      `json:"resourceName"` // required
	ResourceKind string      `json:"resourceKind"` // required
}

func getOwnerReferenceNameAndKind(configAuditReport ConfigAuditReport) (string, string) {
	if len(configAuditReport.Metadata.OwnerReferences) == 0 {
		return "", ""
	}

	return configAuditReport.Metadata.OwnerReferences[0].Name,
		configAuditReport.Metadata.OwnerReferences[0].Kind
}

func (configAuditReportList ConfigAuditReportList) ToConfigAuditExportedList(
	config appconfig.Config,
) []ConfigAuditExported {
	var configAudits []ConfigAuditExported

	for _, report := range configAuditReportList.Items {
		for _, configAudit := range report.Report.Checks {
			resourceName, resourceKind := getOwnerReferenceNameAndKind(report)

			configAudits = append(configAudits, ConfigAuditExported{
				Namespace:    report.Metadata.Namespace,
				ConfigAudit:  configAudit,
				ResourceName: resourceName,
				ResourceKind: resourceKind,
			})
		}
	}

	return configAudits
}

func (report ConfigAuditReport) ToConfigAuditExportedList() []ConfigAuditExported {
	var configAudits []ConfigAuditExported

	for _, configAudit := range report.Report.Checks {
		resourceName, resourceKind := getOwnerReferenceNameAndKind(report)

		configAudits = append(configAudits, ConfigAuditExported{
			Namespace:    report.Metadata.Namespace,
			ConfigAudit:  configAudit,
			ResourceName: resourceName,
			ResourceKind: resourceKind,
		})
	}

	return configAudits
}

type ConfigAuditStore struct {
	mutex sync.RWMutex
	data  map[string][]ConfigAuditExported // key: namespace/name
}

func NewConfigAuditStore() *ConfigAuditStore {
	return &ConfigAuditStore{
		mutex: sync.RWMutex{},
		data:  make(map[string][]ConfigAuditExported),
	}
}

func (store *ConfigAuditStore) Upsert(unstruct *unstructured.Unstructured) error {
	// Convert unstructured → ConfigAuditReport
	reportBytes, err := json.Marshal(unstruct.Object)
	if err != nil {
		return err
	}

	var report ConfigAuditReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return err
	}

	exports := report.ToConfigAuditExportedList()
	key := unstruct.GetNamespace() + "/" + unstruct.GetName()

	store.mutex.Lock()
	defer store.mutex.Unlock()

	store.data[key] = exports

	return nil
}

func (store *ConfigAuditStore) Delete(unstruct *unstructured.Unstructured) {
	key := unstruct.GetNamespace() + "/" + unstruct.GetName()

	store.mutex.Lock()
	defer store.mutex.Unlock()

	delete(store.data, key)
}

func (store *ConfigAuditStore) Snapshot() map[string][]ConfigAuditExported {
	store.mutex.RLock()
	defer store.mutex.RUnlock()

	out := make(map[string][]ConfigAuditExported, len(store.data))
	for key, value := range store.data {
		// shallow copy slice is fine; ConfigAuditExported is value type
		cp := make([]ConfigAuditExported, len(value))
		copy(cp, value)

		out[key] = cp
	}

	return out
}

// SetupConfigAuditMetrics creates a dynamic informer for configauditreports.
// It maintains an in-memory store of current config audits,
// and registers an async gauge callback that reads from that store.
func SetupConfigAuditMetrics(ctx context.Context, config appconfig.Config) error {
	logger := log.WithField("service", "configAuditInformer")

	store := NewConfigAuditStore()

	configAuditGVR := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "configauditreports",
	}

	informer, err := setupDynamicInformer(
		config,
		configAuditGVR,
		"configAuditInformer",
		store.Upsert,
		store.Delete,
	)
	if err != nil {
		return err
	}

	// Wait for sync before we start serving metrics
	if !cache.WaitForCacheSync(informer.StopCh, informer.Informer.HasSynced) {
		return errors.New("failed to sync configauditreport informer cache")
	}

	logger.Info("ConfigAuditReport informer cache synced")

	// Register OTel callback that reads from store
	err = registerObservableGaugeCallback(
		"configAuditMetrics",
		config.ApplicationMetrics.ConfigAudits,
		func(_ context.Context, observer meter.Observer) error {
			return observeConfigAuditsFromStore(observer, config, store)
		},
	)
	if err != nil {
		return fmt.Errorf("failed to register config audit metrics callback: %w", err)
	}

	return nil
}

func observeConfigAuditsFromStore(
	observer meter.Observer,
	config appconfig.Config,
	store *ConfigAuditStore,
) error {
	logger := log.WithField("service", "observeConfigAuditMetrics")
	logger.Debug("Observing config audit metrics from store")

	snapshot := store.Snapshot()

	for _, configAudits := range snapshot {
		for _, configAudit := range configAudits {
			namespace := configAudit.Namespace

			observer.ObserveInt64(
				config.ApplicationMetrics.ConfigAudits,
				1,
				meter.WithAttributes(
					attribute.String("namespace", namespace),
					attribute.String("resource_name", configAudit.ResourceName),
					attribute.String("resource_kind", configAudit.ResourceKind),
					// attribute.String("category", configAudit.ConfigAudit.Category),
					attribute.String("check_id", configAudit.ConfigAudit.CheckID),
					attribute.String("description", configAudit.ConfigAudit.Description),
					attribute.String("remediation", configAudit.ConfigAudit.Remediation),
					attribute.String("severity", configAudit.ConfigAudit.Severity),
					// attribute.Bool("success", configAudit.ConfigAudit.Success),
					attribute.String("title", configAudit.ConfigAudit.Title),
				),
			)
		}
	}

	return nil
}
