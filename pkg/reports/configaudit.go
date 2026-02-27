package reports

/*
import (
	"context"
	"encoding/json"

	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/appconfig"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	meter "go.opentelemetry.io/otel/metric"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	ConfigAudit  ConfigAudit `json:"configAUdit"`  // required
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

func (configAuditReportList ConfigAuditReportList) ToConfigAuditExportedList(config appconfig.Config) []ConfigAuditExported {
	var configAudits []ConfigAuditExported
	for _, report := range configAuditReportList.Items {
		for _, configAudit := range report.Report.Checks {
			resourceName, resourceKind := getOwnerReferenceNameAndKind(report)

			configAudits = append(configAudits, ConfigAuditExported{
				ConfigAudit:  configAudit,
				ResourceName: resourceName,
				ResourceKind: resourceKind,
			})
		}
	}

	return configAudits
}

func UpdateConfigAuditMetrics(ctx context.Context, config appconfig.Config) error {
	log_ := log.WithField("service", "updateConfigAuditMetrics")
	log_.Info("Updating configAudit metrics.")

	namespaceList, err := config.KubernetesClient.CoreV1().Namespaces().List(
		ctx,
		v1.ListOptions{},
	)
	if err != nil {
		return err
	}

	for _, namespace := range namespaceList.Items {
		log_.Infof("Checking namespace: %s", namespace.Name)

		var configAuditReportList ConfigAuditReportList
		configAuditReportListRaw, err := config.KubernetesClient.RESTClient().Get().AbsPath(
			"/apis/aquasecurity.github.io/v1alpha1/namespaces/" + namespace.Name + "/configauditreports",
		).DoRaw(ctx)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(configAuditReportListRaw, &configAuditReportList); err != nil {
			return err
		}

		configAudits := configAuditReportList.ToConfigAuditExportedList(config)
		for _, configAudit := range configAudits {
			log_.Debugf("Found config audit: %s", configAudit.ConfigAudit.Title)
			config.ApplicationMetrics.ConfigAudits.Record(
				ctx,
				1,
				meter.WithAttributes(
					attribute.String("namespace", namespace.Name),
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
*/
