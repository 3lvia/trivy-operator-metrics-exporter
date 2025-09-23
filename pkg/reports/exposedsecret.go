package reports

import (
	"context"
	"encoding/json"

	"github.com/3lvia/core/applications/trivy-operator-metrics-exporter/pkg/appconfig"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	meter "go.opentelemetry.io/otel/metric"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	ExposedSecret ExposedSecret `json:"exposedSecret"` // required
	ImageName     string        `json:"imageName"`     // required
	ImageTag      string        `json:"imageTag"`      // required
}

func (exposedSecretReportList ExposedSecretReportList) ToExposedSecretExportedList(config appconfig.Config) []ExposedSecretExported {
	var exposedSecrets []ExposedSecretExported
	for _, report := range exposedSecretReportList.Items {
		for _, exposedSecret := range report.Report.Secrets {
			exposedSecrets = append(exposedSecrets, ExposedSecretExported{
				ExposedSecret: exposedSecret,
				ImageName:     report.Report.Artifact.Repository,
				ImageTag:      report.Report.Artifact.Tag,
			})
		}
	}

	return exposedSecrets
}

func UpdateExposedSecretMetrics(ctx context.Context, config appconfig.Config) error {
	log_ := log.WithField("service", "updateExposedSecretMetrics")
	log_.Info("Updating exposedSecret metrics.")

	namespaceList, err := config.KubernetesClient.CoreV1().Namespaces().List(
		ctx,
		v1.ListOptions{},
	)
	if err != nil {
		return err
	}

	for _, namespace := range namespaceList.Items {
		log_.Infof("Checking namespace: %s", namespace.Name)

		var exposedSecretReportList ExposedSecretReportList
		exposedSecretReportListRaw, err := config.KubernetesClient.RESTClient().Get().AbsPath(
			"/apis/aquasecurity.github.io/v1alpha1/namespaces/" + namespace.Name + "/exposedsecretreports",
		).DoRaw(ctx)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(exposedSecretReportListRaw, &exposedSecretReportList); err != nil {
			return err
		}

		exposedSecrets := exposedSecretReportList.ToExposedSecretExportedList(config)
		for _, exposedSecret := range exposedSecrets {
			log_.Debugf("Found exposed secret: %s", exposedSecret.ExposedSecret.Title)
			config.ApplicationMetrics.ExposedSecrets.Record(
				ctx,
				1,
				meter.WithAttributes(
					attribute.String("namespace", namespace.Name),
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
	}

	return nil
}
