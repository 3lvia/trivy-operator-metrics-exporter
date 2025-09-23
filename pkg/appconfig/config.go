package appconfig

import (
	"context"

	"github.com/3lvia/core/applications/trivy-operator-metrics-exporter/pkg/utils"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

type Config struct {
	Environment                string                // required
	Debug                      bool                  // required
	Local                      bool                  // required
	KubernetesClient           *kubernetes.Clientset // required
	ApplicationMetrics         ApplicationMetrics    // required
	EnableVulnerabilityMetrics bool                  // required
	EnableExposedSecretMetrics bool                  // required
	EnableConfigAuditMetrics   bool                  // required
}

func CreateConfig(ctx context.Context) *Config {
	log_ := log.WithField("service", "config")

	environment := utils.GetEnvFallback("ENVIRONMENT", "dev")
	debug := utils.GetEnvFallback("DEBUG", "false") == "true"
	local := utils.GetEnvFallback("LOCAL", "false") == "true"

	// Kubernetes client
	kubernetesClient, err := configureKubernetesClient(local)
	if err != nil {
		log_.Fatalf("Could not setup Kubernetes client: %+v", err)
	}

	// Metrics
	applicationMetrics, err := configureMetrics()
	if err != nil {
		log_.Fatalf("Could not configure metrics: %+v", err)
	}

	return &Config{
		Environment:                environment,
		Debug:                      debug,
		Local:                      local,
		KubernetesClient:           kubernetesClient,
		ApplicationMetrics:         *applicationMetrics,
		EnableVulnerabilityMetrics: true,
		EnableExposedSecretMetrics: true,
		EnableConfigAuditMetrics:   environment == "dev", // TODO: enable for all environments
	}
}
