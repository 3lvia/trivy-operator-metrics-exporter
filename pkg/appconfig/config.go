package appconfig

import (
	"context"
	"os"
	"time"

	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/utils"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

type Config struct {
	Debug                      bool                  // required
	Local                      bool                  // required
	KubernetesClient           *kubernetes.Clientset // required
	ApplicationMetrics         ApplicationMetrics    // required
	EnableVulnerabilityMetrics bool                  // required
	EnableExposedSecretMetrics bool                  // required
	EnableConfigAuditMetrics   bool                  // required
	MetricsUpdateInterval      time.Duration         // required
	ExporterRestartInterval    time.Duration         // required
	MuteConfig                 MuteConfig            // required
}

func parseTimeWithDefault(value string, defaultValue time.Duration) (time.Duration, error) {
	if value == "" {
		return defaultValue, nil
	}

	return time.ParseDuration(value)
}

func CreateConfig(ctx context.Context) *Config {
	log_ := log.WithField("service", "config")

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

	enableVulnerabilityMetrics := os.Getenv("ENABLE_VULNERABILITY_METRICS") != "false"
	if !enableVulnerabilityMetrics {
		log_.Info("Vulnerability metrics are disabled via ENABLE_VULNERABILITY_METRICS=false")
	}

	enableExposedSecretMetrics := os.Getenv("ENABLE_EXPOSED_SECRET_METRICS") != "false"
	if !enableExposedSecretMetrics {
		log_.Info("Exposed secret metrics are disabled via ENABLE_EXPOSED_SECRET_METRICS=false")
	}

	enableConfigAuditMetrics := os.Getenv("ENABLE_CONFIG_AUDIT_METRICS") != "false"
	if !enableConfigAuditMetrics {
		log_.Info("Config audit metrics are disabled via ENABLE_CONFIG_AUDIT_METRICS=false")
	}

	metricsUpdateInterval, err := parseTimeWithDefault(
		os.Getenv("METRICS_UPDATE_INTERVAL"),
		15*time.Minute,
	)
	if err != nil {
		log_.Fatalf("Could not parse METRICS_UPDATE_INTERVAL: %+v", err)
	}

	exporterRestartInterval, err := parseTimeWithDefault(
		os.Getenv("EXPORTER_RESTART_INTERVAL"),
		1*time.Hour,
	)
	if err != nil {
		log_.Fatalf("Could not parse EXPORTER_RESTART_INTERVAL: %+v", err)
	}

	muteConfig, err := loadMuteConfig()
	if err != nil {
		log_.Fatalf("Could not load mute config: %+v", err)
	}

	return &Config{
		Debug:                      debug,
		Local:                      local,
		KubernetesClient:           kubernetesClient,
		ApplicationMetrics:         *applicationMetrics,
		EnableVulnerabilityMetrics: enableVulnerabilityMetrics,
		EnableExposedSecretMetrics: enableExposedSecretMetrics,
		EnableConfigAuditMetrics:   enableConfigAuditMetrics,
		MetricsUpdateInterval:      metricsUpdateInterval,
		ExporterRestartInterval:    exporterRestartInterval,
		MuteConfig:                 *muteConfig,
	}
}
