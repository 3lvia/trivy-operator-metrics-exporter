package appconfig

import (
	"context"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Config struct {
	Debug                      bool                  // required
	Local                      bool                  // required
	KubernetesConfig           *rest.Config          // required
	KubernetesClient           *kubernetes.Clientset // required
	ApplicationMetrics         ApplicationMetrics    // required
	EnableVulnerabilityMetrics bool                  // required
	EnableExposedSecretMetrics bool                  // required
	EnableConfigAuditMetrics   bool                  // required
	MuteConfig                 MuteConfig            // required
}

func getEnvFallback(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return fallback
}

func parseTimeWithDefault(value string, defaultValue time.Duration) (time.Duration, error) {
	if value == "" {
		return defaultValue, nil
	}

	return time.ParseDuration(value)
}

func CreateConfig(ctx context.Context) *Config {
	logger := log.WithField("service", "config")

	debug := getEnvFallback("DEBUG", "false") == "true"
	local := getEnvFallback("LOCAL", "false") == "true"

	// Kubernetes config + client
	kubeCfg, kubernetesClient, err := configureKubernetes(local)
	if err != nil {
		logger.Fatalf("Could not setup Kubernetes client: %+v", err)
	}

	// Metrics
	applicationMetrics, err := configureMetrics(ctx)
	if err != nil {
		logger.Fatalf("Could not configure metrics: %+v", err)
	}

	enableVulnerabilityMetrics := os.Getenv("ENABLE_VULNERABILITY_METRICS") != "false" //nolint:goconst
	if !enableVulnerabilityMetrics {
		logger.Info("Vulnerability metrics are disabled via ENABLE_VULNERABILITY_METRICS=false")
	}

	enableExposedSecretMetrics := os.Getenv("ENABLE_EXPOSED_SECRET_METRICS") != "false"
	if !enableExposedSecretMetrics {
		logger.Info("Exposed secret metrics are disabled via ENABLE_EXPOSED_SECRET_METRICS=false")
	}

	enableConfigAuditMetrics := os.Getenv("ENABLE_CONFIG_AUDIT_METRICS") != "false"
	if !enableConfigAuditMetrics {
		logger.Info("Config audit metrics are disabled via ENABLE_CONFIG_AUDIT_METRICS=false")
	}

	muteConfig, err := loadMuteConfig()
	if err != nil {
		logger.Fatalf("Could not load mute config: %+v", err)
	}

	return &Config{
		Debug:                      debug,
		Local:                      local,
		KubernetesConfig:           kubeCfg,
		KubernetesClient:           kubernetesClient,
		ApplicationMetrics:         *applicationMetrics,
		EnableVulnerabilityMetrics: enableVulnerabilityMetrics,
		EnableExposedSecretMetrics: enableExposedSecretMetrics,
		EnableConfigAuditMetrics:   enableConfigAuditMetrics,
		MuteConfig:                 *muteConfig,
	}
}
