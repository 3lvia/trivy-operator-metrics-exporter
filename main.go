package main

import (
	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/api"
	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/appconfig"
	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/reports"
	log "github.com/sirupsen/logrus"
)

func main() {
	config := appconfig.CreateConfig()

	if config.Debug {
		log.SetLevel(log.DebugLevel)
		log.Debug("Debug mode enabled.")
	}

	// --- Informer-based metrics setup ---

	if config.EnableVulnerabilityMetrics {
		if err := reports.SetupVulnerabilityMetrics(*config); err != nil {
			log.Fatalf("Failed to setup vulnerability metrics: %v", err)
		}
	}

	// Once you refactor the others, they’ll look like this:
	//
	// if config.EnableExposedSecretMetrics {
	//     if err := reports.SetupExposedSecretMetrics(ctx, *config); err != nil {
	//         log.Fatalf("Failed to setup exposed secret metrics: %v", err)
	//     }
	// }
	//
	// if config.EnableConfigAuditMetrics {
	//     if err := reports.SetupConfigAuditMetrics(ctx, *config); err != nil {
	//         log.Fatalf("Failed to setup config audit metrics: %v", err)
	//     }
	// }

	// Start HTTP server exposing Prometheus metrics
	api.Start(*config)
}
