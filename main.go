package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/api"
	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/appconfig"
	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/reports"
	log "github.com/sirupsen/logrus"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	config := appconfig.CreateConfig(ctx)

	if config.Debug {
		log.SetLevel(log.DebugLevel)
		log.Debug("Debug mode enabled.")
	}

	if config.EnableVulnerabilityMetrics {
		if err := reports.SetupVulnerabilityMetrics(ctx, *config); err != nil {
			log.Errorf("Failed to setup vulnerability metrics: %v", err)

			return
		}
	}

	if config.EnableExposedSecretMetrics {
		if err := reports.SetupExposedSecretMetrics(ctx, *config); err != nil {
			log.Errorf("Failed to setup exposed secret metrics: %v", err)

			return
		}
	}

	if config.EnableConfigAuditMetrics {
		if err := reports.SetupConfigAuditMetrics(ctx, *config); err != nil {
			log.Errorf("Failed to setup config audit metrics: %v", err)

			return
		}
	}

	api.Start(ctx, *config)
}
