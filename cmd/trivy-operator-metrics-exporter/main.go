package main

import (
	"context"

	"github.com/3lvia/core/applications/trivy-operator-metrics-exporter/pkg/api"
	"github.com/3lvia/core/applications/trivy-operator-metrics-exporter/pkg/appconfig"
	"github.com/3lvia/core/applications/trivy-operator-metrics-exporter/pkg/jobs"
	"github.com/3lvia/core/applications/trivy-operator-metrics-exporter/pkg/reports"
	log "github.com/sirupsen/logrus"
)

func main() {
	ctx := context.Background()
	config := appconfig.CreateConfig(ctx)

	if config.Debug {
		log.SetLevel(log.DebugLevel)
		log.Debug("Debug mode enabled.")
	}

	if config.EnableVulnerabilityMetrics {
		err := reports.UpdateVulnerabilityMetrics(ctx, *config)
		if err != nil {
			log.Fatalf("Failed to update vulnerability metrics: %v", err)
		}
	}

	if config.EnableExposedSecretMetrics {
		err := reports.UpdateExposedSecretMetrics(ctx, *config)
		if err != nil {
			log.Fatalf("Failed to update exposed secrets metrics: %v", err)
		}
	}

	if config.EnableConfigAuditMetrics {
		err := reports.UpdateConfigAuditMetrics(ctx, *config)
		if err != nil {
			log.Fatalf("Failed to update config audit metrics: %v", err)
		}
	}

	jobs.ScheduleJobs(ctx, *config)
	api.Start(*config)
}
