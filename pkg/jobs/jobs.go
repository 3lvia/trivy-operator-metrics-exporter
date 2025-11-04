package jobs

import (
	"context"
	"os"

	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/appconfig"
	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/reports"
	"github.com/go-co-op/gocron/v2"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	meter "go.opentelemetry.io/otel/metric"
)

func ScheduleJobs(ctx context.Context, config appconfig.Config) {
	log_ := log.WithField("service", "gocron")
	scheduler, err := gocron.NewScheduler(
		gocron.WithGlobalJobOptions(
			gocron.WithSingletonMode(gocron.LimitModeReschedule),
		),
	)
	if err != nil {
		log_.Fatalf("Could not create scheduler: %+v", err)
	}

	_, err = scheduler.NewJob(
		gocron.DurationJob(
			config.MetricsUpdateInterval,
		),
		gocron.NewTask(
			func() {
				if !config.EnableVulnerabilityMetrics {
					log_.Info("Vulnerability metrics are disabled")
					return
				}

				err := reports.UpdateVulnerabilityMetrics(ctx, config)
				if err != nil {
					log_.Errorf("Failed to update vulnerabilities: %v", err)
					config.ApplicationMetrics.RuntimeErrorsTotal.Add(
						ctx,
						1,
						meter.WithAttributes(
							attribute.String("source", "reports.UpdateVulnerabilityMetrics"),
							attribute.String("reason", "FailedToUpdateVulnerabilityMetrics"),
							attribute.String("innermost_named_function", "scheduleJobs"),
						),
					)
				}
			},
		),
	)
	if err != nil {
		log_.Fatalf("Could not create job: %+v", err)
	}

	_, err = scheduler.NewJob(
		gocron.DurationJob(
			config.MetricsUpdateInterval,
		),
		gocron.NewTask(
			func() {
				if !config.EnableExposedSecretMetrics {
					log_.Info("Exposed secrets metrics are disabled")
					return
				}

				err := reports.UpdateExposedSecretMetrics(ctx, config)
				if err != nil {
					log_.Errorf("Failed to update exposed secrets: %v", err)
					config.ApplicationMetrics.RuntimeErrorsTotal.Add(
						ctx,
						1,
						meter.WithAttributes(
							attribute.String("source", "reports.UpdateExposedSecretMetrics"),
							attribute.String("reason", "FailedToUpdateExposedSecretMetrics"),
							attribute.String("innermost_named_function", "scheduleJobs"),
						),
					)
				}
			},
		),
	)
	if err != nil {
		log_.Fatalf("Could not create job: %+v", err)
	}

	_, err = scheduler.NewJob(
		gocron.DurationJob(
			config.MetricsUpdateInterval,
		),
		gocron.NewTask(
			func() {
				if !config.EnableConfigAuditMetrics {
					log_.Info("Config audit metrics are disabled")
					return
				}

				err := reports.UpdateConfigAuditMetrics(ctx, config)
				if err != nil {
					log_.Errorf("Failed to update config audits: %v", err)
					config.ApplicationMetrics.RuntimeErrorsTotal.Add(
						ctx,
						1,
						meter.WithAttributes(
							attribute.String("source", "reports.UpdateConfigAuditMetrics"),
							attribute.String("reason", "FailedToUpdateConfigAuditMetrics"),
							attribute.String("innermost_named_function", "scheduleJobs"),
						),
					)
				}
			},
		),
	)
	if err != nil {
		log_.Fatalf("Could not create job: %+v", err)
	}

	_, err = scheduler.NewJob(
		gocron.DurationJob(
			config.ExporterRestartInterval,
		),
		gocron.NewTask(
			func() {
				log_.Info("Shutting down to reset metrics")
				os.Exit(0)
			},
		),
	)
	if err != nil {
		log_.Fatalf("Could not create job: %+v", err)
	}

	scheduler.Start()
}
