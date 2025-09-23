package api

import (
	"net/http"

	"github.com/3lvia/core/applications/trivy-operator-metrics-exporter/pkg/appconfig"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)

func Start(config appconfig.Config) {
	r := setupRouter(config, nil)

	err := r.Run(":8080")
	if err != nil {
		log.Fatalf("Failed to start API: %v", err)
	}
}

type SetupRouterOptions struct {
	Testing bool
}

func setupRouter(config appconfig.Config, options *SetupRouterOptions) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	if options == nil || !options.Testing {
		r.Use(appconfig.Metrics(config))
	}

	r.GET("/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	return r
}
