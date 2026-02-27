package api

import (
	"net/http"

	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/appconfig"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

func Start(config appconfig.Config) {
	router := setupRouter(config, nil)

	err := router.Run(":8080")
	if err != nil {
		log.Fatalf("Failed to start API: %v", err)
	}
}

type SetupRouterOptions struct {
	Testing bool
}

func setupRouter(config appconfig.Config, options *SetupRouterOptions) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())

	if options == nil || !options.Testing {
		router.Use(appconfig.Metrics(config))
	}

	router.GET("/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	return router
}
