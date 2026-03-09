package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/3lvia/trivy-operator-metrics-exporter/pkg/appconfig"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

func Start(ctx context.Context, config appconfig.Config) {
	router := setupRouter()

	srv := &http.Server{ //nolint:exhaustruct
		Addr:              ":8080",
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second, // gosec G112
	}

	// Shutdown goroutine: waits for ctx.Done() then gracefully stops the server.
	go func() {
		<-ctx.Done()
		log.Info("API context canceled, shutting down HTTP server")

		// Use ctx as parent to satisfy contextcheck.
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Errorf("HTTP server Shutdown error: %v", err)
		} else {
			log.Info("HTTP server shut down gracefully")
		}
	}()

	// Start server (blocking call).
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Failed to start API: %v", err)
	}
}

func setupRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())

	router.GET("/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	return router
}
