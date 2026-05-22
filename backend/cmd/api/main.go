package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/httplog/v3"
	"github.com/golang-cz/devslog"

	"github.com/pitik0x/Ai-Security-analyst/internal/config"
	httpHandler "github.com/pitik0x/Ai-Security-analyst/internal/handler/http"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/database"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/jwt"
	"github.com/pitik0x/Ai-Security-analyst/internal/repository/postgresql"
	authService "github.com/pitik0x/Ai-Security-analyst/internal/service/auth"
	dashboardService "github.com/pitik0x/Ai-Security-analyst/internal/service/dashboard"
	notificationService "github.com/pitik0x/Ai-Security-analyst/internal/service/notification"
	reportService "github.com/pitik0x/Ai-Security-analyst/internal/service/report"
	ticketService "github.com/pitik0x/Ai-Security-analyst/internal/service/ticket"
	ticketstream "github.com/pitik0x/Ai-Security-analyst/internal/service/ticketstream"
	webhookService "github.com/pitik0x/Ai-Security-analyst/internal/service/webhook"
)

func main() {
	bootstrapLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	cfg, err := config.Load()
	if err != nil {
		bootstrapLogger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	isDev := strings.EqualFold(cfg.App.Env, "development")
	logFormat := httplog.SchemaECS.Concise(isDev)

	handlerOpts := &slog.HandlerOptions{
		AddSource:   !isDev,
		ReplaceAttr: logFormat.ReplaceAttr,
	}

	var handler slog.Handler
	if isDev {
		handler = devslog.NewHandler(os.Stdout, &devslog.Options{
			SortKeys:       true,
			HandlerOptions: handlerOpts,
		})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, handlerOpts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	slog.SetLogLoggerLevel(slog.LevelError)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := database.New(ctx, cfg.Database)
	if err != nil {
		logger.Error("failed to connect db", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	jwtSvc := jwt.New(cfg.JWT)

	userRepo := postgresql.NewUserRepository(db)
	sessionRepo := postgresql.NewSessionRepository(db)
	ticketRepo := postgresql.NewTicketRepository(db)
	auditRepo := postgresql.NewTicketAuditLogRepository(db)
	authSvc := authService.New(db, userRepo, sessionRepo, jwtSvc, cfg.JWT.RefreshTTL, auditRepo)
	authHandler := httpHandler.NewAuthHandler(authSvc, jwtSvc, userRepo)

	ticketSvc := ticketService.New(db, ticketRepo, auditRepo, cfg.App.AnalyzeAPIURL, cfg.App.AnalyzeAPIKey, cfg.App.AnalyzeTimeout)
	ticketHandler := httpHandler.NewTicketHandler(ticketSvc)
	aiHandler := httpHandler.NewAIHandler(cfg.App.AnalyzeModelsURL, cfg.App.AnalyzeAPIURL, cfg.App.AnalyzeAPIKey, cfg.App.AnalyzeTimeout)

	notifRepo := postgresql.NewNotificationRepository(db)
	notifHub := notificationService.NewHub()
	notifSvc := notificationService.New(notifRepo)
	notifHandler := httpHandler.NewNotificationHandler(notifSvc, notifHub)

	webhookRepo := postgresql.NewWazuhWebhookRepository(db)
	// ticket stream hub for server-sent events
	ticketStreamHub := ticketstream.NewHub()
	webhookSvc := webhookService.New(db, webhookRepo, notifRepo, notifHub, ticketStreamHub)
	webhookHandler := httpHandler.NewWebhookHandler(webhookSvc)
	ticketStreamHandler := httpHandler.NewTicketStreamHandler(ticketStreamHub)

	const windowFinalizeInterval = 5 * time.Second
	go func() {
		ticker := time.NewTicker(windowFinalizeInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				res, err := webhookSvc.FlushExpiredWindows(ctx)
				if err != nil {
					logger.Error("failed to flush expired ingest windows", "error", err)
					continue
				}
				if len(res.CreatedTicketIDs) > 0 {
					logger.Info(
						"materialized expired ingest windows",
						"created_tickets", len(res.CreatedTicketIDs),
						"ticket_ids", res.CreatedTicketIDs,
						"active_grouping_keys", res.ActiveGroupingKeys,
					)
				}
			}
		}
	}()

	dashboardRepo := postgresql.NewDashboardRepository(db)
	dashboardSvc := dashboardService.New(dashboardRepo)
	dashboardHandler := httpHandler.NewDashboardHandler(dashboardSvc)

	reportRepo := postgresql.NewReportRepository(db)
	reportSvc := reportService.New(reportRepo, ticketRepo)
	reportHandler := httpHandler.NewReportHandler(reportSvc)

	r := httpHandler.NewRouter(jwtSvc, authHandler, ticketHandler, ticketStreamHandler, notifHandler, webhookHandler, dashboardHandler, reportHandler, aiHandler, sessionRepo, cfg.App.WebhookAPIKey, logger, isDev)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.App.Port),
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("listening", "addr", srv.Addr, "env", cfg.App.Env)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
