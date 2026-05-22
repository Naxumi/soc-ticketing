package http

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/auth"
	"github.com/pitik0x/Ai-Security-analyst/internal/handler/http/middleware"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/jwt"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httplog/v3"
	"github.com/go-chi/jwtauth/v5"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

func NewRouter(jwtSvc jwt.Service, authHandler *AuthHandler, ticketHandler *TicketHandler, ticketStreamHandler *TicketStreamHandler, notificationHandler *NotificationHandler, webhookHandler *WebhookHandler, dashboardHandler *DashboardHandler, reportHandler *ReportHandler, aiHandler *AIHandler, sessionRepo auth.SessionRepository, webhookAPIKey string, logger *slog.Logger, isDev bool) *chi.Mux {
	r := chi.NewRouter()

	logFormat := httplog.SchemaECS.Concise(isDev)

	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: logFormat.ReplaceAttr}))
	}

	r.Use(httplog.RequestLogger(logger, &httplog.Options{
		Level:  slog.LevelInfo,
		Schema: logFormat,
		Skip: func(req *http.Request, _ int) bool {
			return strings.HasSuffix(req.URL.Path, "/api/v1/notifications/stream")
		},
		LogRequestBody:  func(req *http.Request) bool { return false },
		LogResponseBody: func(req *http.Request) bool { return false },
	}))

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-API-Key"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.Heartbeat("/"))

	// Serve OpenAPI spec and Swagger UI.
	// NOTE: This serves a file from the working directory (api/openapi.json).
	// Run the server from the module root (where the api/ folder exists).
	r.Get("/api/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("api", "openapi.json"))
	})
	// Swagger UI at /swagger/index.html
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/api/openapi.json"),
	))

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/dashboard", func(r chi.Router) {
			r.Use(jwtauth.Verifier(jwtSvc.JWTAuth()))
			r.Use(middleware.AuthRequired(jwtSvc.JWTAuth(), sessionRepo))
			r.Get("/", dashboardHandler.Get)
		})

		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", authHandler.Login)
			r.Post("/refresh", authHandler.Refresh)
			r.Post("/logout", authHandler.Logout)

			r.Group(func(r chi.Router) {
				r.Use(jwtauth.Verifier(jwtSvc.JWTAuth()))
				r.Use(middleware.AuthRequired(jwtSvc.JWTAuth(), sessionRepo))
				r.Get("/me", authHandler.Me)
				r.Post("/change-password", authHandler.ChangePassword)
				r.Patch("/users/{id}", authHandler.AdminUpdateAnalyst)
				r.Post("/register", authHandler.Register)
			})
		})

		r.Route("/users", func(r chi.Router) {
			r.Use(jwtauth.Verifier(jwtSvc.JWTAuth()))
			r.Use(middleware.AuthRequired(jwtSvc.JWTAuth(), sessionRepo))

			r.Get("/", authHandler.ListUsers)
			r.Get("/{id}", authHandler.GetUserDetail)
			r.Post("/{id}/sessions/revoke", authHandler.RevokeUserSessions)
			r.Delete("/{id}", authHandler.DeleteAnalyst)
		})

		r.Route("/tickets", func(r chi.Router) {
			r.Use(jwtauth.Verifier(jwtSvc.JWTAuth()))
			r.Use(middleware.AuthRequired(jwtSvc.JWTAuth(), sessionRepo))

			r.Get("/", ticketHandler.List)
			r.Get("/stream", ticketStreamHandler.Stream)
			r.Get("/{id}", ticketHandler.GetDetail)
			r.Patch("/{id}/status", ticketHandler.UpdateStatus)
			r.Post("/{id}/analyze", ticketHandler.Analyze)
		})

		r.Route("/notifications", func(r chi.Router) {
			r.Use(jwtauth.Verifier(jwtSvc.JWTAuth()))
			r.Use(middleware.AuthRequired(jwtSvc.JWTAuth(), sessionRepo))

			r.Get("/", notificationHandler.List)
			r.Get("/stream", notificationHandler.Stream)
			r.Patch("/{id}/read", notificationHandler.MarkRead)
		})

		r.Route("/reports", func(r chi.Router) {
			r.Use(jwtauth.Verifier(jwtSvc.JWTAuth()))
			r.Use(middleware.AuthRequired(jwtSvc.JWTAuth(), sessionRepo))

			r.Get("/tickets.csv", reportHandler.ExportTicketsCSV)
			r.Get("/tickets.pdf", reportHandler.ExportTicketsPDF)
		})

		r.Route("/ai", func(r chi.Router) {
			r.Use(jwtauth.Verifier(jwtSvc.JWTAuth()))
			r.Use(middleware.AuthRequired(jwtSvc.JWTAuth(), sessionRepo))

			r.Get("/models", aiHandler.ListModels)
		})

		r.Route("/webhook", func(r chi.Router) {
			r.Use(middleware.APIKeyRequired(webhookAPIKey))
			r.Post("/wazuh", webhookHandler.IngestWazuh)
			r.Post("/wazuh/raw-logs", webhookHandler.IngestWazuhRawLogs)
		})
	})

	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return r
}
