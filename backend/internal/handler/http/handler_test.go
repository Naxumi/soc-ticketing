package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	domainAuth "github.com/pitik0x/Ai-Security-analyst/internal/domain/auth"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/notification"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/ticket"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/user"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/webhook"
	"github.com/pitik0x/Ai-Security-analyst/internal/handler/http/response"

	"github.com/pitik0x/Ai-Security-analyst/internal/config"
	pkgJWT "github.com/pitik0x/Ai-Security-analyst/internal/pkg/jwt"
)

// ─── Fake auth service ──────────────────────────────────────────────────────

type fakeAuthService struct {
	loginFn    func(ctx context.Context, req domainAuth.LoginRequest, track domainAuth.SessionTrackingRequest) (domainAuth.TokenResponse, error)
	listFn     func(ctx context.Context, actorRole string) ([]domainAuth.UserListItem, error)
	registerFn func(ctx context.Context, creatorRole string, req domainAuth.RegisterRequest) (domainAuth.RegisterResponse, error)
}

func (f *fakeAuthService) Register(ctx context.Context, creatorRole string, req domainAuth.RegisterRequest) (domainAuth.RegisterResponse, error) {
	if f.registerFn != nil {
		return f.registerFn(ctx, creatorRole, req)
	}
	return domainAuth.RegisterResponse{}, nil
}
func (f *fakeAuthService) Login(ctx context.Context, req domainAuth.LoginRequest, track domainAuth.SessionTrackingRequest) (domainAuth.TokenResponse, error) {
	if f.loginFn != nil {
		return f.loginFn(ctx, req, track)
	}
	return domainAuth.TokenResponse{}, nil
}
func (f *fakeAuthService) Refresh(context.Context, domainAuth.RefreshTokenRequest, domainAuth.SessionTrackingRequest) (domainAuth.TokenResponse, error) {
	return domainAuth.TokenResponse{}, nil
}
func (f *fakeAuthService) Logout(context.Context, domainAuth.RefreshTokenRequest) error { return nil }
func (f *fakeAuthService) ChangePassword(context.Context, string, domainAuth.ChangePasswordRequest) error {
	return nil
}
func (f *fakeAuthService) AdminUpdateAnalyst(context.Context, string, string, string, domainAuth.AdminUpdateAnalystRequest) error {
	return nil
}
func (f *fakeAuthService) ListUsers(ctx context.Context, actorRole string) ([]domainAuth.UserListItem, error) {
	if f.listFn != nil {
		return f.listFn(ctx, actorRole)
	}
	return nil, nil
}
func (f *fakeAuthService) GetUserDetail(context.Context, string, string) (domainAuth.UserDetailResponse, error) {
	return domainAuth.UserDetailResponse{}, nil
}
func (f *fakeAuthService) RevokeUserSessions(context.Context, string, string, domainAuth.RevokeUserSessionsRequest) (domainAuth.RevokeUserSessionsResponse, error) {
	return domainAuth.RevokeUserSessionsResponse{}, nil
}
func (f *fakeAuthService) DeleteAnalyst(context.Context, string, string, string) error { return nil }

// ─── Fake user repository ───────────────────────────────────────────────────

type fakeUserRepo struct{}

func (f *fakeUserRepo) Create(context.Context, user.User) (user.User, error) {
	return user.User{}, nil
}
func (f *fakeUserRepo) List(context.Context) ([]user.User, error) { return nil, nil }
func (f *fakeUserRepo) GetByUsername(context.Context, string) (user.User, error) {
	return user.User{}, user.ErrUserNotFound
}
func (f *fakeUserRepo) GetByID(ctx context.Context, id string) (user.User, error) {
	return user.User{
		ID: id, FullName: "Test User", Username: "testuser",
		Role: user.RoleSOCManager, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}
func (f *fakeUserRepo) UpdatePasswordHash(context.Context, string, string) error { return nil }
func (f *fakeUserRepo) AdminUpdate(context.Context, string, *string, *string, *user.Role, *string) error {
	return nil
}
func (f *fakeUserRepo) DeleteByID(context.Context, string) error { return nil }

// ─── Fake session repository ────────────────────────────────────────────────

type fakeSessionRepo struct{}

func (f *fakeSessionRepo) Create(ctx context.Context, s domainAuth.UserSession) (domainAuth.UserSession, error) {
	s.ID = "session-1"
	s.CreatedAt = time.Now()
	return s, nil
}
func (f *fakeSessionRepo) GetByID(_ context.Context, _ string) (domainAuth.UserSession, error) {
	return domainAuth.UserSession{IsRevoked: false}, nil
}
func (f *fakeSessionRepo) GetByRefreshToken(context.Context, string) (domainAuth.UserSession, error) {
	return domainAuth.UserSession{}, nil
}
func (f *fakeSessionRepo) ListByUserID(context.Context, string) ([]domainAuth.UserSession, error) {
	return nil, nil
}
func (f *fakeSessionRepo) RevokeByRefreshToken(context.Context, string) error { return nil }
func (f *fakeSessionRepo) RevokeByUserID(context.Context, string) (int64, error) {
	return 0, nil
}
func (f *fakeSessionRepo) RevokeByIDAndUserID(context.Context, string, string) (int64, error) {
	return 0, nil
}

// ─── Fake webhook service ───────────────────────────────────────────────────

type fakeWebhookService struct{}

func (f *fakeWebhookService) IngestWazuh(_ context.Context, _ webhook.WazuhWebhookRequest) (webhook.IngestResponse, error) {
	return webhook.IngestResponse{CreatedOrUpdatedTickets: 1, TicketIDs: []string{"t-1"}}, nil
}
func (f *fakeWebhookService) IngestRawLogs(_ context.Context, _ webhook.WazuhRawLogBatchRequest) (webhook.RawLogIngestResponse, error) {
	return webhook.RawLogIngestResponse{ProcessedLogs: 2}, nil
}

// ─── Fake ticket, notification, dashboard, report, AI services ──────────────
// (minimal stubs to satisfy NewRouter)

type fakeTicketService struct{}

func (f *fakeTicketService) List(context.Context, string, string, ticket.ListTicketsQuery) (ticket.ListTicketsResponse, error) {
	return ticket.ListTicketsResponse{}, nil
}
func (f *fakeTicketService) GetDetail(context.Context, string) (ticket.TicketDetailResponse, error) {
	return ticket.TicketDetailResponse{}, nil
}
func (f *fakeTicketService) UpdateStatus(context.Context, string, string, string, ticket.UpdateStatusRequest) error {
	return nil
}
func (f *fakeTicketService) Analyze(context.Context, string, string, ticket.AnalyzeTicketRequest) (ticket.AnalyzeTicketResponse, error) {
	return ticket.AnalyzeTicketResponse{}, nil
}

type fakeNotificationService struct{}

func (f *fakeNotificationService) List(context.Context, string, notification.ListNotificationsQuery) (notification.ListNotificationsResponse, error) {
	return notification.ListNotificationsResponse{}, nil
}
func (f *fakeNotificationService) MarkRead(context.Context, string, string) error { return nil }

// ─── Test helpers ───────────────────────────────────────────────────────────

const testWebhookAPIKey = "test-secret-key"

func setupTestRouter(authSvc domainAuth.Service) *httptest.Server {
	jwtSvc := pkgJWT.New(config.JWTConfig{
		Secret:         "test-jwt-secret-that-is-long-enough",
		Issuer:         "test",
		AccessAudience: "test",
		AccessTTL:      time.Hour,
	})

	userRepo := &fakeUserRepo{}
	sessionRepo := &fakeSessionRepo{}

	authHandler := NewAuthHandler(authSvc, jwtSvc, userRepo)
	ticketHandler := NewTicketHandler(&fakeTicketService{})
	ticketStreamHandler := NewTicketStreamHandler(nil)
	notifHandler := NewNotificationHandler(&fakeNotificationService{}, nil)
	webhookHandler := NewWebhookHandler(&fakeWebhookService{})

	router := NewRouter(
		jwtSvc, authHandler, ticketHandler, ticketStreamHandler,
		notifHandler, webhookHandler,
		nil, nil, nil, // dashboard, report, ai handlers (nil ok for routes we don't hit)
		sessionRepo, testWebhookAPIKey, nil, true,
	)

	return httptest.NewServer(router)
}

func generateTestToken(jwtSvc pkgJWT.Service, userID string, role string) string {
	u := user.User{ID: userID, Username: "testuser", Role: user.Role(role)}
	token, _, _ := jwtSvc.GenerateAccessToken(u, "session-1")
	return token
}

// ─── Actual tests ───────────────────────────────────────────────────────────

func TestLogin_InvalidJSON(t *testing.T) {
	srv := setupTestRouter(&fakeAuthService{})
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString("not json"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	var body response.Response
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Success {
		t.Error("expected success=false")
	}
}

func TestLogin_ValidationError(t *testing.T) {
	authSvc := &fakeAuthService{
		loginFn: func(_ context.Context, req domainAuth.LoginRequest, _ domainAuth.SessionTrackingRequest) (domainAuth.TokenResponse, error) {
			return domainAuth.TokenResponse{}, domainAuth.ErrInvalidCredentials
		},
	}

	srv := setupTestRouter(authSvc)
	defer srv.Close()

	body, _ := json.Marshal(domainAuth.LoginRequest{Username: "wrong", Password: "wrong"})
	resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestLogin_Success(t *testing.T) {
	authSvc := &fakeAuthService{
		loginFn: func(_ context.Context, req domainAuth.LoginRequest, _ domainAuth.SessionTrackingRequest) (domainAuth.TokenResponse, error) {
			return domainAuth.TokenResponse{
				AccessToken:           "test-token",
				AccessTokenExpiresIn:  3600,
				RefreshToken:          "test-refresh",
				RefreshTokenExpiresIn: 604800,
			}, nil
		},
	}

	srv := setupTestRouter(authSvc)
	defer srv.Close()

	body, _ := json.Marshal(domainAuth.LoginRequest{Username: "admin", Password: "password123"})
	resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result response.Response
	json.NewDecoder(resp.Body).Decode(&result)
	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestWebhook_MissingAPIKey(t *testing.T) {
	srv := setupTestRouter(&fakeAuthService{})
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"results": []any{}})
	resp, err := http.Post(srv.URL+"/api/v1/webhook/wazuh", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing API key, got %d", resp.StatusCode)
	}
}

func TestWebhook_InvalidAPIKey(t *testing.T) {
	srv := setupTestRouter(&fakeAuthService{})
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"results": []any{}})
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/webhook/wazuh", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "wrong-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong API key, got %d", resp.StatusCode)
	}
}

func TestWebhook_ValidAPIKey(t *testing.T) {
	srv := setupTestRouter(&fakeAuthService{})
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"results": []any{}})
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/webhook/wazuh", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", testWebhookAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Even with valid key, an empty results array returns a validation error from the webhook service.
	// The point is: we got past the middleware (not 401).
	if resp.StatusCode == http.StatusUnauthorized {
		t.Error("should not get 401 with valid API key")
	}
}

func TestProtectedRoute_NoToken(t *testing.T) {
	srv := setupTestRouter(&fakeAuthService{})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/tickets")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for no token, got %d", resp.StatusCode)
	}
}

func TestProtectedRoute_WithValidToken(t *testing.T) {
	jwtSvc := pkgJWT.New(config.JWTConfig{
		Secret:         "test-jwt-secret-that-is-long-enough",
		Issuer:         "test",
		AccessAudience: "test",
		AccessTTL:      time.Hour,
	})

	authSvc := &fakeAuthService{}
	userRepo := &fakeUserRepo{}
	sessionRepo := &fakeSessionRepo{}

	authHandler := NewAuthHandler(authSvc, jwtSvc, userRepo)
	ticketHandler := NewTicketHandler(&fakeTicketService{})
	ticketStreamHandler := NewTicketStreamHandler(nil)
	notifHandler := NewNotificationHandler(&fakeNotificationService{}, nil)
	webhookHandler := NewWebhookHandler(&fakeWebhookService{})

	router := NewRouter(
		jwtSvc, authHandler, ticketHandler, ticketStreamHandler,
		notifHandler, webhookHandler,
		nil, nil, nil,
		sessionRepo, testWebhookAPIKey, nil, true,
	)

	srv := httptest.NewServer(router)
	defer srv.Close()

	token := generateTestToken(jwtSvc, "user-1", "SOC_MANAGER")

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/tickets?page=1&limit=10&tab=active", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		t.Error("should not get 401 with valid token")
	}
}

func TestLogout_Success(t *testing.T) {
	srv := setupTestRouter(&fakeAuthService{})
	defer srv.Close()

	body, _ := json.Marshal(domainAuth.RefreshTokenRequest{RefreshToken: "some-refresh-token"})
	resp, err := http.Post(srv.URL+"/api/v1/auth/logout", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result response.Response
	json.NewDecoder(resp.Body).Decode(&result)
	if !result.Success {
		t.Error("expected success=true")
	}
	if result.Message != "Logged out" {
		t.Errorf("expected message 'Logged out', got %q", result.Message)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv := setupTestRouter(&fakeAuthService{})
	defer srv.Close()

	// DELETE on /api/v1/auth/login should be 405
	req, _ := http.NewRequest("DELETE", srv.URL+"/api/v1/auth/login", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestNotFound(t *testing.T) {
	srv := setupTestRouter(&fakeAuthService{})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/does-not-exist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}
