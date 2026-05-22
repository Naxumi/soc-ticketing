package auth

import (
	"context"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	domainAuth "github.com/pitik0x/Ai-Security-analyst/internal/domain/auth"
	domainTicket "github.com/pitik0x/Ai-Security-analyst/internal/domain/ticket"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/user"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/database"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/jwt"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/validator"
)

type Service struct {
	db         *database.DB
	users      user.Repository
	sessions   domainAuth.SessionRepository
	logs       domainTicket.AuditLogRepository
	jwt        jwt.Service
	refreshTTL time.Duration
}

func New(db *database.DB, users user.Repository, sessions domainAuth.SessionRepository, jwtSvc jwt.Service, refreshTTL time.Duration, logs domainTicket.AuditLogRepository) *Service {
	return &Service{db: db, users: users, sessions: sessions, logs: logs, jwt: jwtSvc, refreshTTL: refreshTTL}
}

func (s *Service) Register(ctx context.Context, creatorRole string, req domainAuth.RegisterRequest) (domainAuth.RegisterResponse, error) {
	if user.Role(creatorRole) != user.RoleSOCManager {
		return domainAuth.RegisterResponse{}, user.ErrSOCManagerRequired
	}
	if err := req.Validate(); err != nil {
		return domainAuth.RegisterResponse{}, err
	}
	if req.Role != user.RoleL1Analyst && req.Role != user.RoleL2Analyst {
		return domainAuth.RegisterResponse{}, validator.ValidationErrors{{Field: "role", Message: "role must be one of: L1_ANALYST, L2_ANALYST"}}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return domainAuth.RegisterResponse{}, err
	}

	createdUser, err := s.users.Create(ctx, user.User{
		FullName:     req.FullName,
		Username:     req.Username,
		PasswordHash: string(hash),
		Role:         req.Role,
	})
	if err != nil {
		return domainAuth.RegisterResponse{}, err
	}

	return domainAuth.RegisterResponse{
		ID:        createdUser.ID,
		FullName:  createdUser.FullName,
		Username:  createdUser.Username,
		Role:      createdUser.Role,
		CreatedAt: createdUser.CreatedAt.Format(time.RFC3339),
	}, nil
}

func (s *Service) Login(ctx context.Context, req domainAuth.LoginRequest, track domainAuth.SessionTrackingRequest) (domainAuth.TokenResponse, error) {
	if err := req.Validate(); err != nil {
		return domainAuth.TokenResponse{}, err
	}

	u, err := s.users.GetByUsername(ctx, req.Username)
	if err != nil {
		if err == user.ErrUserNotFound {
			return domainAuth.TokenResponse{}, domainAuth.ErrInvalidCredentials
		}
		return domainAuth.TokenResponse{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		return domainAuth.TokenResponse{}, domainAuth.ErrInvalidCredentials
	}

	refreshToken, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		return domainAuth.TokenResponse{}, err
	}

	expiresAt := time.Now().Add(s.refreshTTL)
	var ua *string
	if track.UserAgent != "" {
		ua = &track.UserAgent
	}
	var ip *string
	if track.IPAddress != "" {
		ip = &track.IPAddress
	}

	// Create session first to get session ID
	session, err := s.sessions.Create(ctx, domainAuth.UserSession{
		UserID:       u.ID,
		RefreshToken: refreshToken,
		UserAgent:    ua,
		IPAddress:    ip,
		ExpiresAt:    expiresAt,
	})
	if err != nil {
		return domainAuth.TokenResponse{}, err
	}

	// Generate access token with session ID
	accessToken, accessExp, err := s.jwt.GenerateAccessToken(u, session.ID)
	if err != nil {
		return domainAuth.TokenResponse{}, err
	}

	return domainAuth.TokenResponse{
		AccessToken:           accessToken,
		AccessTokenExpiresIn:  accessExp,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresIn: int64(time.Until(expiresAt).Seconds()),
	}, nil
}

func (s *Service) Refresh(ctx context.Context, req domainAuth.RefreshTokenRequest, track domainAuth.SessionTrackingRequest) (domainAuth.TokenResponse, error) {
	if err := req.Validate(); err != nil {
		return domainAuth.TokenResponse{}, err
	}

	var out domainAuth.TokenResponse
	// Rotate refresh token in a transaction: revoke old, create new.
	err := database.WithTransaction(ctx, s.db, func(txCtx context.Context) error {
		sess, err := s.sessions.GetByRefreshToken(txCtx, req.RefreshToken)
		if err != nil {
			return err
		}

		u, err := s.users.GetByID(txCtx, sess.UserID)
		if err != nil {
			return err
		}

		// Revoke old refresh token
		if err := s.sessions.RevokeByRefreshToken(txCtx, req.RefreshToken); err != nil {
			return err
		}

		newRefresh, err := s.jwt.GenerateRefreshToken()
		if err != nil {
			return err
		}

		expiresAt := time.Now().Add(s.refreshTTL)
		var ua *string
		if track.UserAgent != "" {
			ua = &track.UserAgent
		}
		var ip *string
		if track.IPAddress != "" {
			ip = &track.IPAddress
		}

		// Create new session first to get session ID
		newSession, err := s.sessions.Create(txCtx, domainAuth.UserSession{
			UserID:       u.ID,
			RefreshToken: newRefresh,
			UserAgent:    ua,
			IPAddress:    ip,
			ExpiresAt:    expiresAt,
		})
		if err != nil {
			return err
		}

		// Generate access token with new session ID
		accessToken, accessExp, err := s.jwt.GenerateAccessToken(u, newSession.ID)
		if err != nil {
			return err
		}

		out = domainAuth.TokenResponse{
			AccessToken:           accessToken,
			AccessTokenExpiresIn:  accessExp,
			RefreshToken:          newRefresh,
			RefreshTokenExpiresIn: int64(time.Until(expiresAt).Seconds()),
		}
		return nil
	})
	if err != nil {
		return domainAuth.TokenResponse{}, err
	}
	return out, nil
}

func (s *Service) Logout(ctx context.Context, req domainAuth.RefreshTokenRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	return s.sessions.RevokeByRefreshToken(ctx, req.RefreshToken)
}

func (s *Service) ChangePassword(ctx context.Context, userID string, req domainAuth.ChangePasswordRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	return database.WithTransaction(ctx, s.db, func(txCtx context.Context) error {
		u, err := s.users.GetByID(txCtx, userID)
		if err != nil {
			return err
		}

		if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.OldPassword)); err != nil {
			return domainAuth.ErrInvalidCredentials
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		if err := s.users.UpdatePasswordHash(txCtx, userID, string(hash)); err != nil {
			return err
		}

		// Revoke all refresh tokens after password change.
		_, err = s.sessions.RevokeByUserID(txCtx, userID)
		return err
	})
}

func (s *Service) AdminUpdateAnalyst(ctx context.Context, actorUserID string, actorRole string, targetUserID string, req domainAuth.AdminUpdateAnalystRequest) error {
	if user.Role(actorRole) != user.RoleSOCManager {
		return user.ErrSOCManagerRequired
	}
	if actorUserID == "" || targetUserID == "" || actorUserID == targetUserID {
		return user.ErrUserUpdateForbidden
	}
	if err := req.Validate(); err != nil {
		return err
	}

	return database.WithTransaction(ctx, s.db, func(txCtx context.Context) error {
		tu, err := s.users.GetByID(txCtx, targetUserID)
		if err != nil {
			return err
		}
		if tu.Role != user.RoleL1Analyst && tu.Role != user.RoleL2Analyst {
			return user.ErrUserUpdateForbidden
		}

		var passwordHash *string
		if req.Password != nil {
			hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			hs := string(hash)
			passwordHash = &hs
		}

		if err := s.users.AdminUpdate(txCtx, targetUserID, req.FullName, req.Username, req.Role, passwordHash); err != nil {
			return err
		}

		if passwordHash != nil {
			_, err := s.sessions.RevokeByUserID(txCtx, targetUserID)
			return err
		}
		return nil
	})
}

func (s *Service) ListUsers(ctx context.Context, actorRole string) ([]domainAuth.UserListItem, error) {
	if err := requireSOCManager(actorRole); err != nil {
		return nil, err
	}

	users, err := s.users.List(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]domainAuth.UserListItem, 0, len(users))
	for _, u := range users {
		out = append(out, domainAuth.UserListItem{
			ID:        u.ID,
			FullName:  u.FullName,
			Username:  u.Username,
			Role:      u.Role,
			CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	return out, nil
}

func (s *Service) GetUserDetail(ctx context.Context, actorRole string, targetUserID string) (domainAuth.UserDetailResponse, error) {
	if err := requireSOCManager(actorRole); err != nil {
		return domainAuth.UserDetailResponse{}, err
	}

	targetUserID = strings.TrimSpace(targetUserID)
	u, err := s.users.GetByID(ctx, targetUserID)
	if err != nil {
		return domainAuth.UserDetailResponse{}, err
	}

	sessions, err := s.sessions.ListByUserID(ctx, targetUserID)
	if err != nil {
		return domainAuth.UserDetailResponse{}, err
	}

	auditLogs := make([]domainTicket.AuditLog, 0)
	if s.logs != nil {
		auditLogs, err = s.logs.ListByUserID(ctx, targetUserID)
		if err != nil {
			return domainAuth.UserDetailResponse{}, err
		}
	}

	sessOut := make([]domainAuth.UserSessionItem, 0, len(sessions))
	for _, sess := range sessions {
		sessOut = append(sessOut, domainAuth.UserSessionItem{
			ID:        sess.ID,
			UserAgent: sess.UserAgent,
			IPAddress: sess.IPAddress,
			IsRevoked: sess.IsRevoked,
			ExpiresAt: sess.ExpiresAt.UTC().Format(time.RFC3339),
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	logOut := make([]domainAuth.UserTicketLogItem, 0, len(auditLogs))
	for _, l := range auditLogs {
		var severity *string
		if l.Severity != nil {
			s := string(*l.Severity)
			severity = &s
		}

		logOut = append(logOut, domainAuth.UserTicketLogItem{
			ID:             l.ID,
			TicketID:       l.TicketID,
			TicketNumber:   l.TicketNumber,
			SourceIP:       l.SourceIP,
			ThreatCategory: l.ThreatCategory,
			ThreatType:     l.ThreatType,
			Severity:       severity,
			FirstSeen:      l.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:       l.LastSeen.UTC().Format(time.RFC3339),
			Action:         l.Action,
			Note:           l.Note,
			CreatedAt:      l.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	return domainAuth.UserDetailResponse{
		User: domainAuth.UserDetail{
			ID:        u.ID,
			FullName:  u.FullName,
			Username:  u.Username,
			Role:      u.Role,
			CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
		},
		Sessions:   sessOut,
		TicketLogs: logOut,
	}, nil
}

func (s *Service) RevokeUserSessions(ctx context.Context, actorRole string, targetUserID string, req domainAuth.RevokeUserSessionsRequest) (domainAuth.RevokeUserSessionsResponse, error) {
	if err := requireSOCManager(actorRole); err != nil {
		return domainAuth.RevokeUserSessionsResponse{}, err
	}
	if err := req.Validate(); err != nil {
		return domainAuth.RevokeUserSessionsResponse{}, err
	}

	targetUserID = strings.TrimSpace(targetUserID)
	if _, err := s.users.GetByID(ctx, targetUserID); err != nil {
		return domainAuth.RevokeUserSessionsResponse{}, err
	}

	if req.SessionID != nil {
		revoked, err := s.sessions.RevokeByIDAndUserID(ctx, *req.SessionID, targetUserID)
		if err != nil {
			return domainAuth.RevokeUserSessionsResponse{}, err
		}
		return domainAuth.RevokeUserSessionsResponse{
			Scope:      domainAuth.RevokeScopeSingle,
			SessionID:  req.SessionID,
			RevokedCnt: revoked,
		}, nil
	}

	revoked, err := s.sessions.RevokeByUserID(ctx, targetUserID)
	if err != nil {
		return domainAuth.RevokeUserSessionsResponse{}, err
	}

	return domainAuth.RevokeUserSessionsResponse{
		Scope:      domainAuth.RevokeScopeAll,
		RevokedCnt: revoked,
	}, nil
}

func (s *Service) DeleteAnalyst(ctx context.Context, actorUserID string, actorRole string, targetUserID string) error {
	if err := requireSOCManager(actorRole); err != nil {
		return err
	}

	actorUserID = strings.TrimSpace(actorUserID)
	targetUserID = strings.TrimSpace(targetUserID)
	if actorUserID == "" || targetUserID == "" || actorUserID == targetUserID {
		return user.ErrUserUpdateForbidden
	}

	return database.WithTransaction(ctx, s.db, func(txCtx context.Context) error {
		target, err := s.users.GetByID(txCtx, targetUserID)
		if err != nil {
			return err
		}
		if target.Role != user.RoleL1Analyst && target.Role != user.RoleL2Analyst {
			return user.ErrUserUpdateForbidden
		}

		if _, err := s.sessions.RevokeByUserID(txCtx, targetUserID); err != nil {
			return err
		}

		return s.users.DeleteByID(txCtx, targetUserID)
	})
}

func requireSOCManager(actorRole string) error {
	if user.Role(strings.TrimSpace(actorRole)) != user.RoleSOCManager {
		return user.ErrSOCManagerRequired
	}
	return nil
}
