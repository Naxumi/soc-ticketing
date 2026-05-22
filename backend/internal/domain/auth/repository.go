package auth

import "context"

type SessionRepository interface {
	Create(ctx context.Context, s UserSession) (UserSession, error)
	GetByID(ctx context.Context, sessionID string) (UserSession, error)
	GetByRefreshToken(ctx context.Context, token string) (UserSession, error)
	ListByUserID(ctx context.Context, userID string) ([]UserSession, error)
	RevokeByRefreshToken(ctx context.Context, token string) error
	RevokeByUserID(ctx context.Context, userID string) (int64, error)
	RevokeByIDAndUserID(ctx context.Context, sessionID string, userID string) (int64, error)
}
