package auth

import "context"

type Service interface {
	Register(ctx context.Context, creatorRole string, req RegisterRequest) (RegisterResponse, error)
	Login(ctx context.Context, req LoginRequest, track SessionTrackingRequest) (TokenResponse, error)
	Refresh(ctx context.Context, req RefreshTokenRequest, track SessionTrackingRequest) (TokenResponse, error)
	Logout(ctx context.Context, req RefreshTokenRequest) error
	ChangePassword(ctx context.Context, userID string, req ChangePasswordRequest) error
	AdminUpdateAnalyst(ctx context.Context, actorUserID string, actorRole string, targetUserID string, req AdminUpdateAnalystRequest) error
	ListUsers(ctx context.Context, actorRole string) ([]UserListItem, error)
	GetUserDetail(ctx context.Context, actorRole string, targetUserID string) (UserDetailResponse, error)
	RevokeUserSessions(ctx context.Context, actorRole string, targetUserID string, req RevokeUserSessionsRequest) (RevokeUserSessionsResponse, error)
	DeleteAnalyst(ctx context.Context, actorUserID string, actorRole string, targetUserID string) error
}
