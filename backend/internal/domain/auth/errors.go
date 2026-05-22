package auth

import "errors"

var (
	ErrInvalidCredentials  = errors.New("invalid username or password")
	ErrInvalidToken        = errors.New("invalid or expired token")
	ErrRefreshTokenRevoked = errors.New("refresh token has been revoked")
	ErrRefreshTokenExpired = errors.New("refresh token has expired")
)
