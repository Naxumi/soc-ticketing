package auth

import "time"

type UserSession struct {
	ID           string
	UserID       string
	RefreshToken string
	UserAgent    *string
	IPAddress    *string
	IsRevoked    bool
	ExpiresAt    time.Time
	CreatedAt    time.Time
}
