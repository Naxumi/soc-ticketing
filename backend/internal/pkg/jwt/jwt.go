package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/go-chi/jwtauth/v5"

	"github.com/naxumi/soc-ticketing/internal/config"
	"github.com/naxumi/soc-ticketing/internal/domain/user"
)

type Service interface {
	JWTAuth() *jwtauth.JWTAuth
	GenerateAccessToken(u user.User, sessionID string) (token string, expiresInSeconds int64, err error)
	GenerateRefreshToken() (token string, err error)
}

type serviceImpl struct {
	ja        *jwtauth.JWTAuth
	accessTTL time.Duration
	issuer    string
	accessAud string
}

func New(cfg config.JWTConfig) Service {
	ja := jwtauth.New("HS256", []byte(cfg.Secret), nil)
	return &serviceImpl{
		ja:        ja,
		accessTTL: cfg.AccessTTL,
		issuer:    cfg.Issuer,
		accessAud: cfg.AccessAudience,
	}
}

func (s *serviceImpl) JWTAuth() *jwtauth.JWTAuth { return s.ja }

func (s *serviceImpl) GenerateAccessToken(u user.User, sessionID string) (string, int64, error) {
	expiresAt := time.Now().Add(s.accessTTL)
	claims := map[string]any{
		"sub":        u.ID,
		"username":   u.Username,
		"role":       string(u.Role),
		"type":       "access",
		"session_id": sessionID,
		"iss":        s.issuer,
		"aud":        s.accessAud,
		"exp":        expiresAt.Unix(),
		"iat":        time.Now().Unix(),
	}
	_, tokenString, err := s.ja.Encode(claims)
	if err != nil {
		return "", 0, err
	}
	return tokenString, int64(time.Until(expiresAt).Seconds()), nil
}

func (s *serviceImpl) GenerateRefreshToken() (string, error) {
	// 32 bytes -> 43 chars base64url without padding.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
