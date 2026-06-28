package postgresql

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/naxumi/soc-ticketing/internal/domain/auth"
	"github.com/naxumi/soc-ticketing/internal/pkg/database"
)

type SessionRepository struct {
	db *database.DB
}

func NewSessionRepository(db *database.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, s auth.UserSession) (auth.UserSession, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		INSERT INTO user_sessions (user_id, refresh_token, user_agent, ip_address, is_revoked, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, user_id, refresh_token, user_agent, ip_address, is_revoked, expires_at, created_at
	`, s.UserID, s.RefreshToken, s.UserAgent, s.IPAddress, s.IsRevoked, s.ExpiresAt)

	var out auth.UserSession
	if err := row.Scan(
		&out.ID,
		&out.UserID,
		&out.RefreshToken,
		&out.UserAgent,
		&out.IPAddress,
		&out.IsRevoked,
		&out.ExpiresAt,
		&out.CreatedAt,
	); err != nil {
		return auth.UserSession{}, err
	}
	return out, nil
}

func (r *SessionRepository) GetByID(ctx context.Context, sessionID string) (auth.UserSession, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT id, user_id, refresh_token, user_agent, ip_address, is_revoked, expires_at, created_at
		FROM user_sessions
		WHERE id = $1
	`, sessionID)

	var out auth.UserSession
	if err := row.Scan(
		&out.ID,
		&out.UserID,
		&out.RefreshToken,
		&out.UserAgent,
		&out.IPAddress,
		&out.IsRevoked,
		&out.ExpiresAt,
		&out.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.UserSession{}, auth.ErrInvalidToken
		}
		return auth.UserSession{}, err
	}

	return out, nil
}

func (r *SessionRepository) GetByRefreshToken(ctx context.Context, token string) (auth.UserSession, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT id, user_id, refresh_token, user_agent, ip_address, is_revoked, expires_at, created_at
		FROM user_sessions
		WHERE refresh_token = $1
	`, token)

	var out auth.UserSession
	if err := row.Scan(
		&out.ID,
		&out.UserID,
		&out.RefreshToken,
		&out.UserAgent,
		&out.IPAddress,
		&out.IsRevoked,
		&out.ExpiresAt,
		&out.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.UserSession{}, auth.ErrInvalidToken
		}
		return auth.UserSession{}, err
	}

	if out.IsRevoked {
		return auth.UserSession{}, auth.ErrRefreshTokenRevoked
	}
	if time.Now().After(out.ExpiresAt) {
		return auth.UserSession{}, auth.ErrRefreshTokenExpired
	}

	return out, nil
}

func (r *SessionRepository) ListByUserID(ctx context.Context, userID string) ([]auth.UserSession, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT id, user_id, refresh_token, user_agent, ip_address, is_revoked, expires_at, created_at
		FROM user_sessions
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]auth.UserSession, 0)
	for rows.Next() {
		var s auth.UserSession
		if err := rows.Scan(
			&s.ID,
			&s.UserID,
			&s.RefreshToken,
			&s.UserAgent,
			&s.IPAddress,
			&s.IsRevoked,
			&s.ExpiresAt,
			&s.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *SessionRepository) RevokeByRefreshToken(ctx context.Context, token string) error {
	q := r.db.DBTX(ctx)
	_, err := q.Exec(ctx, `UPDATE user_sessions SET is_revoked = TRUE WHERE refresh_token = $1`, token)
	return err
}

func (r *SessionRepository) RevokeByUserID(ctx context.Context, userID string) (int64, error) {
	q := r.db.DBTX(ctx)
	tag, err := q.Exec(ctx, `
		UPDATE user_sessions
		SET is_revoked = TRUE
		WHERE user_id = $1 AND is_revoked = FALSE
	`, userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *SessionRepository) RevokeByIDAndUserID(ctx context.Context, sessionID string, userID string) (int64, error) {
	q := r.db.DBTX(ctx)
	tag, err := q.Exec(ctx, `
		UPDATE user_sessions
		SET is_revoked = TRUE
		WHERE id = $1 AND user_id = $2 AND is_revoked = FALSE
	`, sessionID, userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
