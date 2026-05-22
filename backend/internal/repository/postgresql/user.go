package postgresql

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/user"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/database"
)

type UserRepository struct {
	db *database.DB
}

func NewUserRepository(db *database.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, u user.User) (user.User, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		INSERT INTO users (full_name, username, password_hash, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, full_name, username, password_hash, role, created_at
	`, u.FullName, u.Username, u.PasswordHash, string(u.Role))

	var out user.User
	var role string
	if err := row.Scan(&out.ID, &out.FullName, &out.Username, &out.PasswordHash, &role, &out.CreatedAt); err != nil {
		// Unique violation for username
		if isUniqueViolation(err) {
			return user.User{}, user.ErrUsernameExists
		}
		return user.User{}, err
	}
	out.Role = user.Role(role)
	return out, nil
}

func (r *UserRepository) List(ctx context.Context) ([]user.User, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT id, full_name, username, password_hash, role, created_at
		FROM users
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]user.User, 0)
	for rows.Next() {
		var u user.User
		var role string
		if err := rows.Scan(&u.ID, &u.FullName, &u.Username, &u.PasswordHash, &role, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.Role = user.Role(role)
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (user.User, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT id, full_name, username, password_hash, role, created_at
		FROM users
		WHERE username = $1
	`, username)

	var out user.User
	var role string
	if err := row.Scan(&out.ID, &out.FullName, &out.Username, &out.PasswordHash, &role, &out.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return user.User{}, user.ErrUserNotFound
		}
		return user.User{}, err
	}
	out.Role = user.Role(role)
	return out, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (user.User, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT id, full_name, username, password_hash, role, created_at
		FROM users
		WHERE id = $1
	`, id)

	var out user.User
	var role string
	if err := row.Scan(&out.ID, &out.FullName, &out.Username, &out.PasswordHash, &role, &out.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return user.User{}, user.ErrUserNotFound
		}
		return user.User{}, err
	}
	out.Role = user.Role(role)
	return out, nil
}

func (r *UserRepository) UpdatePasswordHash(ctx context.Context, id string, passwordHash string) error {
	q := r.db.DBTX(ctx)
	ct, err := q.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, passwordHash, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return user.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) AdminUpdate(ctx context.Context, id string, fullName *string, username *string, role *user.Role, passwordHash *string) error {
	q := r.db.DBTX(ctx)

	var roleStr *string
	if role != nil {
		rs := string(*role)
		roleStr = &rs
	}

	ct, err := q.Exec(ctx, `
		UPDATE users
		SET
			full_name = COALESCE($1, full_name),
			username = COALESCE($2, username),
			role = COALESCE($3, role),
			password_hash = COALESCE($4, password_hash)
		WHERE id = $5
	`, fullName, username, roleStr, passwordHash, id)
	if err != nil {
		if isUniqueViolation(err) {
			return user.ErrUsernameExists
		}
		return err
	}
	if ct.RowsAffected() == 0 {
		return user.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) DeleteByID(ctx context.Context, id string) error {
	q := r.db.DBTX(ctx)
	ct, err := q.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return user.ErrUserNotFound
	}
	return nil
}
