package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	domainAuth "github.com/pitik0x/Ai-Security-analyst/internal/domain/auth"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/user"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/validator"
)

type fakeUserRepo struct {
	createFn func(ctx context.Context, u user.User) (user.User, error)

	createdUser user.User
	createCalls int
}

func (f *fakeUserRepo) Create(ctx context.Context, u user.User) (user.User, error) {
	f.createCalls++
	f.createdUser = u
	if f.createFn != nil {
		return f.createFn(ctx, u)
	}
	return user.User{}, nil
}

func (f *fakeUserRepo) List(ctx context.Context) ([]user.User, error) {
	return []user.User{}, nil
}

func (f *fakeUserRepo) GetByUsername(ctx context.Context, username string) (user.User, error) {
	return user.User{}, user.ErrUserNotFound
}

func (f *fakeUserRepo) GetByID(ctx context.Context, id string) (user.User, error) {
	return user.User{}, user.ErrUserNotFound
}

func (f *fakeUserRepo) UpdatePasswordHash(ctx context.Context, id string, passwordHash string) error {
	return nil
}

func (f *fakeUserRepo) AdminUpdate(ctx context.Context, id string, fullName *string, username *string, role *user.Role, passwordHash *string) error {
	return nil
}

func (f *fakeUserRepo) DeleteByID(ctx context.Context, id string) error {
	return nil
}

func TestRegister_RequiresSOCManager(t *testing.T) {
	svc := New(nil, &fakeUserRepo{}, nil, nil, 0, nil)

	req := domainAuth.RegisterRequest{
		FullName: "Alice",
		Username: "alice",
		Password: "password123",
		Role:     user.RoleL1Analyst,
	}

	_, err := svc.Register(context.Background(), string(user.RoleL1Analyst), req)
	if !errors.Is(err, user.ErrSOCManagerRequired) {
		t.Fatalf("expected ErrSOCManagerRequired, got %v", err)
	}
}

func TestRegister_ValidatesRequest(t *testing.T) {
	svc := New(nil, &fakeUserRepo{}, nil, nil, 0, nil)

	req := domainAuth.RegisterRequest{
		FullName: "",
		Username: "",
		Password: "",
		Role:     user.RoleSOCManager,
	}

	_, err := svc.Register(context.Background(), string(user.RoleSOCManager), req)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) {
		t.Fatalf("expected validator.ValidationErrors, got %T: %v", err, err)
	}
}

func TestRegister_CreatesUserAndReturnsResponse(t *testing.T) {
	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	repo := &fakeUserRepo{}
	repo.createFn = func(ctx context.Context, u user.User) (user.User, error) {
		return user.User{
			ID:           "user-1",
			FullName:     u.FullName,
			Username:     u.Username,
			PasswordHash: u.PasswordHash,
			Role:         u.Role,
			CreatedAt:    createdAt,
		}, nil
	}

	svc := New(nil, repo, nil, nil, 0, nil)

	req := domainAuth.RegisterRequest{
		FullName: "Alice",
		Username: "alice",
		Password: "password123",
		Role:     user.RoleL2Analyst,
	}

	resp, err := svc.Register(context.Background(), string(user.RoleSOCManager), req)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if repo.createCalls != 1 {
		t.Fatalf("expected Create to be called once, got %d", repo.createCalls)
	}
	if repo.createdUser.PasswordHash == "" || repo.createdUser.PasswordHash == req.Password {
		t.Fatalf("expected password to be hashed, got %q", repo.createdUser.PasswordHash)
	}

	if resp.ID != "user-1" {
		t.Fatalf("expected id user-1, got %q", resp.ID)
	}
	if resp.FullName != req.FullName || resp.Username != req.Username || resp.Role != req.Role {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.CreatedAt != createdAt.Format(time.RFC3339) {
		t.Fatalf("expected created_at %q, got %q", createdAt.Format(time.RFC3339), resp.CreatedAt)
	}
}

func TestRegister_PropagatesRepoError(t *testing.T) {
	repo := &fakeUserRepo{}
	repo.createFn = func(ctx context.Context, u user.User) (user.User, error) {
		return user.User{}, user.ErrUsernameExists
	}

	svc := New(nil, repo, nil, nil, 0, nil)

	req := domainAuth.RegisterRequest{
		FullName: "Alice",
		Username: "alice",
		Password: "password123",
		Role:     user.RoleL1Analyst,
	}

	_, err := svc.Register(context.Background(), string(user.RoleSOCManager), req)
	if !errors.Is(err, user.ErrUsernameExists) {
		t.Fatalf("expected ErrUsernameExists, got %v", err)
	}
}
