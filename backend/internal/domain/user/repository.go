package user

import "context"

type Repository interface {
	Create(ctx context.Context, u User) (User, error)
	List(ctx context.Context) ([]User, error)
	GetByUsername(ctx context.Context, username string) (User, error)
	GetByID(ctx context.Context, id string) (User, error)
	UpdatePasswordHash(ctx context.Context, id string, passwordHash string) error
	AdminUpdate(ctx context.Context, id string, fullName *string, username *string, role *Role, passwordHash *string) error
	DeleteByID(ctx context.Context, id string) error
}
