package user

import "errors"

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrUsernameExists      = errors.New("username already exists")
	ErrSOCManagerRequired  = errors.New("soc manager access required")
	ErrUserUpdateForbidden = errors.New("user update forbidden")
	ErrInvalidUserRole     = errors.New("invalid user role")
	ErrInvalidUsername     = errors.New("invalid username")
	ErrInvalidFullName     = errors.New("invalid full_name")
	ErrInvalidPassword     = errors.New("invalid password")
)
