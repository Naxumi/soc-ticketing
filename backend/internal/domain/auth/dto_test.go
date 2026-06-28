package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/naxumi/soc-ticketing/internal/domain/user"
	"github.com/naxumi/soc-ticketing/internal/pkg/validator"
)

func TestRegisterRequest_Validate(t *testing.T) {
	tests := []struct {
		name       string
		req        RegisterRequest
		wantErr    bool
		wantFields []string
	}{
		{
			name:    "valid L1 request",
			req:     RegisterRequest{FullName: "Alice", Username: "alice", Password: "password123", Role: user.RoleL1Analyst},
			wantErr: false,
		},
		{
			name:    "valid L2 request",
			req:     RegisterRequest{FullName: "Bob", Username: "bob", Password: "securepass", Role: user.RoleL2Analyst},
			wantErr: false,
		},
		{
			name:       "all fields empty",
			req:        RegisterRequest{},
			wantErr:    true,
			wantFields: []string{"full_name", "username", "password", "role"},
		},
		{
			name:       "full_name too long",
			req:        RegisterRequest{FullName: strings.Repeat("a", 101), Username: "alice", Password: "password123", Role: user.RoleL1Analyst},
			wantErr:    true,
			wantFields: []string{"full_name"},
		},
		{
			name:       "username has spaces",
			req:        RegisterRequest{FullName: "Alice", Username: "alice smith", Password: "password123", Role: user.RoleL1Analyst},
			wantErr:    true,
			wantFields: []string{"username"},
		},
		{
			name:       "password too short",
			req:        RegisterRequest{FullName: "Alice", Username: "alice", Password: "abc", Role: user.RoleL1Analyst},
			wantErr:    true,
			wantFields: []string{"password"},
		},
		{
			name:       "invalid role SOC_MANAGER",
			req:        RegisterRequest{FullName: "Alice", Username: "alice", Password: "password123", Role: user.RoleSOCManager},
			wantErr:    true,
			wantFields: []string{"role"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tt.wantFields != nil {
				var verrs validator.ValidationErrors
				if !errors.As(err, &verrs) {
					t.Fatalf("expected ValidationErrors, got %T", err)
				}
				fieldSet := make(map[string]bool)
				for _, ve := range verrs {
					fieldSet[ve.Field] = true
				}
				for _, f := range tt.wantFields {
					if !fieldSet[f] {
						t.Errorf("expected validation error for field %q, not found in %v", f, verrs)
					}
				}
			}
		})
	}
}

func TestLoginRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     LoginRequest
		wantErr bool
	}{
		{name: "valid", req: LoginRequest{Username: "alice", Password: "pass"}, wantErr: false},
		{name: "empty username", req: LoginRequest{Password: "pass"}, wantErr: true},
		{name: "empty password", req: LoginRequest{Username: "alice"}, wantErr: true},
		{name: "both empty", req: LoginRequest{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestChangePasswordRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     ChangePasswordRequest
		wantErr bool
	}{
		{name: "valid", req: ChangePasswordRequest{OldPassword: "oldpass12", NewPassword: "newpass12"}, wantErr: false},
		{name: "empty old", req: ChangePasswordRequest{NewPassword: "newpass12"}, wantErr: true},
		{name: "new too short", req: ChangePasswordRequest{OldPassword: "oldpass12", NewPassword: "abc"}, wantErr: true},
		{name: "both empty", req: ChangePasswordRequest{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRefreshTokenRequest_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		req := RefreshTokenRequest{RefreshToken: "some-token"}
		if err := req.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		req := RefreshTokenRequest{}
		if err := req.Validate(); err == nil {
			t.Error("expected error for empty refresh token")
		}
	})
}

func TestAdminUpdateAnalystRequest_Validate(t *testing.T) {
	fn := "New Name"
	un := "newuser"
	pw := "newpassword123"
	shortPw := "abc"
	role := user.RoleL1Analyst
	badRole := user.RoleSOCManager

	tests := []struct {
		name    string
		req     AdminUpdateAnalystRequest
		wantErr bool
	}{
		{name: "update full_name only", req: AdminUpdateAnalystRequest{FullName: &fn}, wantErr: false},
		{name: "update username only", req: AdminUpdateAnalystRequest{Username: &un}, wantErr: false},
		{name: "update password only", req: AdminUpdateAnalystRequest{Password: &pw}, wantErr: false},
		{name: "update role only", req: AdminUpdateAnalystRequest{Role: &role}, wantErr: false},
		{name: "no fields provided", req: AdminUpdateAnalystRequest{}, wantErr: true},
		{name: "short password", req: AdminUpdateAnalystRequest{Password: &shortPw}, wantErr: true},
		{name: "invalid role SOC_MANAGER", req: AdminUpdateAnalystRequest{Role: &badRole}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
