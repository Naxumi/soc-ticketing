package auth

import (
	"net"
	"net/http"
	"strings"

	"github.com/naxumi/soc-ticketing/internal/domain/user"
	"github.com/naxumi/soc-ticketing/internal/pkg/validator"
)

type RegisterRequest struct {
	FullName string    `json:"full_name"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	Role     user.Role `json:"role"`
}

func (r *RegisterRequest) Validate() error {
	var errs validator.ValidationErrors

	if validator.IsEmpty(r.FullName) {
		errs = append(errs, validator.ValidationError{Field: "full_name", Message: "full_name is required"})
	} else if len(r.FullName) > 100 {
		errs = append(errs, validator.ValidationError{Field: "full_name", Message: "full_name must not exceed 100 characters"})
	}

	if validator.IsEmpty(r.Username) {
		errs = append(errs, validator.ValidationError{Field: "username", Message: "username is required"})
	} else if len(r.Username) > 50 {
		errs = append(errs, validator.ValidationError{Field: "username", Message: "username must not exceed 50 characters"})
	} else if strings.ContainsAny(r.Username, " \t\n\r") {
		errs = append(errs, validator.ValidationError{Field: "username", Message: "username must not contain spaces"})
	}

	if validator.IsEmpty(r.Password) {
		errs = append(errs, validator.ValidationError{Field: "password", Message: "password is required"})
	} else if len(r.Password) < 8 {
		errs = append(errs, validator.ValidationError{Field: "password", Message: "password must be at least 8 characters"})
	} else if len(r.Password) > 255 {
		errs = append(errs, validator.ValidationError{Field: "password", Message: "password must not exceed 255 characters"})
	}

	if r.Role != user.RoleL1Analyst && r.Role != user.RoleL2Analyst {
		errs = append(errs, validator.ValidationError{Field: "role", Message: "role must be one of: L1_ANALYST, L2_ANALYST"})
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (r *LoginRequest) Validate() error {
	var errs validator.ValidationErrors

	if validator.IsEmpty(r.Username) {
		errs = append(errs, validator.ValidationError{Field: "username", Message: "username is required"})
	}
	if validator.IsEmpty(r.Password) {
		errs = append(errs, validator.ValidationError{Field: "password", Message: "password is required"})
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (r *RefreshTokenRequest) Validate() error {
	var errs validator.ValidationErrors
	if validator.IsEmpty(r.RefreshToken) {
		errs = append(errs, validator.ValidationError{Field: "refresh_token", Message: "refresh_token is required"})
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (r *ChangePasswordRequest) Validate() error {
	var errs validator.ValidationErrors

	if validator.IsEmpty(r.OldPassword) {
		errs = append(errs, validator.ValidationError{Field: "old_password", Message: "old_password is required"})
	}

	if validator.IsEmpty(r.NewPassword) {
		errs = append(errs, validator.ValidationError{Field: "new_password", Message: "new_password is required"})
	} else if len(r.NewPassword) < 8 {
		errs = append(errs, validator.ValidationError{Field: "new_password", Message: "new_password must be at least 8 characters"})
	} else if len(r.NewPassword) > 255 {
		errs = append(errs, validator.ValidationError{Field: "new_password", Message: "new_password must not exceed 255 characters"})
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

type AdminUpdateAnalystRequest struct {
	FullName *string    `json:"full_name"`
	Username *string    `json:"username"`
	Role     *user.Role `json:"role"`
	Password *string    `json:"password"`
}

func (r *AdminUpdateAnalystRequest) Validate() error {
	var errs validator.ValidationErrors

	if r.FullName == nil && r.Username == nil && r.Role == nil && r.Password == nil {
		errs = append(errs, validator.ValidationError{Field: "body", Message: "at least one field must be provided"})
		return errs
	}

	if r.FullName != nil {
		if validator.IsEmpty(*r.FullName) {
			errs = append(errs, validator.ValidationError{Field: "full_name", Message: "full_name must not be empty"})
		} else if len(*r.FullName) > 100 {
			errs = append(errs, validator.ValidationError{Field: "full_name", Message: "full_name must not exceed 100 characters"})
		}
	}

	if r.Username != nil {
		if validator.IsEmpty(*r.Username) {
			errs = append(errs, validator.ValidationError{Field: "username", Message: "username must not be empty"})
		} else if len(*r.Username) > 50 {
			errs = append(errs, validator.ValidationError{Field: "username", Message: "username must not exceed 50 characters"})
		} else if strings.ContainsAny(*r.Username, " \t\n\r") {
			errs = append(errs, validator.ValidationError{Field: "username", Message: "username must not contain spaces"})
		}
	}

	if r.Role != nil {
		if *r.Role != user.RoleL1Analyst && *r.Role != user.RoleL2Analyst {
			errs = append(errs, validator.ValidationError{Field: "role", Message: "role must be one of: L1_ANALYST, L2_ANALYST"})
		}
	}

	if r.Password != nil {
		if validator.IsEmpty(*r.Password) {
			errs = append(errs, validator.ValidationError{Field: "password", Message: "password must not be empty"})
		} else if len(*r.Password) < 8 {
			errs = append(errs, validator.ValidationError{Field: "password", Message: "password must be at least 8 characters"})
		} else if len(*r.Password) > 255 {
			errs = append(errs, validator.ValidationError{Field: "password", Message: "password must not exceed 255 characters"})
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

type RevokeUserSessionsRequest struct {
	SessionID *string `json:"session_id,omitempty"`
}

func (r *RevokeUserSessionsRequest) Validate() error {
	if r.SessionID == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*r.SessionID)
	if trimmed == "" {
		return validator.ValidationErrors{{Field: "session_id", Message: "session_id must not be empty"}}
	}

	r.SessionID = &trimmed
	return nil
}

const (
	RevokeScopeAll    = "all"
	RevokeScopeSingle = "single"
)

type RevokeUserSessionsResponse struct {
	Scope      string  `json:"scope"`
	SessionID  *string `json:"session_id,omitempty"`
	RevokedCnt int64   `json:"revoked_count"`
}

type SessionTrackingRequest struct {
	UserAgent string
	IPAddress string
}

func SessionTrackingFromRequest(r *http.Request) SessionTrackingRequest {
	ua := r.UserAgent()
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	return SessionTrackingRequest{UserAgent: ua, IPAddress: ip}
}

type TokenResponse struct {
	AccessToken           string `json:"access_token"`
	AccessTokenExpiresIn  int64  `json:"access_token_expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
}

type AccessTokenResponse struct {
	AccessToken          string `json:"access_token"`
	AccessTokenExpiresIn int64  `json:"access_token_expires_in"`
}

type RegisterResponse struct {
	ID        string    `json:"id"`
	FullName  string    `json:"full_name"`
	Username  string    `json:"username"`
	Role      user.Role `json:"role"`
	CreatedAt string    `json:"created_at"`
}

type UserListItem struct {
	ID        string    `json:"id"`
	FullName  string    `json:"full_name"`
	Username  string    `json:"username"`
	Role      user.Role `json:"role"`
	CreatedAt string    `json:"created_at"`
}

type UserDetail struct {
	ID        string    `json:"id"`
	FullName  string    `json:"full_name"`
	Username  string    `json:"username"`
	Role      user.Role `json:"role"`
	CreatedAt string    `json:"created_at"`
}

type UserSessionItem struct {
	ID        string  `json:"id"`
	UserAgent *string `json:"user_agent,omitempty"`
	IPAddress *string `json:"ip_address,omitempty"`
	IsRevoked bool    `json:"is_revoked"`
	ExpiresAt string  `json:"expires_at"`
	CreatedAt string  `json:"created_at"`
}

type UserTicketLogItem struct {
	ID             string  `json:"id"`
	TicketID       string  `json:"ticket_id"`
	TicketNumber   string  `json:"ticket_number"`
	SourceIP       string  `json:"source_ip"`
	ThreatCategory *string `json:"threat_category,omitempty"`
	ThreatType     *string `json:"threat_type,omitempty"`
	Severity       *string `json:"severity,omitempty"`
	FirstSeen      string  `json:"first_seen"`
	LastSeen       string  `json:"last_seen"`
	Action         string  `json:"action"`
	Note           *string `json:"note,omitempty"`
	CreatedAt      string  `json:"created_at"`
}

type UserDetailResponse struct {
	User       UserDetail          `json:"user"`
	Sessions   []UserSessionItem   `json:"sessions"`
	TicketLogs []UserTicketLogItem `json:"ticket_logs"`
}
