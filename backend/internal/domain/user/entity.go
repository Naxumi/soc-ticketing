package user

import "time"

type Role string

const (
	RoleL1Analyst  Role = "L1_ANALYST"
	RoleL2Analyst  Role = "L2_ANALYST"
	RoleSOCManager Role = "SOC_MANAGER"
)

type User struct {
	ID           string
	FullName     string
	Username     string
	PasswordHash string
	Role         Role
	CreatedAt    time.Time
}
