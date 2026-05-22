package ticket

import "errors"

var (
	ErrTicketNotFound            = errors.New("ticket not found")
	ErrInvalidTicketStatus       = errors.New("invalid ticket status")
	ErrTicketForbidden           = errors.New("ticket action forbidden")
	ErrTicketStatusTerminal      = errors.New("ticket in terminal status: only SOC Manager can modify")
	ErrInsufficientRoleForStatus = errors.New("insufficient role to set this ticket status")
	ErrTicketLockedByUser        = errors.New("ticket is locked: only the assigned analyst can update it")
)
