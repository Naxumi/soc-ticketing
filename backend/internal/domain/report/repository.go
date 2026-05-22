package report

import "context"

// Repository provides report-specific DB queries.
// Keep this separate from domain/ticket repository to avoid widening that interface.
type Repository interface {
	ListTicketIDsForExport(ctx context.Context, q ExportTicketsQuery) ([]string, error)
}
