package postgresql

import (
	"context"

	"github.com/naxumi/soc-ticketing/internal/domain/report"
	"github.com/naxumi/soc-ticketing/internal/pkg/database"
)

type ReportRepository struct {
	db *database.DB
}

func NewReportRepository(db *database.DB) *ReportRepository {
	return &ReportRepository{db: db}
}

func (r *ReportRepository) ListTicketIDsForExport(ctx context.Context, qf report.ExportTicketsQuery) ([]string, error) {
	q := r.db.DBTX(ctx)

	status := any(nil)
	if qf.Status != nil {
		status = string(*qf.Status)
	}
	severity := any(nil)
	if qf.Severity != nil {
		severity = string(*qf.Severity)
	}
	assignee := any(nil)
	if qf.AssigneeID != nil {
		assignee = *qf.AssigneeID
	}

	rows, err := q.Query(ctx, `
		SELECT id
		FROM tickets
		WHERE first_seen >= $1 AND first_seen <= $2
		  AND ($3::text IS NULL OR status = $3)
		  AND ($4::text IS NULL OR severity = $4)
		  AND ($5::uuid IS NULL OR assignee_id = $5)
		ORDER BY last_seen DESC
		LIMIT $6
	`, qf.Window.From, qf.Window.To, status, severity, assignee, qf.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

var _ report.Repository = (*ReportRepository)(nil)
