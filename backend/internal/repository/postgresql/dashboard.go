package postgresql

import (
	"context"
	"time"

	"github.com/naxumi/soc-ticketing/internal/domain/dashboard"
	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
	"github.com/naxumi/soc-ticketing/internal/domain/user"
	"github.com/naxumi/soc-ticketing/internal/pkg/database"
)

type DashboardRepository struct {
	db *database.DB
}

func NewDashboardRepository(db *database.DB) *DashboardRepository {
	return &DashboardRepository{db: db}
}

func buildStatusFilter(statuses []ticket.Status) any {
	if len(statuses) == 0 {
		return any(nil)
	}
	list := make([]string, 0, len(statuses))
	for _, s := range statuses {
		list = append(list, string(s))
	}
	return list
}

func buildScopeArgs(filter dashboard.TicketScopeFilter) (statusFilter any, userID any, allowOpen bool, allowEscalated bool) {
	statusFilter = buildStatusFilter(filter.Statuses)
	if filter.UserID != nil {
		userID = *filter.UserID
	} else {
		userID = any(nil)
	}
	allowOpen = filter.AllowOpenForAll
	allowEscalated = filter.AllowEscalatedForAll
	return statusFilter, userID, allowOpen, allowEscalated
}

func (r *DashboardRepository) CountUnreadNotifications(ctx context.Context, userID string) (int64, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM notifications
		WHERE user_id = $1 AND is_read = FALSE
	`, userID)
	var total int64
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (r *DashboardRepository) CountTicketsByStatus(ctx context.Context, assigneeID *string) ([]dashboard.StatusCount, error) {
	q := r.db.DBTX(ctx)
	assignee := any(nil)
	if assigneeID != nil {
		assignee = *assigneeID
	}

	rows, err := q.Query(ctx, `
		SELECT status, COUNT(*)
		FROM tickets
		WHERE ($1::uuid IS NULL OR assignee_id = $1)
		GROUP BY status
	`, assignee)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]dashboard.StatusCount, 0)
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		out = append(out, dashboard.StatusCount{Status: ticket.Status(status), Count: count})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DashboardRepository) CountTicketsByStatusScoped(ctx context.Context, filter dashboard.TicketScopeFilter) ([]dashboard.StatusCount, error) {
	q := r.db.DBTX(ctx)
	statusFilter, userID, allowOpen, allowEscalated := buildScopeArgs(filter)

	rows, err := q.Query(ctx, `
		SELECT t.status, COUNT(*)
		FROM tickets t
		WHERE ($1::text[] IS NULL OR t.status = ANY($1))
		  AND (
			$2::uuid IS NULL
			OR t.assignee_id = $2
			OR EXISTS (
				SELECT 1
				FROM ticket_logs l
				WHERE l.ticket_id = t.id
				  AND l.user_id = $2
				  AND l.action LIKE 'STATUS_UPDATED_TO_%'
			)
			OR ($3::bool IS TRUE AND t.status = 'OPEN')
			OR ($4::bool IS TRUE AND t.status = 'ESCALATED')
		  )
		GROUP BY t.status
	`, statusFilter, userID, allowOpen, allowEscalated)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]dashboard.StatusCount, 0)
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		out = append(out, dashboard.StatusCount{Status: ticket.Status(status), Count: count})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DashboardRepository) CountTicketsBySeverity(ctx context.Context) ([]dashboard.StringCount, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT COALESCE(severity, 'unknown') AS sev, COUNT(*)
		FROM tickets
		GROUP BY COALESCE(severity, 'unknown')
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]dashboard.StringCount, 0)
	for rows.Next() {
		var sev string
		var count int64
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		out = append(out, dashboard.StringCount{Key: sev, Count: count})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DashboardRepository) CountTicketsBySeverityScoped(ctx context.Context, filter dashboard.TicketScopeFilter) ([]dashboard.StringCount, error) {
	q := r.db.DBTX(ctx)
	statusFilter, userID, allowOpen, allowEscalated := buildScopeArgs(filter)

	rows, err := q.Query(ctx, `
		SELECT COALESCE(t.severity, 'unknown') AS sev, COUNT(*)
		FROM tickets t
		WHERE ($1::text[] IS NULL OR t.status = ANY($1))
		  AND (
			$2::uuid IS NULL
			OR t.assignee_id = $2
			OR EXISTS (
				SELECT 1
				FROM ticket_logs l
				WHERE l.ticket_id = t.id
				  AND l.user_id = $2
				  AND l.action LIKE 'STATUS_UPDATED_TO_%'
			)
			OR ($3::bool IS TRUE AND t.status = 'OPEN')
			OR ($4::bool IS TRUE AND t.status = 'ESCALATED')
		  )
		GROUP BY COALESCE(t.severity, 'unknown')
	`, statusFilter, userID, allowOpen, allowEscalated)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]dashboard.StringCount, 0)
	for rows.Next() {
		var sev string
		var count int64
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		out = append(out, dashboard.StringCount{Key: sev, Count: count})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DashboardRepository) CountTicketsByStatusAndSeverities(ctx context.Context, status ticket.Status, severities []ticket.Severity) (int64, error) {
	sevs := make([]string, 0, len(severities))
	for _, s := range severities {
		sevs = append(sevs, string(s))
	}

	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM tickets
		WHERE status = $1
		  AND severity = ANY($2::text[])
	`, string(status), sevs)

	var total int64
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (r *DashboardRepository) CountTicketsCreatedInWindow(ctx context.Context, from, to time.Time) (int64, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM tickets
		WHERE first_seen >= $1 AND first_seen <= $2
	`, from, to)
	var total int64
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (r *DashboardRepository) CountTicketsCreatedInWindowScoped(ctx context.Context, from, to time.Time, filter dashboard.TicketScopeFilter) (int64, error) {
	q := r.db.DBTX(ctx)
	statusFilter, userID, allowOpen, allowEscalated := buildScopeArgs(filter)
	row := q.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM tickets t
		WHERE t.first_seen >= $1 AND t.first_seen <= $2
		  AND ($3::text[] IS NULL OR t.status = ANY($3))
		  AND (
			$4::uuid IS NULL
			OR t.assignee_id = $4
			OR EXISTS (
				SELECT 1
				FROM ticket_logs l
				WHERE l.ticket_id = t.id
				  AND l.user_id = $4
				  AND l.action LIKE 'STATUS_UPDATED_TO_%'
			)
			OR ($5::bool IS TRUE AND t.status = 'OPEN')
			OR ($6::bool IS TRUE AND t.status = 'ESCALATED')
		  )
	`, from, to, statusFilter, userID, allowOpen, allowEscalated)
	var total int64
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (r *DashboardRepository) CountTicketsCreatedBySeverityInWindow(ctx context.Context, from, to time.Time) ([]dashboard.StringCount, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT COALESCE(severity, 'unknown') AS sev, COUNT(*)
		FROM tickets
		WHERE first_seen >= $1 AND first_seen <= $2
		GROUP BY COALESCE(severity, 'unknown')
	`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]dashboard.StringCount, 0)
	for rows.Next() {
		var sev string
		var count int64
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		out = append(out, dashboard.StringCount{Key: sev, Count: count})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DashboardRepository) CountTicketsCreatedBySeverityInWindowScoped(ctx context.Context, from, to time.Time, filter dashboard.TicketScopeFilter) ([]dashboard.StringCount, error) {
	q := r.db.DBTX(ctx)
	statusFilter, userID, allowOpen, allowEscalated := buildScopeArgs(filter)
	rows, err := q.Query(ctx, `
		SELECT COALESCE(t.severity, 'unknown') AS sev, COUNT(*)
		FROM tickets t
		WHERE t.first_seen >= $1 AND t.first_seen <= $2
		  AND ($3::text[] IS NULL OR t.status = ANY($3))
		  AND (
			$4::uuid IS NULL
			OR t.assignee_id = $4
			OR EXISTS (
				SELECT 1
				FROM ticket_logs l
				WHERE l.ticket_id = t.id
				  AND l.user_id = $4
				  AND l.action LIKE 'STATUS_UPDATED_TO_%'
			)
			OR ($5::bool IS TRUE AND t.status = 'OPEN')
			OR ($6::bool IS TRUE AND t.status = 'ESCALATED')
		  )
		GROUP BY COALESCE(t.severity, 'unknown')
	`, from, to, statusFilter, userID, allowOpen, allowEscalated)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]dashboard.StringCount, 0)
	for rows.Next() {
		var sev string
		var count int64
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		out = append(out, dashboard.StringCount{Key: sev, Count: count})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DashboardRepository) ListRecentTicketsInWindow(ctx context.Context, from, to time.Time, limit int) ([]dashboard.RecentTicket, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT id, ticket_number, source_ip, attack_rule_id, threat_category, threat_type, severity, status, first_seen, last_seen, raw_log_count
		FROM tickets
		WHERE first_seen >= $1 AND first_seen <= $2
		ORDER BY last_seen DESC
		LIMIT $3
	`, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]dashboard.RecentTicket, 0)
	for rows.Next() {
		var t dashboard.RecentTicket
		var sev *string
		if err := rows.Scan(
			&t.ID,
			&t.TicketNumber,
			&t.SourceIP,
			&t.AttackRuleID,
			&t.ThreatCategory,
			&t.ThreatType,
			&sev,
			&t.Status,
			&t.FirstSeen,
			&t.LastSeen,
			&t.RawLogCount,
		); err != nil {
			return nil, err
		}
		if sev != nil {
			s := ticket.Severity(*sev)
			t.Severity = &s
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DashboardRepository) ListRecentTicketsInWindowScoped(ctx context.Context, from, to time.Time, filter dashboard.TicketScopeFilter, limit int) ([]dashboard.RecentTicket, error) {
	q := r.db.DBTX(ctx)
	statusFilter, userID, allowOpen, allowEscalated := buildScopeArgs(filter)
	rows, err := q.Query(ctx, `
		SELECT t.id, t.ticket_number, t.source_ip, t.attack_rule_id, t.threat_category, t.threat_type, t.severity, t.status, t.first_seen, t.last_seen, t.raw_log_count
		FROM tickets t
		WHERE t.first_seen >= $1 AND t.first_seen <= $2
		  AND ($3::text[] IS NULL OR t.status = ANY($3))
		  AND (
			$4::uuid IS NULL
			OR t.assignee_id = $4
			OR EXISTS (
				SELECT 1
				FROM ticket_logs l
				WHERE l.ticket_id = t.id
				  AND l.user_id = $4
				  AND l.action LIKE 'STATUS_UPDATED_TO_%'
			)
			OR ($5::bool IS TRUE AND t.status = 'OPEN')
			OR ($6::bool IS TRUE AND t.status = 'ESCALATED')
		  )
		ORDER BY t.last_seen DESC
		LIMIT $7
	`, from, to, statusFilter, userID, allowOpen, allowEscalated, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]dashboard.RecentTicket, 0)
	for rows.Next() {
		var t dashboard.RecentTicket
		var sev *string
		if err := rows.Scan(
			&t.ID,
			&t.TicketNumber,
			&t.SourceIP,
			&t.AttackRuleID,
			&t.ThreatCategory,
			&t.ThreatType,
			&sev,
			&t.Status,
			&t.FirstSeen,
			&t.LastSeen,
			&t.RawLogCount,
		); err != nil {
			return nil, err
		}
		if sev != nil {
			s := ticket.Severity(*sev)
			t.Severity = &s
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DashboardRepository) ListTeamActiveByAssigneeAndStatus(ctx context.Context, activeStatuses []ticket.Status) ([]dashboard.TeamStatusCount, error) {
	statuses := make([]string, 0, len(activeStatuses))
	for _, s := range activeStatuses {
		statuses = append(statuses, string(s))
	}

	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT u.id, u.full_name, u.username, u.role, t.status, COUNT(*)
		FROM tickets t
		JOIN users u ON u.id = t.assignee_id
		WHERE t.status = ANY($1::text[])
		GROUP BY u.id, u.full_name, u.username, u.role, t.status
	`, statuses)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]dashboard.TeamStatusCount, 0)
	for rows.Next() {
		var rrow dashboard.TeamStatusCount
		var roleStr string
		var statusStr string
		if err := rows.Scan(&rrow.UserID, &rrow.FullName, &rrow.Username, &roleStr, &statusStr, &rrow.Count); err != nil {
			return nil, err
		}
		rrow.Role = user.Role(roleStr)
		rrow.Status = ticket.Status(statusStr)
		out = append(out, rrow)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DashboardRepository) CountUnassignedActive(ctx context.Context, activeStatuses []ticket.Status) (int64, error) {
	statuses := make([]string, 0, len(activeStatuses))
	for _, s := range activeStatuses {
		statuses = append(statuses, string(s))
	}

	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM tickets
		WHERE assignee_id IS NULL
		  AND status = ANY($1::text[])
	`, statuses)
	var total int64
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (r *DashboardRepository) CountUnassignedActiveScoped(ctx context.Context, activeStatuses []ticket.Status, filter dashboard.TicketScopeFilter) (int64, error) {
	statuses := make([]string, 0, len(activeStatuses))
	for _, s := range activeStatuses {
		statuses = append(statuses, string(s))
	}

	q := r.db.DBTX(ctx)
	statusFilter, userID, allowOpen, allowEscalated := buildScopeArgs(filter)
	row := q.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM tickets t
		WHERE t.assignee_id IS NULL
		  AND ($1::text[] IS NULL OR t.status = ANY($1))
		  AND ($2::text[] IS NULL OR t.status = ANY($2))
		  AND (
			$3::uuid IS NULL
			OR EXISTS (
				SELECT 1
				FROM ticket_logs l
				WHERE l.ticket_id = t.id
				  AND l.user_id = $3
				  AND l.action LIKE 'STATUS_UPDATED_TO_%'
			)
			OR ($4::bool IS TRUE AND t.status = 'OPEN')
			OR ($5::bool IS TRUE AND t.status = 'ESCALATED')
		  )
	`, statuses, statusFilter, userID, allowOpen, allowEscalated)
	var total int64
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

var _ dashboard.Repository = (*DashboardRepository)(nil)
