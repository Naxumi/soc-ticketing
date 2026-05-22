package postgresql

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/ticket"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/database"
)

type TicketRepository struct {
	db *database.DB
}

func NewTicketRepository(db *database.DB) *TicketRepository {
	return &TicketRepository{db: db}
}

func (r *TicketRepository) Count(ctx context.Context, qf ticket.ListTicketsQuery) (int64, error) {
	q := r.db.DBTX(ctx)
	statuses := qf.Statuses
	if len(statuses) == 0 && qf.Status != nil {
		statuses = []ticket.Status{*qf.Status}
	}
	statusFilter := any(nil)
	if len(statuses) > 0 {
		list := make([]string, 0, len(statuses))
		for _, s := range statuses {
			list = append(list, string(s))
		}
		statusFilter = list
	}
	severity := any(nil)
	if qf.Severity != nil {
		severity = string(*qf.Severity)
	}
	assignee := any(nil)
	if qf.AssigneeID != nil {
		assignee = *qf.AssigneeID
	}
	activityUser := any(nil)
	if qf.ActivityUserID != nil {
		activityUser = *qf.ActivityUserID
	}
	allowOpenForAll := qf.AllowOpenForAll
	allowEscalatedForAll := qf.AllowEscalatedForAll
	allowAggregatingForAll := qf.AllowAggregatingForAll

	isAggregatingOnly := len(statuses) == 1 && statuses[0] == ticket.StatusAggregating

	if isAggregatingOnly {
		if qf.AssigneeID != nil || qf.ActivityUserID != nil {
			return 0, nil
		}
		row := q.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM ticket_ingest_windows
			WHERE ($1::text IS NULL OR severity = $1)
		`, severity)
		var total int64
		if err := row.Scan(&total); err != nil {
			return 0, err
		}
		return total, nil
	}

	row := q.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM tickets t
		WHERE ($1::text[] IS NULL OR t.status = ANY($1))
		  AND ($2::text IS NULL OR t.severity = $2)
		  AND ($3::uuid IS NULL OR t.assignee_id = $3)
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
	`, statusFilter, severity, assignee, activityUser, allowOpenForAll, allowEscalatedForAll)
	var total int64
	if err := row.Scan(&total); err != nil {
		return 0, err
	}

	if allowAggregatingForAll && !isAggregatingOnly {
		row = q.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM ticket_ingest_windows
			WHERE ($1::text IS NULL OR severity = $1)
		`, severity)
		var windowTotal int64
		if err := row.Scan(&windowTotal); err != nil {
			return 0, err
		}
		total += windowTotal
		return total, nil
	}

	if len(statuses) == 0 && qf.AssigneeID == nil && qf.ActivityUserID == nil {
		row = q.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM ticket_ingest_windows
			WHERE ($1::text IS NULL OR severity = $1)
		`, severity)
		var windowTotal int64
		if err := row.Scan(&windowTotal); err != nil {
			return 0, err
		}
		total += windowTotal
	}
	return total, nil
}

func (r *TicketRepository) List(ctx context.Context, qf ticket.ListTicketsQuery, limit, offset int) ([]ticket.Ticket, error) {
	q := r.db.DBTX(ctx)
	statuses := qf.Statuses
	if len(statuses) == 0 && qf.Status != nil {
		statuses = []ticket.Status{*qf.Status}
	}
	statusFilter := any(nil)
	if len(statuses) > 0 {
		list := make([]string, 0, len(statuses))
		for _, s := range statuses {
			list = append(list, string(s))
		}
		statusFilter = list
	}
	severity := any(nil)
	if qf.Severity != nil {
		severity = string(*qf.Severity)
	}
	assignee := any(nil)
	if qf.AssigneeID != nil {
		assignee = *qf.AssigneeID
	}
	activityUser := any(nil)
	if qf.ActivityUserID != nil {
		activityUser = *qf.ActivityUserID
	}
	allowOpenForAll := qf.AllowOpenForAll
	allowEscalatedForAll := qf.AllowEscalatedForAll
	allowAggregatingForAll := qf.AllowAggregatingForAll

	isAggregatingOnly := len(statuses) == 1 && statuses[0] == ticket.StatusAggregating

	if isAggregatingOnly {
		if qf.AssigneeID != nil || qf.ActivityUserID != nil {
			return []ticket.Ticket{}, nil
		}
		return r.listAggregatingWindows(ctx, severity, limit, offset)
	}
	if allowAggregatingForAll {
		rows, err := q.Query(ctx, `
			WITH items AS (
				SELECT
					t.id,
					t.ticket_number,
					t.source_ip,
					t.attack_rule_id,
					t.threat_category,
					t.threat_type,
					t.severity,
					t.status,
					t.assignee_id,
					u.full_name AS assignee_name,
					t.first_seen,
					t.last_seen,
					t.raw_log_count,
					t.payload_first,
					t.payload_last,
					t.payload_sample,
					t.created_at,
					t.updated_at,
				FALSE AS is_aggregating,
				NULL::timestamptz AS window_expires_at,
				NULL::int AS window_seconds
				FROM tickets t
				LEFT JOIN users u ON u.id = t.assignee_id
				WHERE ($1::text[] IS NULL OR t.status = ANY($1))
				  AND ($2::text IS NULL OR t.severity = $2)
				  AND ($3::uuid IS NULL OR t.assignee_id = $3)
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

				UNION ALL

				SELECT
					id,
					''::text AS ticket_number,
					source_ip,
					attack_rule_id,
					threat_category,
					threat_type,
					severity,
					'AGGREGATING' AS status,
					NULL::uuid AS assignee_id,
					NULL::text AS assignee_name,
					first_seen,
					last_seen,
					raw_log_count,
					payload_first,
					payload_last,
					payload_sample,
					created_at,
					updated_at,
					TRUE AS is_aggregating,
					window_expires_at,
					window_seconds
				FROM ticket_ingest_windows
				WHERE ($2::text IS NULL OR severity = $2)
			)
			SELECT
				id,
				ticket_number,
				source_ip,
				attack_rule_id,
				threat_category,
				threat_type,
				severity,
				status,
				assignee_id,
				assignee_name,
				first_seen,
				last_seen,
				raw_log_count,
				payload_first,
				payload_last,
				payload_sample,
				created_at,
				updated_at,
				is_aggregating,
				window_expires_at,
				window_seconds
			FROM items
			ORDER BY last_seen DESC
			LIMIT $7 OFFSET $8
		`, statusFilter, severity, assignee, activityUser, allowOpenForAll, allowEscalatedForAll, limit, offset)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		out := make([]ticket.Ticket, 0)
		for rows.Next() {
			var t ticket.Ticket
			var sev *string
			var cat *string
			var typ *string
			var windowExpiresAt *time.Time
			var windowSeconds *int
			if err := rows.Scan(
				&t.ID,
				&t.TicketNumber,
				&t.SourceIP,
				&t.AttackRuleID,
				&cat,
				&typ,
				&sev,
				&t.Status,
				&t.AssigneeID,
				&t.AssigneeName,
				&t.FirstSeen,
				&t.LastSeen,
				&t.RawLogCount,
				&t.PayloadFirst,
				&t.PayloadLast,
				&t.PayloadSample,
				&t.CreatedAt,
				&t.UpdatedAt,
				&t.IsAggregating,
				&windowExpiresAt,
				&windowSeconds,
			); err != nil {
				return nil, err
			}
			t.ThreatCategory = cat
			t.ThreatType = typ
			if sev != nil {
				s := ticket.Severity(*sev)
				t.Severity = &s
			}
			t.WindowExpiresAt = windowExpiresAt
			t.WindowSeconds = windowSeconds
			out = append(out, t)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return out, nil
	}
	if len(statuses) == 0 && qf.AssigneeID == nil && qf.ActivityUserID == nil {
		return r.listTicketsWithWindows(ctx, severity, limit, offset)
	}

	rows, err := q.Query(ctx, `
		SELECT
			t.id,
			t.ticket_number,
			t.source_ip,
			t.attack_rule_id,
			t.threat_category,
			t.threat_type,
			t.severity,
			t.status,
			t.assignee_id,
			u.full_name AS assignee_name,
			t.first_seen,
			t.last_seen,
			t.raw_log_count,
			t.payload_first,
			t.payload_last,
			t.payload_sample,
			t.created_at,
			t.updated_at,
			FALSE AS is_aggregating,
			NULL::timestamptz AS window_expires_at,
			NULL::int AS window_seconds
		FROM tickets t
		LEFT JOIN users u ON u.id = t.assignee_id
		WHERE ($1::text[] IS NULL OR t.status = ANY($1))
		  AND ($2::text IS NULL OR t.severity = $2)
		  AND ($3::uuid IS NULL OR t.assignee_id = $3)
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
		LIMIT $7 OFFSET $8
	`, statusFilter, severity, assignee, activityUser, allowOpenForAll, allowEscalatedForAll, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ticket.Ticket, 0)
	for rows.Next() {
		var t ticket.Ticket
		var sev *string
		var cat *string
		var typ *string
		var windowExpiresAt *time.Time
		var windowSeconds *int
		if err := rows.Scan(
			&t.ID,
			&t.TicketNumber,
			&t.SourceIP,
			&t.AttackRuleID,
			&cat,
			&typ,
			&sev,
			&t.Status,
			&t.AssigneeID,
			&t.AssigneeName,
			&t.FirstSeen,
			&t.LastSeen,
			&t.RawLogCount,
			&t.PayloadFirst,
			&t.PayloadLast,
			&t.PayloadSample,
			&t.CreatedAt,
			&t.UpdatedAt,
			&t.IsAggregating,
			&windowExpiresAt,
			&windowSeconds,
		); err != nil {
			return nil, err
		}
		t.ThreatCategory = cat
		t.ThreatType = typ
		if sev != nil {
			s := ticket.Severity(*sev)
			t.Severity = &s
		}
		t.WindowExpiresAt = windowExpiresAt
		t.WindowSeconds = windowSeconds
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *TicketRepository) listAggregatingWindows(ctx context.Context, severity any, limit, offset int) ([]ticket.Ticket, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT
			id,
			''::text AS ticket_number,
			source_ip,
			attack_rule_id,
			threat_category,
			threat_type,
			severity,
			'AGGREGATING' AS status,
			NULL::uuid AS assignee_id,
			NULL::text AS assignee_name,
			first_seen,
			last_seen,
			raw_log_count,
			payload_first,
			payload_last,
			payload_sample,
			created_at,
			updated_at,
			TRUE AS is_aggregating,
			window_expires_at,
			window_seconds
		FROM ticket_ingest_windows
		WHERE ($1::text IS NULL OR severity = $1)
		ORDER BY last_seen DESC
		LIMIT $2 OFFSET $3
	`, severity, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ticket.Ticket, 0)
	for rows.Next() {
		var t ticket.Ticket
		var sev *string
		var cat *string
		var typ *string
		var windowExpiresAt *time.Time
		var windowSeconds *int
		if err := rows.Scan(
			&t.ID,
			&t.TicketNumber,
			&t.SourceIP,
			&t.AttackRuleID,
			&cat,
			&typ,
			&sev,
			&t.Status,
			&t.AssigneeID,
			&t.AssigneeName,
			&t.FirstSeen,
			&t.LastSeen,
			&t.RawLogCount,
			&t.PayloadFirst,
			&t.PayloadLast,
			&t.PayloadSample,
			&t.CreatedAt,
			&t.UpdatedAt,
			&t.IsAggregating,
			&windowExpiresAt,
			&windowSeconds,
		); err != nil {
			return nil, err
		}
		t.ThreatCategory = cat
		t.ThreatType = typ
		if sev != nil {
			s := ticket.Severity(*sev)
			t.Severity = &s
		}
		t.WindowExpiresAt = windowExpiresAt
		t.WindowSeconds = windowSeconds
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *TicketRepository) listTicketsWithWindows(ctx context.Context, severity any, limit, offset int) ([]ticket.Ticket, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		WITH items AS (
			SELECT
				t.id,
				t.ticket_number,
				t.source_ip,
				t.attack_rule_id,
				t.threat_category,
				t.threat_type,
				t.severity,
				t.status,
				t.assignee_id,
				u.full_name AS assignee_name,
				t.first_seen,
				t.last_seen,
				t.raw_log_count,
				t.payload_first,
				t.payload_last,
				t.payload_sample,
				t.created_at,
				t.updated_at,
				FALSE AS is_aggregating,
				NULL::timestamptz AS window_expires_at,
				NULL::int AS window_seconds
			FROM tickets t
			LEFT JOIN users u ON u.id = t.assignee_id
			WHERE ($1::text IS NULL OR t.severity = $1)

			UNION ALL

			SELECT
				id,
				''::text AS ticket_number,
				source_ip,
				attack_rule_id,
				threat_category,
				threat_type,
				severity,
				'AGGREGATING' AS status,
				NULL::uuid AS assignee_id,
				NULL::text AS assignee_name,
				first_seen,
				last_seen,
				raw_log_count,
				payload_first,
				payload_last,
				payload_sample,
				created_at,
				updated_at,
				TRUE AS is_aggregating,
				window_expires_at,
				window_seconds
			FROM ticket_ingest_windows
			WHERE ($1::text IS NULL OR severity = $1)
		)
		SELECT
			id,
			ticket_number,
			source_ip,
			attack_rule_id,
			threat_category,
			threat_type,
			severity,
			status,
			assignee_id,
			assignee_name,
			first_seen,
			last_seen,
			raw_log_count,
			payload_first,
			payload_last,
			payload_sample,
			created_at,
			updated_at,
			is_aggregating,
			window_expires_at,
			window_seconds
		FROM items
		ORDER BY last_seen DESC
		LIMIT $2 OFFSET $3
	`, severity, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ticket.Ticket, 0)
	for rows.Next() {
		var t ticket.Ticket
		var sev *string
		var cat *string
		var typ *string
		var windowExpiresAt *time.Time
		var windowSeconds *int
		if err := rows.Scan(
			&t.ID,
			&t.TicketNumber,
			&t.SourceIP,
			&t.AttackRuleID,
			&cat,
			&typ,
			&sev,
			&t.Status,
			&t.AssigneeID,
			&t.AssigneeName,
			&t.FirstSeen,
			&t.LastSeen,
			&t.RawLogCount,
			&t.PayloadFirst,
			&t.PayloadLast,
			&t.PayloadSample,
			&t.CreatedAt,
			&t.UpdatedAt,
			&t.IsAggregating,
			&windowExpiresAt,
			&windowSeconds,
		); err != nil {
			return nil, err
		}
		t.ThreatCategory = cat
		t.ThreatType = typ
		if sev != nil {
			s := ticket.Severity(*sev)
			t.Severity = &s
		}
		t.WindowExpiresAt = windowExpiresAt
		t.WindowSeconds = windowSeconds
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *TicketRepository) GetByID(ctx context.Context, id string) (ticket.Ticket, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT
			id,
			ticket_number,
			source_ip,
			attack_rule_id,
			threat_category,
			threat_type,
			severity,
			status,
			assignee_id,
			first_seen,
			last_seen,
			raw_log_count,
			payload_first,
			payload_last,
			payload_sample,
			created_at,
			updated_at
		FROM tickets
		WHERE id = $1
	`, id)

	var out ticket.Ticket
	var sev *string
	var cat *string
	var typ *string
	if err := row.Scan(
		&out.ID,
		&out.TicketNumber,
		&out.SourceIP,
		&out.AttackRuleID,
		&cat,
		&typ,
		&sev,
		&out.Status,
		&out.AssigneeID,
		&out.FirstSeen,
		&out.LastSeen,
		&out.RawLogCount,
		&out.PayloadFirst,
		&out.PayloadLast,
		&out.PayloadSample,
		&out.CreatedAt,
		&out.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ticket.Ticket{}, ticket.ErrTicketNotFound
		}
		return ticket.Ticket{}, err
	}
	out.ThreatCategory = cat
	out.ThreatType = typ
	if sev != nil {
		s := ticket.Severity(*sev)
		out.Severity = &s
	}
	return out, nil
}

func (r *TicketRepository) GetByIDForUpdate(ctx context.Context, id string) (ticket.Ticket, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT
			id,
			ticket_number,
			source_ip,
			attack_rule_id,
			threat_category,
			threat_type,
			severity,
			status,
			assignee_id,
			first_seen,
			last_seen,
			raw_log_count,
			payload_first,
			payload_last,
			payload_sample,
			created_at,
			updated_at
		FROM tickets
		WHERE id = $1
		FOR UPDATE
	`, id)

	var out ticket.Ticket
	var sev *string
	var cat *string
	var typ *string
	if err := row.Scan(
		&out.ID,
		&out.TicketNumber,
		&out.SourceIP,
		&out.AttackRuleID,
		&cat,
		&typ,
		&sev,
		&out.Status,
		&out.AssigneeID,
		&out.FirstSeen,
		&out.LastSeen,
		&out.RawLogCount,
		&out.PayloadFirst,
		&out.PayloadLast,
		&out.PayloadSample,
		&out.CreatedAt,
		&out.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ticket.Ticket{}, ticket.ErrTicketNotFound
		}
		return ticket.Ticket{}, err
	}
	out.ThreatCategory = cat
	out.ThreatType = typ
	if sev != nil {
		s := ticket.Severity(*sev)
		out.Severity = &s
	}
	return out, nil
}

func (r *TicketRepository) GetDetail(ctx context.Context, id string) (ticket.Detail, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT
			t.id,
			t.ticket_number,
			t.source_ip,
			t.attack_rule_id,
			t.threat_category,
			t.threat_type,
			t.severity,
			t.status,
			t.assignee_id,
			t.first_seen,
			t.last_seen,
			t.raw_log_count,
			t.payload_first,
			t.payload_last,
			t.payload_sample,
			t.created_at,
			t.updated_at,

			a.id,
			a.model_name,
			a.summary,
			a.detailed_analysis,
			a.attack_vector,
			a.potential_impact,
			a.confidence_score,
			a.processing_time_ms,
			a.created_at,

			COALESCE((
				SELECT jsonb_agg(
					jsonb_build_object(
						'wazuh_event_id', rl.wazuh_event_id,
						'source_ip', rl.source_ip,
						'attack_rule_id', rl.attack_rule_id,
						'event_timestamp', rl.event_timestamp,
						'raw_payload', rl.raw_payload,
						'created_at', rl.created_at
					)
					ORDER BY rl.event_timestamp ASC, rl.created_at ASC
				)
				FROM ticket_raw_logs rl
				WHERE rl.ticket_id = t.id
			), '[]'::jsonb) AS raw_logs,

			COALESCE((
				SELECT jsonb_agg(
					jsonb_build_object(
						'priority', r.priority,
						'action', r.action,
						'reason', r.reason,
						'created_at', r.created_at
					)
					ORDER BY r.priority ASC
				)
				FROM ticket_recommendations r
				WHERE a.id IS NOT NULL AND r.analysis_id = a.id
			), '[]'::jsonb) AS recommendations,

			COALESCE((
				SELECT jsonb_agg(
					jsonb_build_object(
						'ioc_type', i.ioc_type,
						'ioc_value', i.ioc_value,
						'created_at', i.created_at
					)
					ORDER BY i.created_at ASC
				)
				FROM ticket_iocs i
				WHERE i.ticket_id = t.id
			), '[]'::jsonb) AS iocs,

			COALESCE((
				SELECT jsonb_agg(
					jsonb_build_object(
						'action', l.action,
						'note', l.note,
						'created_at', l.created_at,
						'user_full_name', u.full_name,
						'user_role', u.role
					)
					ORDER BY l.created_at ASC
				)
				FROM ticket_logs l
				LEFT JOIN users u ON l.user_id = u.id
				WHERE l.ticket_id = t.id
			), '[]'::jsonb) AS audit_logs
		FROM tickets t
		LEFT JOIN ticket_analyses a ON a.ticket_id = t.id
		WHERE t.id = $1
	`, id)

	var t ticket.Ticket
	var sev *string
	var cat *string
	var typ *string

	var analysisID *string
	var modelName *string
	var summary *string
	var detailed *string
	var attackVector *string
	var potentialImpact *string
	var confidence *float64
	var processing *float64
	var analysisCreatedAt *time.Time

	var rawLogsJSON []byte
	var recsJSON []byte
	var iocsJSON []byte
	var logsJSON []byte

	if err := row.Scan(
		&t.ID,
		&t.TicketNumber,
		&t.SourceIP,
		&t.AttackRuleID,
		&cat,
		&typ,
		&sev,
		&t.Status,
		&t.AssigneeID,
		&t.FirstSeen,
		&t.LastSeen,
		&t.RawLogCount,
		&t.PayloadFirst,
		&t.PayloadLast,
		&t.PayloadSample,
		&t.CreatedAt,
		&t.UpdatedAt,
		&analysisID,
		&modelName,
		&summary,
		&detailed,
		&attackVector,
		&potentialImpact,
		&confidence,
		&processing,
		&analysisCreatedAt,
		&rawLogsJSON,
		&recsJSON,
		&iocsJSON,
		&logsJSON,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ticket.Detail{}, ticket.ErrTicketNotFound
		}
		return ticket.Detail{}, err
	}

	t.ThreatCategory = cat
	t.ThreatType = typ
	if sev != nil {
		s := ticket.Severity(*sev)
		t.Severity = &s
	}

	var ana *ticket.Analysis
	if analysisID != nil {
		createdAt := time.Time{}
		if analysisCreatedAt != nil {
			createdAt = *analysisCreatedAt
		}
		mn := ""
		if modelName != nil {
			mn = *modelName
		}
		ana = &ticket.Analysis{
			ID:               *analysisID,
			TicketID:         t.ID,
			ModelName:        mn,
			Summary:          summary,
			DetailedAnalysis: detailed,
			AttackVector:     attackVector,
			PotentialImpact:  potentialImpact,
			ConfidenceScore:  confidence,
			ProcessingTimeMs: processing,
			CreatedAt:        createdAt,
		}
	}

	type rawRow struct {
		WazuhEventID *string         `json:"wazuh_event_id"`
		SourceIP     string          `json:"source_ip"`
		AttackRuleID string          `json:"attack_rule_id"`
		EventTime    time.Time       `json:"event_timestamp"`
		RawPayload   json.RawMessage `json:"raw_payload"`
		CreatedAt    time.Time       `json:"created_at"`
	}
	var rawRows []rawRow
	if len(rawLogsJSON) > 0 {
		_ = json.Unmarshal(rawLogsJSON, &rawRows)
	}
	rawLogs := make([]ticket.RawLog, 0, len(rawRows))
	for _, rr := range rawRows {
		rawLogs = append(rawLogs, ticket.RawLog{
			TicketID:     t.ID,
			WazuhEventID: rr.WazuhEventID,
			SourceIP:     rr.SourceIP,
			AttackRuleID: rr.AttackRuleID,
			EventTime:    rr.EventTime,
			RawPayload:   rr.RawPayload,
			CreatedAt:    rr.CreatedAt,
		})
	}

	type recRow struct {
		Priority  int       `json:"priority"`
		Action    string    `json:"action"`
		Reason    *string   `json:"reason"`
		CreatedAt time.Time `json:"created_at"`
	}
	var recRows []recRow
	if len(recsJSON) > 0 {
		_ = json.Unmarshal(recsJSON, &recRows)
	}
	recs := make([]ticket.Recommendation, 0, len(recRows))
	for _, rr := range recRows {
		recs = append(recs, ticket.Recommendation{
			Priority:  rr.Priority,
			Action:    rr.Action,
			Reason:    rr.Reason,
			CreatedAt: rr.CreatedAt,
		})
	}

	type iocRow struct {
		IOCType   string    `json:"ioc_type"`
		IOCValue  string    `json:"ioc_value"`
		CreatedAt time.Time `json:"created_at"`
	}
	var iocRows []iocRow
	if len(iocsJSON) > 0 {
		_ = json.Unmarshal(iocsJSON, &iocRows)
	}
	iocs := make([]ticket.IOC, 0, len(iocRows))
	for _, ir := range iocRows {
		iocs = append(iocs, ticket.IOC{
			IOCType:   ir.IOCType,
			IOCValue:  ir.IOCValue,
			CreatedAt: ir.CreatedAt,
		})
	}

	type logRow struct {
		Action       string    `json:"action"`
		Note         *string   `json:"note"`
		CreatedAt    time.Time `json:"created_at"`
		UserFullName *string   `json:"user_full_name"`
		UserRole     *string   `json:"user_role"`
	}
	var logRows []logRow
	if len(logsJSON) > 0 {
		_ = json.Unmarshal(logsJSON, &logRows)
	}
	logs := make([]ticket.AuditLog, 0, len(logRows))
	for _, lr := range logRows {
		logs = append(logs, ticket.AuditLog{
			Action:       lr.Action,
			Note:         lr.Note,
			CreatedAt:    lr.CreatedAt,
			UserFullName: lr.UserFullName,
			UserRole:     lr.UserRole,
		})
	}

	return ticket.Detail{
		Ticket:          t,
		RawLogs:         rawLogs,
		Analysis:        ana,
		Recommendations: recs,
		IOCs:            iocs,
		AuditLogs:       logs,
	}, nil
}

func (r *TicketRepository) UpdateStatus(ctx context.Context, id string, status ticket.Status, assigneeID *string) error {
	q := r.db.DBTX(ctx)
	tag, err := q.Exec(ctx, `
		UPDATE tickets
		SET status = $1, assignee_id = $2, updated_at = NOW()
		WHERE id = $3
	`, string(status), assigneeID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ticket.ErrTicketNotFound
	}
	return nil
}

func (r *TicketRepository) UpdateFromAnalysis(ctx context.Context, id string, in ticket.UpdateFromAnalysisInput) error {
	q := r.db.DBTX(ctx)

	var severity *string
	if in.Severity != nil {
		s := string(*in.Severity)
		severity = &s
	}

	var status *string
	if in.Status != nil {
		s := string(*in.Status)
		status = &s
	}

	tag, err := q.Exec(ctx, `
		UPDATE tickets
		SET
			severity = COALESCE($1, severity),
			threat_category = CASE
				WHEN threat_category IS NULL OR BTRIM(threat_category) = ''
					THEN COALESCE($2, threat_category)
				ELSE threat_category
			END,
			threat_type = CASE
				WHEN threat_type IS NULL OR BTRIM(threat_type) = ''
					THEN COALESCE($3, threat_type)
				ELSE threat_type
			END,
			status = COALESCE($4, status),
			updated_at = NOW()
		WHERE id = $5
	`, severity, in.ThreatCategory, in.ThreatType, status, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ticket.ErrTicketNotFound
	}
	return nil
}

func (r *TicketRepository) UpsertAnalysis(ctx context.Context, ticketID string, in ticket.UpsertAnalysisInput) (string, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		INSERT INTO ticket_analyses (
			ticket_id, model_name, summary, detailed_analysis, attack_vector, potential_impact,
			confidence_score, processing_time_ms, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (ticket_id) DO UPDATE
		SET model_name = EXCLUDED.model_name,
			summary = EXCLUDED.summary,
			detailed_analysis = EXCLUDED.detailed_analysis,
			attack_vector = EXCLUDED.attack_vector,
			potential_impact = EXCLUDED.potential_impact,
			confidence_score = EXCLUDED.confidence_score,
			processing_time_ms = EXCLUDED.processing_time_ms,
			created_at = EXCLUDED.created_at
		RETURNING id
	`, ticketID, in.ModelName, in.Summary, in.DetailedAnalysis, in.AttackVector, in.PotentialImpact, in.ConfidenceScore, in.ProcessingTimeMs, in.CreatedAt)

	var analysisID string
	if err := row.Scan(&analysisID); err != nil {
		return "", err
	}
	return analysisID, nil
}

func (r *TicketRepository) ReplaceRecommendations(ctx context.Context, analysisID string, recs []ticket.UpsertRecommendationInput) error {
	q := r.db.DBTX(ctx)
	if _, err := q.Exec(ctx, `DELETE FROM ticket_recommendations WHERE analysis_id = $1`, analysisID); err != nil {
		return err
	}

	for _, rec := range recs {
		if strings.TrimSpace(rec.Action) == "" {
			continue
		}
		if _, err := q.Exec(ctx, `
			INSERT INTO ticket_recommendations (analysis_id, priority, action, reason)
			VALUES ($1, $2, $3, $4)
		`, analysisID, rec.Priority, rec.Action, rec.Reason); err != nil {
			return err
		}
	}
	return nil
}

func (r *TicketRepository) ReplaceMitreTechniques(ctx context.Context, ticketID string, techniques []string) error {
	q := r.db.DBTX(ctx)
	if _, err := q.Exec(ctx, `DELETE FROM ticket_iocs WHERE ticket_id = $1 AND ioc_type = 'mitre_technique'`, ticketID); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(techniques))
	for _, techniqueID := range techniques {
		val := strings.TrimSpace(techniqueID)
		if val == "" {
			continue
		}
		if _, ok := seen[val]; ok {
			continue
		}
		seen[val] = struct{}{}

		if _, err := q.Exec(ctx, `
			INSERT INTO ticket_iocs (ticket_id, ioc_type, ioc_value)
			VALUES ($1, 'mitre_technique', $2)
		`, ticketID, val); err != nil {
			return err
		}
	}

	return nil
}

type TicketRawLogRepository struct {
	db *database.DB
}

func NewTicketRawLogRepository(db *database.DB) *TicketRawLogRepository {
	return &TicketRawLogRepository{db: db}
}

func (r *TicketRawLogRepository) ListByTicketID(ctx context.Context, ticketID string) ([]ticket.RawLog, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT id, ticket_id, wazuh_event_id, source_ip, attack_rule_id, event_timestamp, raw_payload, created_at
		FROM ticket_raw_logs
		WHERE ticket_id = $1
		ORDER BY event_timestamp ASC, created_at ASC
	`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ticket.RawLog, 0)
	for rows.Next() {
		var item ticket.RawLog
		var payload []byte
		if err := rows.Scan(&item.ID, &item.TicketID, &item.WazuhEventID, &item.SourceIP, &item.AttackRuleID, &item.EventTime, &payload, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.RawPayload = json.RawMessage(payload)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type TicketAnalysisRepository struct {
	db *database.DB
}

func NewTicketAnalysisRepository(db *database.DB) *TicketAnalysisRepository {
	return &TicketAnalysisRepository{db: db}
}

func (r *TicketAnalysisRepository) GetByTicketID(ctx context.Context, ticketID string) (*ticket.Analysis, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT id, ticket_id, model_name, summary, detailed_analysis, attack_vector, potential_impact, confidence_score, processing_time_ms, created_at
		FROM ticket_analyses
		WHERE ticket_id = $1
	`, ticketID)

	var out ticket.Analysis
	if err := row.Scan(
		&out.ID,
		&out.TicketID,
		&out.ModelName,
		&out.Summary,
		&out.DetailedAnalysis,
		&out.AttackVector,
		&out.PotentialImpact,
		&out.ConfidenceScore,
		&out.ProcessingTimeMs,
		&out.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &out, nil
}

type TicketRecommendationRepository struct {
	db *database.DB
}

func NewTicketRecommendationRepository(db *database.DB) *TicketRecommendationRepository {
	return &TicketRecommendationRepository{db: db}
}

func (r *TicketRecommendationRepository) ListByAnalysisID(ctx context.Context, analysisID string) ([]ticket.Recommendation, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT id, analysis_id, priority, action, reason, created_at
		FROM ticket_recommendations
		WHERE analysis_id = $1
		ORDER BY priority ASC
	`, analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ticket.Recommendation, 0)
	for rows.Next() {
		var rec ticket.Recommendation
		if err := rows.Scan(&rec.ID, &rec.AnalysisID, &rec.Priority, &rec.Action, &rec.Reason, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type TicketIOCRepository struct {
	db *database.DB
}

func NewTicketIOCRepository(db *database.DB) *TicketIOCRepository {
	return &TicketIOCRepository{db: db}
}

func (r *TicketIOCRepository) ListByTicketID(ctx context.Context, ticketID string) ([]ticket.IOC, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT id, ticket_id, ioc_type, ioc_value, created_at
		FROM ticket_iocs
		WHERE ticket_id = $1
		ORDER BY created_at ASC
	`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ticket.IOC, 0)
	for rows.Next() {
		var i ticket.IOC
		if err := rows.Scan(&i.ID, &i.TicketID, &i.IOCType, &i.IOCValue, &i.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type TicketAuditLogRepository struct {
	db *database.DB
}

func NewTicketAuditLogRepository(db *database.DB) *TicketAuditLogRepository {
	return &TicketAuditLogRepository{db: db}
}

func (r *TicketAuditLogRepository) Create(ctx context.Context, l ticket.AuditLog) error {
	q := r.db.DBTX(ctx)
	_, err := q.Exec(ctx, `
		INSERT INTO ticket_logs (ticket_id, user_id, action, note)
		VALUES ($1, $2, $3, $4)
	`, l.TicketID, l.UserID, l.Action, l.Note)
	return err
}

func (r *TicketAuditLogRepository) ListByTicketID(ctx context.Context, ticketID string) ([]ticket.AuditLog, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT id, ticket_id, user_id, action, note, created_at
		FROM ticket_logs
		WHERE ticket_id = $1
		ORDER BY created_at ASC
	`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ticket.AuditLog, 0)
	for rows.Next() {
		var l ticket.AuditLog
		if err := rows.Scan(&l.ID, &l.TicketID, &l.UserID, &l.Action, &l.Note, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *TicketAuditLogRepository) ListByUserID(ctx context.Context, userID string) ([]ticket.AuditLog, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT
			l.id,
			l.ticket_id,
			l.user_id,
			l.action,
			l.note,
			l.created_at,
			t.ticket_number,
			t.source_ip,
			t.threat_category,
			t.threat_type,
			t.severity,
			t.first_seen,
			t.last_seen
		FROM ticket_logs l
		JOIN tickets t ON t.id = l.ticket_id
		WHERE l.user_id = $1
		ORDER BY l.created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ticket.AuditLog, 0)
	for rows.Next() {
		var l ticket.AuditLog
		var sev *string
		if err := rows.Scan(
			&l.ID,
			&l.TicketID,
			&l.UserID,
			&l.Action,
			&l.Note,
			&l.CreatedAt,
			&l.TicketNumber,
			&l.SourceIP,
			&l.ThreatCategory,
			&l.ThreatType,
			&sev,
			&l.FirstSeen,
			&l.LastSeen,
		); err != nil {
			return nil, err
		}
		if sev != nil {
			s := ticket.Severity(*sev)
			l.Severity = &s
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *TicketAuditLogRepository) GetLastStatusUpdatedBy(ctx context.Context, ticketID string) (*string, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT user_id
		FROM ticket_logs
		WHERE ticket_id = $1 AND (action = 'STATUS_UPDATED' OR action LIKE 'STATUS_UPDATED_TO_%')
		ORDER BY created_at DESC
		LIMIT 1
	`, ticketID)

	var userID *string
	if err := row.Scan(&userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return userID, nil
}

func (r *TicketAuditLogRepository) GetUserFullNameAndRoleByID(ctx context.Context, userID string) (string, string, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `SELECT full_name, role FROM users WHERE id = $1`, userID)

	var fullName, role string
	if err := row.Scan(&fullName, &role); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", nil
		}
		return "", "", err
	}
	return fullName, role, nil
}
