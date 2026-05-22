package postgresql

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/ticket"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/webhook"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/database"
)

type WazuhWebhookRepository struct {
	db *database.DB
}

func NewWazuhWebhookRepository(db *database.DB) *WazuhWebhookRepository {
	return &WazuhWebhookRepository{db: db}
}

func (r *WazuhWebhookRepository) UpsertTicketByAlertID(ctx context.Context, in webhook.UpsertTicketInput) (string, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		WITH counter AS (
			INSERT INTO ticket_daily_counters AS tdc (ticket_date, seq)
			VALUES ((NOW() AT TIME ZONE 'UTC')::date, 1)
			ON CONFLICT (ticket_date)
			DO UPDATE SET seq = tdc.seq + 1
			RETURNING ticket_date, seq
		)
		INSERT INTO tickets (
			source_ip,
			attack_rule_id,
			threat_category,
			threat_type,
			severity,
			first_seen,
			last_seen,
			raw_log_count,
			ticket_number
		)
		SELECT
			'legacy',
			$1,
			$2,
			$3,
			$4,
			$5,
			$5,
			1,
			TO_CHAR(counter.ticket_date, 'YYYY-MMDD') || '-' || counter.seq::TEXT
		FROM counter
		RETURNING id
	`, in.WazuhAlertID, in.ThreatCategory, in.ThreatType, in.Severity, in.EventTimestamp)

	var ticketID string
	if err := row.Scan(&ticketID); err != nil {
		return "", err
	}
	return ticketID, nil
}

func (r *WazuhWebhookRepository) UpsertRawLog(ctx context.Context, ticketID string, rawPayload json.RawMessage) error {
	q := r.db.DBTX(ctx)
	_, err := q.Exec(ctx, `
		INSERT INTO ticket_raw_logs (ticket_id, source_ip, attack_rule_id, event_timestamp, raw_payload)
		VALUES ($1, 'legacy', 'legacy', NOW(), $2)
	`, ticketID, rawPayload)
	return err
}

func (r *WazuhWebhookRepository) UpsertAnalysis(ctx context.Context, ticketID string, in webhook.UpsertAnalysisInput) (string, error) {
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

func (r *WazuhWebhookRepository) ReplaceRecommendations(ctx context.Context, analysisID string, recs []webhook.UpsertRecommendationInput) error {
	q := r.db.DBTX(ctx)
	if _, err := q.Exec(ctx, `DELETE FROM ticket_recommendations WHERE analysis_id = $1`, analysisID); err != nil {
		return err
	}
	for _, rec := range recs {
		if _, err := q.Exec(ctx, `
			INSERT INTO ticket_recommendations (analysis_id, priority, action, reason)
			VALUES ($1, $2, $3, $4)
		`, analysisID, rec.Priority, rec.Action, rec.Reason); err != nil {
			return err
		}
	}
	return nil
}

func (r *WazuhWebhookRepository) ReplaceIOCs(ctx context.Context, ticketID string, iocs []webhook.UpsertIOCInput) error {
	q := r.db.DBTX(ctx)
	if _, err := q.Exec(ctx, `DELETE FROM ticket_iocs WHERE ticket_id = $1`, ticketID); err != nil {
		return err
	}
	for _, ioc := range iocs {
		if _, err := q.Exec(ctx, `
			INSERT INTO ticket_iocs (ticket_id, ioc_type, ioc_value)
			VALUES ($1, $2, $3)
		`, ticketID, ioc.IOCType, ioc.IOCValue); err != nil {
			return err
		}
	}
	return nil
}

func (r *WazuhWebhookRepository) GetWindowForUpdate(ctx context.Context, sourceIP string, attackRuleID string) (*webhook.IngestWindow, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		SELECT
			id,
			source_ip,
			attack_rule_id,
			threat_category,
			threat_type,
			severity,
			sample_score,
			first_seen,
			last_seen,
			raw_log_count,
			window_seconds,
			window_expires_at,
			payload_first,
			payload_last,
			payload_sample
		FROM ticket_ingest_windows
		WHERE source_ip = $1 AND attack_rule_id = $2
		FOR UPDATE
	`, sourceIP, attackRuleID)

	var out webhook.IngestWindow
	var sev *string
	if err := row.Scan(
		&out.ID,
		&out.SourceIP,
		&out.AttackRuleID,
		&out.ThreatCategory,
		&out.ThreatType,
		&sev,
		&out.SampleScore,
		&out.FirstSeen,
		&out.LastSeen,
		&out.RawLogCount,
		&out.WindowSeconds,
		&out.WindowExpiresAt,
		&out.PayloadFirst,
		&out.PayloadLast,
		&out.PayloadSample,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if sev != nil {
		s := ticket.Severity(*sev)
		out.Severity = &s
	}
	return &out, nil
}

func (r *WazuhWebhookRepository) CreateWindow(ctx context.Context, in webhook.CreateWindowInput) (*webhook.IngestWindow, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		INSERT INTO ticket_ingest_windows (
			source_ip,
			attack_rule_id,
			threat_category,
			threat_type,
			severity,
			sample_score,
			first_seen,
			last_seen,
			raw_log_count,
			window_seconds,
			window_expires_at,
			payload_first,
			payload_last,
			payload_sample
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id
	`,
		in.SourceIP,
		in.AttackRuleID,
		in.ThreatCategory,
		in.ThreatType,
		in.Severity,
		in.SampleScore,
		in.FirstSeen,
		in.LastSeen,
		in.RawLogCount,
		in.WindowSeconds,
		in.WindowExpiresAt,
		in.PayloadFirst,
		in.PayloadLast,
		in.PayloadSample,
	)

	out := &webhook.IngestWindow{
		SourceIP:        in.SourceIP,
		AttackRuleID:    in.AttackRuleID,
		ThreatCategory:  in.ThreatCategory,
		ThreatType:      in.ThreatType,
		Severity:        in.Severity,
		SampleScore:     in.SampleScore,
		FirstSeen:       in.FirstSeen,
		LastSeen:        in.LastSeen,
		RawLogCount:     in.RawLogCount,
		WindowSeconds:   in.WindowSeconds,
		WindowExpiresAt: in.WindowExpiresAt,
		PayloadFirst:    in.PayloadFirst,
		PayloadLast:     in.PayloadLast,
		PayloadSample:   in.PayloadSample,
	}
	if err := row.Scan(&out.ID); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *WazuhWebhookRepository) UpdateWindow(ctx context.Context, in webhook.UpdateWindowInput) error {
	q := r.db.DBTX(ctx)
	_, err := q.Exec(ctx, `
		UPDATE ticket_ingest_windows
		SET
			threat_category = COALESCE($2, threat_category),
			threat_type = COALESCE($3, threat_type),
			severity = COALESCE($4, severity),
			sample_score = $5,
			last_seen = $6,
			raw_log_count = $7,
			window_seconds = $8,
			window_expires_at = $9,
			payload_last = $10,
			payload_sample = $11,
			updated_at = NOW()
		WHERE id = $1
	`,
		in.WindowID,
		in.ThreatCategory,
		in.ThreatType,
		in.Severity,
		in.SampleScore,
		in.LastSeen,
		in.RawLogCount,
		in.WindowSeconds,
		in.WindowExpiresAt,
		in.PayloadLast,
		in.PayloadSample,
	)
	return err
}

func (r *WazuhWebhookRepository) InsertWindowLog(ctx context.Context, in webhook.InsertWindowLogInput) error {
	q := r.db.DBTX(ctx)
	_, err := q.Exec(ctx, `
		INSERT INTO ticket_ingest_window_logs (
			window_id,
			wazuh_event_id,
			source_ip,
			attack_rule_id,
			event_timestamp,
			raw_payload
		)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (wazuh_event_id) DO NOTHING
	`, in.WindowID, in.WazuhEventID, in.SourceIP, in.AttackRuleID, in.EventTime, in.RawPayload)
	return err
}

func (r *WazuhWebhookRepository) ListWindowLogPayloads(ctx context.Context, windowID string) ([]json.RawMessage, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT raw_payload
		FROM ticket_ingest_window_logs
		WHERE window_id = $1
		ORDER BY event_timestamp ASC
	`, windowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]json.RawMessage, 0)
	for rows.Next() {
		var payload json.RawMessage
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		out = append(out, payload)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *WazuhWebhookRepository) ListDueWindowsForUpdate(ctx context.Context, now time.Time) ([]webhook.IngestWindow, error) {
	q := r.db.DBTX(ctx)
	rows, err := q.Query(ctx, `
		SELECT
			id,
			source_ip,
			attack_rule_id,
			threat_category,
			threat_type,
			severity,
			sample_score,
			first_seen,
			last_seen,
			raw_log_count,
			window_seconds,
			window_expires_at,
			payload_first,
			payload_last,
			payload_sample
		FROM ticket_ingest_windows
		WHERE window_expires_at <= $1
		ORDER BY window_expires_at ASC
		FOR UPDATE SKIP LOCKED
	`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]webhook.IngestWindow, 0)
	for rows.Next() {
		var w webhook.IngestWindow
		var sev *string
		if err := rows.Scan(
			&w.ID,
			&w.SourceIP,
			&w.AttackRuleID,
			&w.ThreatCategory,
			&w.ThreatType,
			&sev,
			&w.SampleScore,
			&w.FirstSeen,
			&w.LastSeen,
			&w.RawLogCount,
			&w.WindowSeconds,
			&w.WindowExpiresAt,
			&w.PayloadFirst,
			&w.PayloadLast,
			&w.PayloadSample,
		); err != nil {
			return nil, err
		}
		if sev != nil {
			s := ticket.Severity(*sev)
			w.Severity = &s
		}
		out = append(out, w)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *WazuhWebhookRepository) CreateTicketFromWindow(ctx context.Context, in webhook.CreateTicketFromWindowInput) (string, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `
		WITH counter AS (
			INSERT INTO ticket_daily_counters AS tdc (ticket_date, seq)
			VALUES ((NOW() AT TIME ZONE 'UTC')::date, 1)
			ON CONFLICT (ticket_date)
			DO UPDATE SET seq = tdc.seq + 1
			RETURNING ticket_date, seq
		)
		INSERT INTO tickets (
			source_ip,
			attack_rule_id,
			threat_category,
			threat_type,
			severity,
			status,
			first_seen,
			last_seen,
			raw_log_count,
			payload_first,
			payload_last,
			payload_sample,
			ticket_number
		)
		SELECT
			$1,
			$2,
			$3,
			$4,
			$5,
			'OPEN',
			$6,
			$7,
			$8,
			$9,
			$10,
			$11,
			TO_CHAR(counter.ticket_date, 'YYYY-MMDD') || '-' || counter.seq::TEXT
		FROM counter
		RETURNING id
	`,
		in.SourceIP,
		in.AttackRuleID,
		in.ThreatCategory,
		in.ThreatType,
		in.Severity,
		in.FirstSeen,
		in.LastSeen,
		in.RawLogCount,
		in.PayloadFirst,
		in.PayloadLast,
		in.PayloadSample,
	)

	var ticketID string
	if err := row.Scan(&ticketID); err != nil {
		return "", err
	}
	return ticketID, nil
}

func (r *WazuhWebhookRepository) MoveWindowLogsToTicket(ctx context.Context, windowID string, ticketID string) (int64, error) {
	q := r.db.DBTX(ctx)
	tag, err := q.Exec(ctx, `
		INSERT INTO ticket_raw_logs (
			ticket_id,
			wazuh_event_id,
			source_ip,
			attack_rule_id,
			event_timestamp,
			raw_payload
		)
		SELECT
			$2,
			wazuh_event_id,
			source_ip,
			attack_rule_id,
			event_timestamp,
			raw_payload
		FROM ticket_ingest_window_logs
		WHERE window_id = $1
	`, windowID, ticketID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *WazuhWebhookRepository) DeleteWindow(ctx context.Context, windowID string) error {
	q := r.db.DBTX(ctx)
	_, err := q.Exec(ctx, `DELETE FROM ticket_ingest_windows WHERE id = $1`, windowID)
	return err
}

func (r *WazuhWebhookRepository) CountActiveWindows(ctx context.Context) (int, error) {
	q := r.db.DBTX(ctx)
	row := q.QueryRow(ctx, `SELECT COUNT(*) FROM ticket_ingest_windows`)
	var total int
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}
