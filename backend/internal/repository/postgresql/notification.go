package postgresql

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/notification"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/database"
)

type NotificationRepository struct {
	db *database.DB
}

func NewNotificationRepository(db *database.DB) *NotificationRepository {
	return &NotificationRepository{db: db}
}

func (r *NotificationRepository) CountByUser(ctx context.Context, userID string, q notification.ListNotificationsQuery) (int64, error) {
	query := r.db.DBTX(ctx)
	row := query.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM notifications
		WHERE user_id = $1
			AND ($2::boolean IS NULL OR is_read = $2)
	`, userID, q.IsRead)

	var total int64
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (r *NotificationRepository) ListByUser(ctx context.Context, userID string, q notification.ListNotificationsQuery, limit, offset int) ([]notification.Notification, error) {
	query := r.db.DBTX(ctx)
	rows, err := query.Query(ctx, `
		SELECT id, user_id, ticket_id, message, is_read, created_at
		FROM notifications
		WHERE user_id = $1
			AND ($2::boolean IS NULL OR is_read = $2)
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`, userID, q.IsRead, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]notification.Notification, 0)
	for rows.Next() {
		var n notification.Notification
		var ticketID *string
		if err := rows.Scan(&n.ID, &n.UserID, &ticketID, &n.Message, &n.IsRead, &n.CreatedAt); err != nil {
			return nil, err
		}
		n.TicketID = ticketID
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *NotificationRepository) MarkRead(ctx context.Context, userID string, notificationID string) error {
	query := r.db.DBTX(ctx)
	tag, err := query.Exec(ctx, `
		UPDATE notifications
		SET is_read = TRUE
		WHERE id = $1 AND user_id = $2
	`, notificationID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return notification.ErrNotificationNotFound
	}
	return nil
}

func (r *NotificationRepository) CreateForAllUsers(ctx context.Context, ticketID *string, message string) ([]notification.Notification, error) {
	query := r.db.DBTX(ctx)
	rows, err := query.Query(ctx, `
		INSERT INTO notifications (user_id, ticket_id, message)
		SELECT id, $1, $2
		FROM users
		RETURNING id, user_id, ticket_id, message, is_read, created_at
	`, ticketID, message)
	if err != nil {
		// Surface FK or other DB errors directly
		if errors.Is(err, pgx.ErrNoRows) {
			return []notification.Notification{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	out := make([]notification.Notification, 0)
	for rows.Next() {
		var n notification.Notification
		var createdTicketID *string
		if err := rows.Scan(&n.ID, &n.UserID, &createdTicketID, &n.Message, &n.IsRead, &n.CreatedAt); err != nil {
			return nil, err
		}
		n.TicketID = createdTicketID
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
