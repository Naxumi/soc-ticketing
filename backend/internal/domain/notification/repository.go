package notification

import "context"

type Repository interface {
	CountByUser(ctx context.Context, userID string, q ListNotificationsQuery) (int64, error)
	ListByUser(ctx context.Context, userID string, q ListNotificationsQuery, limit, offset int) ([]Notification, error)
	MarkRead(ctx context.Context, userID string, notificationID string) error
	CreateForAllUsers(ctx context.Context, ticketID *string, message string) ([]Notification, error)
}
