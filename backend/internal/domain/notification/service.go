package notification

import "context"

type Service interface {
	List(ctx context.Context, userID string, q ListNotificationsQuery) (ListNotificationsResponse, error)
	MarkRead(ctx context.Context, userID string, notificationID string) error
}
