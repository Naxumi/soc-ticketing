package notification

import (
	"context"
	"math"
	"time"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/notification"
)

type Service struct {
	repo notification.Repository
}

func New(repo notification.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) List(ctx context.Context, userID string, q notification.ListNotificationsQuery) (notification.ListNotificationsResponse, error) {
	if err := q.Validate(); err != nil {
		return notification.ListNotificationsResponse{}, err
	}

	total, err := s.repo.CountByUser(ctx, userID, q)
	if err != nil {
		return notification.ListNotificationsResponse{}, err
	}

	totalPages := 0
	if q.Limit > 0 {
		totalPages = int(math.Ceil(float64(total) / float64(q.Limit)))
	}
	if total == 0 {
		totalPages = 0
	}

	offset := (q.Page - 1) * q.Limit
	items, err := s.repo.ListByUser(ctx, userID, q, q.Limit, offset)
	if err != nil {
		return notification.ListNotificationsResponse{}, err
	}

	outItems := make([]notification.NotificationListItem, 0, len(items))
	for _, n := range items {
		outItems = append(outItems, notification.NotificationListItem{
			ID:        n.ID,
			TicketID:  n.TicketID,
			Message:   n.Message,
			IsRead:    n.IsRead,
			CreatedAt: n.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	return notification.ListNotificationsResponse{
		Metadata: notification.NotificationListMetadata{
			TotalData:  total,
			Page:       q.Page,
			TotalPages: totalPages,
		},
		Data: outItems,
	}, nil
}

func (s *Service) MarkRead(ctx context.Context, userID string, notificationID string) error {
	if notificationID == "" {
		return notification.ErrNotificationNotFound
	}
	return s.repo.MarkRead(ctx, userID, notificationID)
}
