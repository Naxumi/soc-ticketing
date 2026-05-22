package notification

import (
	"strconv"
	"strings"
	"time"

	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/validator"
)

type ListNotificationsQuery struct {
	Page   int
	Limit  int
	IsRead *bool
}

func ListNotificationsQueryFromStrings(pageStr, limitStr, isReadStr string) (ListNotificationsQuery, error) {
	page := 1
	limit := 10

	if strings.TrimSpace(pageStr) != "" {
		p, err := strconv.Atoi(pageStr)
		if err != nil {
			return ListNotificationsQuery{}, validator.ValidationErrors{{Field: "page", Message: "page must be an integer"}}
		}
		page = p
	}
	if strings.TrimSpace(limitStr) != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil {
			return ListNotificationsQuery{}, validator.ValidationErrors{{Field: "limit", Message: "limit must be an integer"}}
		}
		limit = l
	}

	var isRead *bool
	if strings.TrimSpace(isReadStr) != "" {
		s := strings.ToLower(strings.TrimSpace(isReadStr))
		switch s {
		case "true":
			v := true
			isRead = &v
		case "false":
			v := false
			isRead = &v
		default:
			return ListNotificationsQuery{}, validator.ValidationErrors{{Field: "is_read", Message: "is_read must be true or false"}}
		}
	}

	q := ListNotificationsQuery{Page: page, Limit: limit, IsRead: isRead}
	if err := q.Validate(); err != nil {
		return ListNotificationsQuery{}, err
	}
	return q, nil
}

func (q ListNotificationsQuery) Validate() error {
	var errs validator.ValidationErrors
	if q.Page < 1 {
		errs = append(errs, validator.ValidationError{Field: "page", Message: "page must be >= 1"})
	}
	if q.Limit < 1 {
		errs = append(errs, validator.ValidationError{Field: "limit", Message: "limit must be >= 1"})
	} else if q.Limit > 100 {
		errs = append(errs, validator.ValidationError{Field: "limit", Message: "limit must be <= 100"})
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ========================================
// Notification Response DTOs
// ========================================

type NotificationListMetadata struct {
	TotalData  int64 `json:"total_data"`
	Page       int   `json:"page"`
	TotalPages int   `json:"total_pages"`
}

type NotificationListItem struct {
	ID        string  `json:"id"`
	TicketID  *string `json:"ticket_id,omitempty"`
	Message   string  `json:"message"`
	IsRead    bool    `json:"is_read"`
	CreatedAt string  `json:"created_at"`
}

type ListNotificationsResponse struct {
	Metadata NotificationListMetadata `json:"metadata"`
	Data     []NotificationListItem   `json:"data"`
}

func FormatTimeRFC3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
