package dashboard

import "context"

type Service interface {
	Get(ctx context.Context, userID string, role string, q Query) (Response, error)
}
