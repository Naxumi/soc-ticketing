package notification

type Publisher interface {
	Publish(userID string, n Notification)
}
