-- Revert notifications.ticket_id to NOT NULL.
DELETE FROM notifications WHERE ticket_id IS NULL;
ALTER TABLE notifications ALTER COLUMN ticket_id SET NOT NULL;
