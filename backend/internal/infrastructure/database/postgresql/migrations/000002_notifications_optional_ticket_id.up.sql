-- Allow notifications without ticket_id for aggregating windows.
ALTER TABLE notifications ALTER COLUMN ticket_id DROP NOT NULL;
