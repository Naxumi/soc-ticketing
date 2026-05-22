-- ==============================================================================
-- NAMA PROYEK   : SOC Ticketing System (Tugas Akhir / PBL)
-- DATABASE      : PostgreSQL
-- MIGRATION DOWN: Rollback Initial Schema
-- ==============================================================================

-- Drop all tables in reverse order of creation (respecting foreign key constraints)

DROP TABLE IF EXISTS ticket_logs CASCADE;
DROP TABLE IF EXISTS notifications CASCADE;
DROP TABLE IF EXISTS ticket_iocs CASCADE;
DROP TABLE IF EXISTS ticket_recommendations CASCADE;
DROP TABLE IF EXISTS ticket_analyses CASCADE;
DROP TABLE IF EXISTS ticket_raw_logs CASCADE;
DROP TABLE IF EXISTS ticket_ingest_window_logs CASCADE;
DROP TABLE IF EXISTS ticket_ingest_windows CASCADE;
DROP TABLE IF EXISTS tickets CASCADE;
DROP FUNCTION IF EXISTS set_ticket_number();
DROP TABLE IF EXISTS ticket_daily_counters CASCADE;
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS users CASCADE;