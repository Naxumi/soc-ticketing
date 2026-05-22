-- ============================================================================== 
-- NAMA PROYEK   : SOC Ticketing System (Tugas Akhir / PBL)
-- DATABASE      : PostgreSQL
-- ARSITEKTUR    : Tabel relasional dengan grouping raw log (IP + rule_id)
-- ============================================================================== 

-- Catatan: Pastikan function uuidv7() sudah tersedia di database Anda.

-- ==========================================
-- FASE 1: MANAJEMEN PENGGUNA & KEAMANAN
-- ==========================================

-- 1. Tabel Master: Pengguna (Analis SOC)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    full_name VARCHAR(100) NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('L1_ANALYST', 'L2_ANALYST', 'SOC_MANAGER')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_users_role ON users(role);

-- 2. Tabel Keamanan: Manajemen Sesi (Stateful Refresh Tokens pengganti Redis)
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token VARCHAR(255) UNIQUE NOT NULL,
    user_agent TEXT,
    ip_address VARCHAR(45),
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_user_sessions_token ON user_sessions(refresh_token);

-- ==========================================
-- FASE 2: BUFFER GROUPING RAW LOG (IP + rule_id)
-- ==========================================

-- 3. Tabel Buffer Header: Window aktif untuk grouping raw log
CREATE TABLE ticket_ingest_windows (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    source_ip VARCHAR(45) NOT NULL,
    attack_rule_id VARCHAR(100) NOT NULL,
    threat_category VARCHAR(100),
    threat_type VARCHAR(100),
    severity VARCHAR(20) CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    sample_score INT NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    raw_log_count INT NOT NULL DEFAULT 0,
    window_seconds INT NOT NULL DEFAULT 30,
    window_expires_at TIMESTAMPTZ NOT NULL,
    payload_first JSONB,
    payload_last JSONB,
    payload_sample JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ticket_ingest_windows_key UNIQUE (source_ip, attack_rule_id),
    CONSTRAINT chk_ticket_ingest_windows_last_seen CHECK (last_seen >= first_seen),
    CONSTRAINT chk_ticket_ingest_windows_window_seconds CHECK (window_seconds >= 1),
    CONSTRAINT chk_ticket_ingest_windows_raw_log_count CHECK (raw_log_count >= 0)
);
CREATE INDEX idx_ticket_ingest_windows_expires_at ON ticket_ingest_windows(window_expires_at);

-- 4. Tabel Buffer Detail: seluruh raw log per window aktif
CREATE TABLE ticket_ingest_window_logs (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    window_id UUID NOT NULL REFERENCES ticket_ingest_windows(id) ON DELETE CASCADE,
    wazuh_event_id VARCHAR(100),
    source_ip VARCHAR(45) NOT NULL,
    attack_rule_id VARCHAR(100) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    raw_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ticket_ingest_window_logs_event UNIQUE (wazuh_event_id)
);
CREATE INDEX idx_ticket_ingest_window_logs_window_id ON ticket_ingest_window_logs(window_id);

-- ==========================================
-- FASE 3: TRANSAKSI UTAMA (HEADER)
-- ==========================================

-- 5. Tabel Utama: Tiket Insiden hasil materialisasi window
CREATE TABLE tickets (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    ticket_number VARCHAR(32) UNIQUE NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    attack_rule_id VARCHAR(100) NOT NULL,
    threat_category VARCHAR(100),
    threat_type VARCHAR(100),
    severity VARCHAR(20) CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'ESCALATED', 'INVESTIGATING', 'FALSE_POSITIVE', 'RESOLVED')),
    assignee_id UUID REFERENCES users(id) ON DELETE SET NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    raw_log_count INT NOT NULL DEFAULT 0,
    payload_first JSONB,
    payload_last JSONB,
    payload_sample JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_tickets_last_seen CHECK (last_seen >= first_seen),
    CONSTRAINT chk_tickets_raw_log_count CHECK (raw_log_count >= 0),
    CONSTRAINT chk_updated_at_not_before_created_at CHECK (updated_at >= created_at)
);
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_assignee ON tickets(assignee_id);
CREATE INDEX idx_tickets_source_rule ON tickets(source_ip, attack_rule_id, last_seen DESC);

-- Counter harian untuk nomor tiket format: YYYYMMDD-000001
CREATE TABLE ticket_daily_counters (
    ticket_date DATE PRIMARY KEY,
    seq BIGINT NOT NULL DEFAULT 0
);

CREATE OR REPLACE FUNCTION set_ticket_number()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    created_ts TIMESTAMPTZ := COALESCE(NEW.created_at, NOW());
    v_ticket_date DATE := (created_ts AT TIME ZONE 'UTC')::date;
    next_seq BIGINT;
BEGIN
    IF NEW.ticket_number IS NOT NULL AND BTRIM(NEW.ticket_number) <> '' THEN
        RETURN NEW;
    END IF;

    INSERT INTO ticket_daily_counters (ticket_date, seq)
    VALUES (v_ticket_date, 1)
    ON CONFLICT (ticket_date)
    DO UPDATE SET seq = ticket_daily_counters.seq + 1
    RETURNING seq INTO next_seq;

    NEW.ticket_number := TO_CHAR(v_ticket_date, 'YYYY-MMDD') || '-' || next_seq::TEXT;
    NEW.created_at := created_ts;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_tickets_set_ticket_number
BEFORE INSERT ON tickets
FOR EACH ROW
EXECUTE FUNCTION set_ticket_number();

-- ==========================================
-- FASE 4: BUKTI FORENSIK (VERTICAL PARTITIONING)
-- ==========================================

-- 6. Tabel Forensik: Penyimpanan seluruh raw log Wazuh per tiket
CREATE TABLE ticket_raw_logs (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    wazuh_event_id VARCHAR(100),
    source_ip VARCHAR(45) NOT NULL,
    attack_rule_id VARCHAR(100) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    raw_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ticket_raw_logs_event UNIQUE (wazuh_event_id)
);
CREATE INDEX idx_ticket_raw_logs_ticket_id ON ticket_raw_logs(ticket_id);
CREATE INDEX idx_ticket_raw_logs_source_rule ON ticket_raw_logs(source_ip, attack_rule_id);

-- ==========================================
-- FASE 5: DETAIL ANALISIS KECERDASAN BUATAN (AI)
-- ==========================================

-- 7. Tabel Detail: Hasil Pemikiran LLM
CREATE TABLE ticket_analyses (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    ticket_id UUID UNIQUE NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    model_name VARCHAR(100) NOT NULL,
    summary TEXT,
    detailed_analysis TEXT,
    attack_vector TEXT,
    potential_impact TEXT,
    confidence_score DECIMAL(3,2),
    processing_time_ms DECIMAL(12,4),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. Tabel Detail: Rekomendasi Aksi (Pecahan Array)
CREATE TABLE ticket_recommendations (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    analysis_id UUID NOT NULL REFERENCES ticket_analyses(id) ON DELETE CASCADE,
    priority SMALLINT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 9. Tabel Detail: Indicator of Compromise (Bukti Teknis)
CREATE TABLE ticket_iocs (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    ioc_type VARCHAR(50) NOT NULL, 
    ioc_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ticket_iocs_value ON ticket_iocs(ioc_value);

-- ==========================================
-- FASE 6: INTERAKSI & AUDIT (SYARAT KAMPUS)
-- ==========================================

-- 10. Tabel Notifikasi: Dukungan Real-time (Server-Sent Events)
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notifications_user_unread ON notifications(user_id) WHERE is_read = FALSE;

-- 11. Tabel Audit: Jejak Langkah Analis
CREATE TABLE ticket_logs (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL, 
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ticket_logs_ticket_id ON ticket_logs(ticket_id);