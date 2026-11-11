-- Production Database Schema for DHCP Leases & Audit Log
CREATE TABLE IF NOT EXISTS dhcp_leases (
    ip VARCHAR(45) PRIMARY KEY,
    mac VARCHAR(17) NOT NULL,
    hostname VARCHAR(64),
    state VARCHAR(16) NOT NULL,
    allocated_by VARCHAR(32),
    ttl INT,
    is_static BOOLEAN DEFAULT FALSE,
    last_synced TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cluster_audit_log (
    id SERIAL PRIMARY KEY,
    event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(32),
    details TEXT
);

-- Seed initial static VIP records in PostgreSQL
INSERT INTO dhcp_leases (ip, mac, hostname, state, allocated_by, ttl, is_static)
VALUES 
    ('192.168.10.5', '00:1A:2B:3C:4D:01', 'gateway-admin-vip', 'ACTIVE', 'STATIC-VIP', -1, true),
    ('192.168.10.6', '00:1A:2B:3C:4D:02', 'prod-db-primary', 'ACTIVE', 'STATIC-VIP', -1, true)
ON CONFLICT (ip) DO NOTHING;

INSERT INTO cluster_audit_log (event_type, details)
VALUES ('SYSTEM_INIT', 'Production Database prod-db-primary initialized on 192.168.10.6:5432');
