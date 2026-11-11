#!/bin/sh
echo "[DB-SYNC] Waiting for PostgreSQL and DHCP Load Balancer to become ready..."
until pg_isready -h localhost -p 5432 -U postgres -d dhcp_db >/dev/null 2>&1; do
  sleep 2
done

echo "[DB-SYNC] PostgreSQL is ready. Starting continuous lease synchronizer daemon..."

while true; do
  # Poll the DHCP Cluster state API
  DATA=$(curl -s --connect-timeout 2 http://192.168.10.200:8080/api/state 2>/dev/null)
  if [ -n "$DATA" ]; then
    # Parse leases array and UPSERT into PostgreSQL
    echo "$DATA" | jq -r '.leases[]? | "\(.ip)|\(.mac)|\(.hostname)|\(.state)|\(.node)|\(.ttl)|\(.isStatic)"' 2>/dev/null | while IFS="|" read -r ip mac host state node ttl isStatic; do
      if [ -n "$ip" ] && [ "$ip" != "null" ]; then
        PGPASSWORD=postgrespassword psql -h localhost -p 5432 -U postgres -d dhcp_db -q -c "
          INSERT INTO dhcp_leases (ip, mac, hostname, state, allocated_by, ttl, is_static, last_synced)
          VALUES ('$ip', '$mac', '$host', '$state', '$node', ${ttl:-0}, ${isStatic:-false}, CURRENT_TIMESTAMP)
          ON CONFLICT (ip) DO UPDATE SET
            mac = EXCLUDED.mac,
            hostname = EXCLUDED.hostname,
            state = EXCLUDED.state,
            allocated_by = EXCLUDED.allocated_by,
            ttl = EXCLUDED.ttl,
            is_static = EXCLUDED.is_static,
            last_synced = CURRENT_TIMESTAMP;
        " >/dev/null 2>&1
      fi
    done
  fi
  sleep 3
done
