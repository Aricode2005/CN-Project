#!/bin/sh
IFACE="${CAPTURE_IFACE:-dhcp_br0}"
OUT_DIR="${CAPTURE_DIR:-/captures}"
ROTATE_SECONDS="${CAPTURE_ROTATE_SECONDS:-600}"
FILTER="${CAPTURE_FILTER:-}"

mkdir -p "$OUT_DIR"

echo "[CAPTURE] Waiting for interface $IFACE ..."
while ! ip link show "$IFACE" >/dev/null 2>&1; do
  sleep 1
done

echo "[CAPTURE] Recording all traffic on $IFACE into $OUT_DIR (new file every ${ROTATE_SECONDS}s)"
exec tcpdump -i "$IFACE" -n -U -s 0 -Z root \
  -G "$ROTATE_SECONDS" \
  -w "$OUT_DIR/dhcp_cluster_%Y%m%d_%H%M%S.pcap" \
  $FILTER
