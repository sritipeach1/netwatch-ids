#!/bin/sh
set -e
CMD="uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"

if [ "$NETWATCH_RESPONSE" = "enforce" ]; then
  # Create the blocklist set and drop rule once. Runs as root with NET_ADMIN.
  nft add table inet netwatch 2>/dev/null || true
  nft add set inet netwatch blocklist '{ type ipv4_addr; flags timeout; }' 2>/dev/null || true
  nft add chain inet netwatch input '{ type filter hook input priority -10; policy accept; }' 2>/dev/null || true
  nft list chain inet netwatch input | grep -q blocklist || \
    nft add rule inet netwatch input ip saddr @blocklist drop
  exec $CMD
fi

exec su netwatch -s /bin/sh -c "exec $CMD"
