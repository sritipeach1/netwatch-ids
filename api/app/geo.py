"""Country lookup. Uses a GeoLite2 database when one is mounted, otherwise a small demo table."""
from __future__ import annotations

import ipaddress
import os

# Demo mode attackers live in 198.18.0.0/15 (reserved for benchmarking, never routed on the internet).
DEMO_COUNTRIES = {
    10: "Russia", 11: "Russia", 12: "China", 13: "China", 14: "United States",
    15: "United States", 16: "Brazil", 17: "India", 18: "Germany", 19: "Vietnam",
}

_reader = None
_reader_tried = False


def _get_reader():
    global _reader, _reader_tried
    if _reader_tried:
        return _reader
    _reader_tried = True
    path = os.getenv("NETWATCH_GEOIP_DB", "")
    if path and os.path.exists(path):
        try:
            import geoip2.database  # type: ignore

            _reader = geoip2.database.Reader(path)
        except Exception:
            _reader = None
    return _reader


def lookup(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"
    if addr in ipaddress.ip_network("198.18.0.0/15"):
        return DEMO_COUNTRIES.get(int(ip.split(".")[2]), "Unknown")
    if addr.is_private or addr.is_loopback:
        return "Private network"
    reader = _get_reader()
    if reader is not None:
        try:
            return reader.country(ip).country.name or "Unknown"
        except Exception:
            return "Unknown"
    return "Unknown"
