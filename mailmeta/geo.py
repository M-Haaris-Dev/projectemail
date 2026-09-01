"""IP geolocation via free ip-api.com endpoint. No API key required.

Free tier: HTTP only, ~45 req/min. Private/reserved IPs skipped.
"""

import ipaddress
import logging
import urllib.parse
import urllib.request

log = logging.getLogger("mailmeta.geo")

API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
UA = "mailMeta/2.0 (email-forensics)"
TIMEOUT = 5

_cache: dict[str, dict] = {}


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def geolocate(ip: str, client=None) -> dict:
    """Look up location for a public IPv4/IPv6 address.

    Returns dict with: status, country, countryCode, region, city, lat, lon,
    timezone, isp, org, as, query. status in success/private/fail.
    Cached per IP; client is an injected callable for tests.
    """
    if not ip:
        return {"status": "unknown", "error": "no IP address"}
    if not _is_public(ip):
        return {"status": "private", "ip": ip, "note": "private/local address (RFC 1918)"}

    if ip in _cache:
        return _cache[ip]

    url = API_URL.format(ip=urllib.parse.quote(ip))
    try:
        if client is not None:
            data = client(url)
        else:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                data = resp.read().decode("utf-8", errors="replace")
        import json
        result = json.loads(data)
        result["status"] = result.get("status", "fail")
        result["ip"] = result.get("query", ip)
        _cache[ip] = result
        return result
    except Exception as e:
        log.warning("geo lookup failed for %s: %s", ip, e)
        return {"status": "fail", "ip": ip, "error": str(e)}


def geolocate_many(ips: list[str], client=None) -> dict[str, dict]:
    """Geolocate several IPs, reused for Received chain hops."""
    out = {}
    for ip in ips:
        if not ip:
            continue
        out[ip] = geolocate(ip, client=client)
    return out