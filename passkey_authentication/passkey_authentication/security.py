"""Security utilities: client IP, RP ID / origin resolution, rate limiting."""
import ipaddress
import json

import frappe

from .challenges import _cache


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def _is_internal(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


def get_client_ip() -> str:
    """Client IP, honouring proxy headers only when the direct peer is a local/private proxy.

    Behind nginx (which appends the real peer address) the right-most
    X-Forwarded-For entry is the one our proxy added; left-most entries are
    client-controlled and must not be trusted.
    """
    req = frappe.request
    if not req:
        return "unknown"
    remote = req.remote_addr or ""
    if remote and not _is_internal(remote):
        return remote
    real_ip = req.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    forwarded_for = req.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[-1].strip()
    return remote or "unknown"


def get_user_agent() -> str:
    return (frappe.request.headers.get("User-Agent", "unknown") if frappe.request else "unknown")[:500]


def get_origin() -> str:
    return frappe.request.headers.get("Origin", "") if frappe.request else ""


def _request_scheme() -> str:
    req = frappe.request
    if not req:
        return "https"
    forwarded = req.headers.get("X-Forwarded-Proto")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return req.scheme or "https"


# ---------------------------------------------------------------------------
# RP ID / origin
# ---------------------------------------------------------------------------

def validate_rp_id(rp_id: str) -> bool:
    if not rp_id:
        return False
    if rp_id.startswith("http://") or rp_id.startswith("https://"):
        return False
    if "/" in rp_id or ":" in rp_id:
        return False
    return rp_id == "localhost" or "." in rp_id


def get_rp_id(settings) -> str:
    if settings.rp_id:
        return settings.rp_id.strip()
    if frappe.request and frappe.request.host:
        return frappe.request.host.split(":")[0]
    return "localhost"


def parse_allowed_origins(settings) -> list:
    if not settings.allowed_origins:
        return []
    try:
        origins = json.loads(settings.allowed_origins)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(origins, list):
        return []
    return [o.strip().rstrip("/") for o in origins if isinstance(o, str) and o.strip()]


def get_expected_origins(settings, rp_id: str) -> list:
    """All origins a ceremony may legitimately come from."""
    origins = parse_allowed_origins(settings)
    if not origins:
        scheme = _request_scheme()
        host = frappe.request.host if frappe.request and frappe.request.host else rp_id
        # Keep the port (e.g. localhost:8000) only when the host really is the RP ID.
        if host.split(":")[0] != rp_id:
            host = rp_id
        origins = [f"{scheme}://{host}"]
    # Registered client apps (other web origins, Android apk-key-hash origins, iOS).
    from .client_apps import get_client_origins
    for origin in get_client_origins(rp_id):
        if origin not in origins:
            origins.append(origin)
    return origins


def check_secure_context(settings, rp_id: str):
    """Return an error message when HTTPS is enforced but not used, else None."""
    if not settings.enforce_https:
        return None
    if rp_id in ("localhost", "127.0.0.1"):
        return None
    if _request_scheme() != "https":
        return "Passkeys require a secure (HTTPS) connection."
    return None


# ---------------------------------------------------------------------------
# Rate limiting (fixed window, atomic counters)
# ---------------------------------------------------------------------------
#
# Login attempts are limited by *failed* verifications per client IP, so many people
# signing in successfully from one shared address (campus NAT, office proxy) never
# lock each other out. Fetching login options only has a loose anti-flood limit,
# because conditional UI requests options on every login page load.

OPTIONS_LIMIT_MULTIPLIER = 20


def _ratelimit_key(cache, key: str) -> str:
    return cache.make_key(f"passkey_ratelimit:{key}")


def _hit(key: str, window: int) -> int:
    """Increment a window counter and return the new value.

    SET NX EX creates the key together with its TTL, so a crash between the two
    calls can never leave a counter that never expires.
    """
    cache = _cache()
    rkey = _ratelimit_key(cache, key)
    cache.set(rkey, 0, ex=window, nx=True)
    return int(cache.incr(rkey))


def _count(key: str) -> int:
    cache = _cache()
    return int(cache.get(_ratelimit_key(cache, key)) or 0)


def check_rate_limit(key: str, limit: int, window: int = 60) -> bool:
    """Count one attempt; True while the window has not exceeded `limit`."""
    try:
        return _hit(key, window) <= limit
    except Exception:
        frappe.log_error(title="Passkey Rate Limit Error", message=frappe.get_traceback())
        return True


def _auth_limit() -> int:
    return frappe.get_single("Passkey Settings").authentication_rate_limit or 10


def check_authentication_options_rate_limit(ip_address: str) -> bool:
    return check_rate_limit(f"authopt:{ip_address}", _auth_limit() * OPTIONS_LIMIT_MULTIPLIER, 60)


def is_authentication_blocked(ip_address: str) -> bool:
    """True when this IP already has too many failed verifications in the window."""
    try:
        return _count(f"authfail:{ip_address}") >= _auth_limit()
    except Exception:
        frappe.log_error(title="Passkey Rate Limit Error", message=frappe.get_traceback())
        return False


def record_authentication_failure(ip_address: str) -> None:
    try:
        _hit(f"authfail:{ip_address}", 60)
    except Exception:
        frappe.log_error(title="Passkey Rate Limit Error", message=frappe.get_traceback())


def check_registration_rate_limit(user_email: str) -> bool:
    settings = frappe.get_single("Passkey Settings")
    return check_rate_limit(f"reg:{user_email}", settings.registration_rate_limit or 5, 60)
