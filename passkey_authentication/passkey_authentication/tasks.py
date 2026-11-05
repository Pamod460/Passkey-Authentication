"""Scheduled tasks."""
import frappe
from frappe.utils import add_days, now_datetime


def cleanup_old_logs():
    """Delete audit-log entries older than the configured retention (default 90 days).

    Challenges live in Redis with a TTL and expire on their own.
    """
    try:
        days = int(frappe.db.get_single_value("Passkey Settings", "log_retention_days") or 90)
        if days <= 0:
            return
        frappe.db.delete("Passkey Authentication Log",
                         {"timestamp": ["<", add_days(now_datetime(), -days)]})
    except Exception:
        frappe.log_error(title="Passkey Cleanup Error", message=frappe.get_traceback())
