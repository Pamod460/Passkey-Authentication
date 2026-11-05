"""Audit logging for passkey operations."""
import frappe

from .security import get_client_ip, get_origin, get_user_agent


def log_event(user_email, credential_name, operation, success, failure_reason=None,
              sign_count_before=None, sign_count_after=None):
    try:
        settings = frappe.get_single("Passkey Settings")
        if not settings.audit_logging_enabled:
            return
        data = {
            "doctype": "Passkey Authentication Log",
            "user": user_email or "Guest",
            "credential": credential_name,
            "operation": operation,
            "success": 1 if success else 0,
            "failure_reason": (failure_reason or "")[:500] or None,
            "ip_address": get_client_ip(),
            "user_agent": get_user_agent(),
            "origin": get_origin(),
        }
        if sign_count_before is not None:
            data["sign_count_before"] = sign_count_before
        if sign_count_after is not None:
            data["sign_count_after"] = sign_count_after
        frappe.get_doc(data).insert(ignore_permissions=True)
    except Exception:
        frappe.log_error(title="Passkey Log Error", message=frappe.get_traceback())
