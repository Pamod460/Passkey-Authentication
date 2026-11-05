import frappe
from frappe.model.document import Document


class PasskeyRecoveryCode(Document):
    pass


def has_permission(doc, user=None, ptype=None):
    # Only hashes are stored; still, only System Managers may see or delete them.
    user = user or frappe.session.user
    return "System Manager" in frappe.get_roles(user) and ptype in (None, "read", "delete", "report")
