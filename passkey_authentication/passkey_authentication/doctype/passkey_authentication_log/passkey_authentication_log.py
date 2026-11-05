import frappe
from frappe.model.document import Document


class PasskeyAuthenticationLog(Document):
    pass


def has_permission(doc, user=None, ptype=None):
    user = user or frappe.session.user
    return "System Manager" in frappe.get_roles(user)
