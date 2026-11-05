import frappe
from frappe.model.document import Document


class PasskeyCredential(Document):
    def validate(self):
        if self.credential_id and frappe.db.exists(
            "Passkey Credential",
            {"credential_id": self.credential_id, "name": ["!=", self.name]},
        ):
            frappe.throw("A passkey with this Credential ID already exists.")


def has_permission(doc, user=None, ptype=None):
    user = user or frappe.session.user
    if "System Manager" in frappe.get_roles(user):
        return True
    # Owners may only read their own entries via the standard API; changes go through passkey/api.py.
    return doc.user == user and ptype in (None, "read")
