"""The "My Passkeys" page was called passkey-settings, the same route as the Passkey Settings
doctype (/app/passkey-settings), so Desk opened the settings form instead. It is now
my-passkeys; remove the old Page record."""
import frappe


def execute():
    if frappe.db.exists("Page", "passkey-settings"):
        frappe.delete_doc("Page", "passkey-settings", ignore_permissions=True, force=True)
