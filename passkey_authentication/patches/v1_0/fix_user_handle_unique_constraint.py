import frappe


def execute():
    """Drop unique constraint on user_handle in Passkey Credential.

    user_handle is a user-level identifier shared across all passkeys for a
    user, so it should not be unique at the credential level.
    """
    if not frappe.db.exists("DocType", "Passkey Credential"):
        return

    indexes = frappe.db.sql(
        """
        SELECT INDEX_NAME
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'tabPasskey Credential'
          AND COLUMN_NAME = 'user_handle'
          AND NON_UNIQUE = 0
        """,
        pluck=True,
    )

    for idx_name in indexes:
        frappe.db.sql(
            "ALTER TABLE `tabPasskey Credential` DROP INDEX `{}`".format(idx_name)
        )

    frappe.db.commit()
