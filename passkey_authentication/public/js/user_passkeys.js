// Passkey admin buttons on the User form (System Manager only).
frappe.ui.form.on("User", {
    refresh: function (frm) {
        if (frm.is_new() || !frappe.user.has_role("System Manager")) return;
        const API = "passkey_authentication.passkey_authentication.admin.";
        frappe.call({ method: API + "user_passkey_summary", args: { user: frm.doc.name } }).then(function (r) {
            const s = r.message || {};
            if (!s.success) return;
            const group = __("Passkeys");
            frm.add_custom_button(__("View Passkeys ({0})", [s.active]), function () {
                frappe.set_route("List", "Passkey Credential", { user: frm.doc.name });
            }, group);
            if (s.active) {
                frm.add_custom_button(__("Revoke All Passkeys"), function () {
                    frappe.prompt(
                        { fieldname: "reason", label: __("Reason (logged)"), fieldtype: "Data" },
                        function (values) {
                            frappe.call({ method: API + "revoke_user_passkeys",
                                args: { user: frm.doc.name, reason: values.reason || "" }, freeze: true })
                                .then(function (res) {
                                    frappe.show_alert({ message: res.message.message, indicator: "green" });
                                    frm.reload_doc();
                                });
                        },
                        __("Revoke all passkeys of {0}?", [frm.doc.name]), __("Revoke")
                    );
                }, group);
            }
            if (s.recovery_codes) {
                frm.add_custom_button(__("Delete Recovery Codes ({0})", [s.recovery_codes]), function () {
                    frappe.confirm(__("Delete this user's unused recovery codes?"), function () {
                        frappe.call({ method: API + "reset_recovery_codes", args: { user: frm.doc.name } })
                            .then(function (res) {
                                frappe.show_alert({ message: res.message.message, indicator: "green" });
                                frm.reload_doc();
                            });
                    });
                }, group);
            }
            const e = s.enrollment || {};
            if (e.required && !e.has_passkey) {
                frm.dashboard.set_headline_alert(
                    e.overdue ? __("This user's role requires a passkey and the grace period has ended.")
                              : __("This user's role requires a passkey; they have not added one yet."),
                    e.overdue ? "red" : "orange");
            }
        });
    },
});
