frappe.listview_settings["Passkey Credential"] = {
    add_fields: ["revoked", "enabled", "user"],
    get_indicator: function (doc) {
        if (doc.revoked) return [__("Revoked"), "red", "revoked,=,1"];
        if (!doc.enabled) return [__("Disabled"), "orange", "enabled,=,0"];
        return [__("Active"), "green", "enabled,=,1|revoked,=,0"];
    },
    onload: function (listview) {
        if (!frappe.user.has_role("System Manager")) return;
        listview.page.add_actions_menu_item(__("Revoke"), function () {
            const names = listview.get_checked_items(true);
            if (!names.length) return frappe.msgprint(__("Select the passkeys to revoke."));
            frappe.prompt(
                { fieldname: "reason", label: __("Reason (logged and not shown to the user)"), fieldtype: "Data" },
                function (values) {
                    frappe.call({
                        method: "passkey_authentication.passkey_authentication.admin.revoke_credentials",
                        args: { names: names, reason: values.reason || "" },
                        freeze: true,
                    }).then(function (r) {
                        frappe.show_alert({ message: r.message.message, indicator: "green" });
                        listview.clear_checked_items();
                        listview.refresh();
                    });
                },
                __("Revoke {0} passkey(s)?", [names.length]), __("Revoke")
            );
        });
        listview.page.add_inner_button(__("Enrollment Report"), function () {
            frappe.set_route("query-report", "Passkey Enrollment");
        });
    },
};
