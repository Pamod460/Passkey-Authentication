frappe.ui.form.on("Passkey Settings", {
    refresh: function (frm) {
        frm.add_custom_button(__("Run Setup Check"), function () { runSetupCheck(); });
        frm.add_custom_button(__("Enrollment Report"), function () {
            frappe.set_route("query-report", "Passkey Enrollment");
        }, __("View"));
        frm.add_custom_button(__("Passkeys"), function () {
            frappe.set_route("List", "Passkey Credential");
        }, __("View"));
        frm.add_custom_button(__("Authentication Log"), function () {
            frappe.set_route("List", "Passkey Authentication Log");
        }, __("View"));

        const host = window.location.hostname;
        if (!frm.doc.rp_id && host) {
            frm.set_intro(__("RP ID is empty. Click 'Use This Domain' to set it to {0}.", [frappe.utils.escape_html(host)]), "orange");
            frm.add_custom_button(__("Use This Domain"), function () {
                frm.set_value("rp_id", host);
            });
        }
    },
});

function runSetupCheck() {
    frappe.call({
        method: "passkey_authentication.passkey_authentication.diagnostics.run_setup_check",
        freeze: true,
        freeze_message: __("Checking..."),
    }).then(function (r) {
        const res = r.message || {};
        const esc = frappe.utils.escape_html;
        const colour = { ok: "green", warning: "orange", error: "red", info: "blue" };
        const label = { ok: __("OK"), warning: __("Warning"), error: __("Error"), info: __("Info") };
        const order = { error: 0, warning: 1, info: 2, ok: 3 };
        const checks = (res.checks || []).slice().sort(function (a, b) { return order[a.status] - order[b.status]; });
        const rows = checks.map(function (c) {
            return "<tr><td style='white-space:nowrap'><span class='indicator-pill " + colour[c.status] + "'>" +
                label[c.status] + "</span></td><td><b>" + esc(c.title) + "</b>" +
                (c.detail ? "<div class='text-muted small'>" + esc(c.detail) + "</div>" : "") + "</td></tr>";
        }).join("");
        const s = res.summary || {};
        const d = new frappe.ui.Dialog({
            title: __("Passkey Setup Check"),
            size: "large",
            fields: [{ fieldtype: "HTML", options:
                "<p>" + __("{0} error(s), {1} warning(s).", [s.error || 0, s.warning || 0]) + "</p>" +
                "<table class='table table-bordered'><tbody>" + rows + "</tbody></table>" }],
        });
        d.show();
    });
}
