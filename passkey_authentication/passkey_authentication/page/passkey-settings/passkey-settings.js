frappe.pages["passkey-settings"].on_page_load = function (wrapper) {
    const utils = PasskeyAuth.utils;
    const page = frappe.ui.make_app_page({
        parent: wrapper,
        title: __("Passkeys"),
        single_column: true,
    });

    page.set_primary_action(__("Add Passkey"), handleAdd, "add");
    $(page.body).html(
        '<div class="passkey-container">' +
            '<p class="text-muted">' +
                __("Sign in using your device's fingerprint, face recognition, PIN, or security key.") +
            "</p>" +
            '<div id="passkey-enrollment-banner"></div>' +
            '<div id="passkey-list-container"></div>' +
            '<div id="passkey-recovery-container" style="margin-top:24px"></div>' +
        "</div>"
    );
    const $list = $(page.body).find("#passkey-list-container");
    const $recovery = $(page.body).find("#passkey-recovery-container");
    const $banner = $(page.body).find("#passkey-enrollment-banner");
    load();
    loadRecovery();
    loadEnrollment();

    async function loadEnrollment() {
        try {
            const status = await utils.apiCallAsync("get_status", {});
            const e = status.enrollment || {};
            if (!e.required || e.has_passkey) return $banner.empty();
            const text = e.overdue
                ? __("Your role requires a passkey. Add one now to keep using this site.")
                : __("Your role requires a passkey. Please add one within {0} day(s).", [String(e.days_left)]);
            $banner.html('<div class="alert alert-warning">' + frappe.utils.escape_html(text) + "</div>");
        } catch (err) { /* optional */ }
    }

    async function loadRecovery() {
        try {
            const r = await utils.apiCallAsync("recovery_codes_status", {});
            if (!r.success || !r.enabled) return $recovery.empty();
            const text = r.remaining
                ? __("You have {0} unused recovery code(s).", [r.remaining])
                : __("You have no recovery codes. Create some so you can still sign in if you lose your passkeys.");
            $recovery.html(
                '<h5>' + __("Recovery codes") + "</h5>" +
                '<p class="text-muted">' + frappe.utils.escape_html(text) + "</p>" +
                '<button class="btn btn-default btn-sm act-recovery">' +
                    (r.remaining ? __("Create new codes") : __("Create recovery codes")) + "</button>"
            );
            $recovery.find(".act-recovery").on("click", createRecoveryCodes);
        } catch (e) {
            $recovery.empty();
        }
    }

    async function createRecoveryCodes() {
        const r = await utils.apiCallAsync("generate_recovery_codes", {});
        if (r.stepup_required) return confirmIdentity(r.has_passkeys, createRecoveryCodes, __("Identity confirmed. Create new recovery codes now?"));
        if (!r.success) return utils.showError(r.message);
        const text = r.codes.join("\n");
        const d = new frappe.ui.Dialog({
            title: __("Your recovery codes"),
            fields: [{ fieldtype: "HTML", options:
                "<p>" + __("Save these codes somewhere safe. Each one works once. They will not be shown again, and any older codes no longer work.") + "</p>" +
                '<pre style="font-size:15px;line-height:1.7">' + frappe.utils.escape_html(text) + "</pre>" }],
            primary_action_label: __("Copy"),
            primary_action: function () {
                frappe.utils.copy_to_clipboard(text);
            },
            secondary_action_label: __("Download"),
            secondary_action: function () {
                const blob = new Blob([__("Recovery codes for") + " " + frappe.session.user + " (" + window.location.host + ")\n\n" + text + "\n"], { type: "text/plain" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = "passkey-recovery-codes.txt";
                a.click();
                URL.revokeObjectURL(a.href);
            },
            onhide: loadRecovery,
        });
        d.show();
    }

    async function load() {
        $list.html('<div class="text-center" style="padding:40px"><span class="spinner-border text-primary"></span></div>');
        try {
            const result = await utils.apiCallAsync("list_credentials", {});
            if (!result.success) throw new Error(result.message);
            render(result.credentials || []);
        } catch (e) {
            $list.html('<div class="alert alert-danger">' + __("Failed to load passkeys.") + "</div>");
        }
    }

    function render(credentials) {
        if (!credentials.length) {
            $list.html('<div class="text-center text-muted" style="padding:40px">' + __("No passkeys registered yet.") + "</div>");
            return;
        }
        const esc = frappe.utils.escape_html;
        const rows = credentials.map(function (c) {
            const lastUsed = c.last_used_at ? frappe.datetime.str_to_user(c.last_used_at) : __("Never");
            const created = c.created_at ? frappe.datetime.str_to_user(c.created_at) : "";
            const synced = c.backed_up ? " · " + __("Synced") : "";
            const provider = c.authenticator_name ? '<div class="passkey-card-meta">' + esc(c.authenticator_name) + "</div>" : "";
            const badge = c.enabled
                ? '<span class="badge badge-success">' + __("Active") + "</span>"
                : '<span class="badge badge-danger">' + __("Disabled") + "</span>";
            return '<div class="passkey-card" data-name="' + esc(c.name) + '" data-nickname="' + esc(c.nickname || "") + '">' +
                '<div class="passkey-card-info">' +
                    '<div class="passkey-card-title">' + esc(c.nickname || __("Passkey")) + "</div>" + provider +
                    '<div class="passkey-card-meta">' + __("Created") + ": " + esc(created) + " · " +
                        __("Last used") + ": " + esc(lastUsed) + esc(synced) + "</div>" +
                "</div>" +
                '<div class="passkey-card-actions">' + badge +
                    '<button class="btn btn-xs btn-default act-rename" title="' + __("Rename") + '"><i class="fa fa-pencil"></i></button>' +
                    (c.enabled ? '<button class="btn btn-xs btn-warning act-revoke" title="' + __("Revoke") + '"><i class="fa fa-ban"></i></button>' : "") +
                    '<button class="btn btn-xs btn-danger act-delete" title="' + __("Delete") + '"><i class="fa fa-trash"></i></button>' +
                "</div></div>";
        });
        $list.html(rows.join(""));
        $list.find(".act-rename").on("click", function () { rename($(this).closest(".passkey-card")); });
        $list.find(".act-revoke").on("click", function () { act("revoke_credential", $(this).closest(".passkey-card"), __("Revoke this passkey? It will stop working immediately.")); });
        $list.find(".act-delete").on("click", function () { act("delete_credential", $(this).closest(".passkey-card"), __("Permanently delete this passkey?")); });
    }

    async function handleAdd() {
        if (!utils.isWebAuthnSupported()) {
            utils.showError(__("Your browser does not support passkeys."));
            return;
        }
        try {
            const opts = await utils.apiCallAsync("registration_options", {});
            if (opts.stepup_required) return confirmIdentity(opts.has_passkeys, handleAdd);
            if (!opts.success) throw new Error(opts.message);

            const credential = await navigator.credentials.create({ publicKey: utils.toCreationOptions(opts.options) });
            const verify = await utils.apiCallAsync("verify_registration", {
                credential: utils.serializeAttestation(credential),
            });
            if (verify.stepup_required) return confirmIdentity(verify.has_passkeys, handleAdd);
            if (!verify.success) throw new Error(verify.message);

            utils.showSuccess(__("Passkey registered: ") + (verify.nickname || ""));
            load();
            loadEnrollment();
        } catch (error) {
            console.error("Passkey registration error:", error);
            utils.showError(error.name ? utils.mapWebAuthnError(error) : (error.message || __("Registration failed.")));
        }
    }

    // Adding a passkey or recovery codes needs a recent login or a fresh identity check (server enforced).
    function confirmIdentity(hasPasskeys, next, question) {
        const done = function () {
            // A new click gives the browser the user gesture it needs for create().
            frappe.confirm(question || __("Identity confirmed. Create the new passkey now?"), next);
        };
        const withPassword = function () {
            frappe.prompt(
                { label: __("Your password"), fieldname: "password", fieldtype: "Password", reqd: 1 },
                async function (values) {
                    const r = await utils.apiCallAsync("confirm_password", { password: values.password });
                    r.success ? done() : utils.showError(r.message);
                },
                __("Confirm it's you"), __("Confirm")
            );
        };
        if (!hasPasskeys) return withPassword();

        const d = new frappe.ui.Dialog({
            title: __("Confirm it's you"),
            fields: [{ fieldtype: "HTML", options: "<p>" + __("Before adding a passkey, confirm your identity with an existing passkey or your password.") + "</p>" }],
            primary_action_label: __("Use a passkey"),
            primary_action: async function () {
                d.hide();
                try {
                    const opts = await utils.apiCallAsync("stepup_options", {});
                    if (!opts.success) throw new Error(opts.message);
                    const assertion = await navigator.credentials.get({ publicKey: utils.toRequestOptions(opts.options) });
                    const r = await utils.apiCallAsync("verify_stepup", {
                        credential: utils.serializeAssertion(assertion),
                        session_token: opts.session_token,
                    });
                    if (!r.success) throw new Error(r.message);
                    done();
                } catch (error) {
                    utils.showError(error.name ? utils.mapWebAuthnError(error) : (error.message || __("Confirmation failed.")));
                }
            },
            secondary_action_label: __("Use password"),
            secondary_action: function () {
                d.hide();
                withPassword();
            },
        });
        d.show();
    }

    function rename($card) {
        frappe.prompt(
            { label: __("Passkey Name"), fieldname: "nickname", fieldtype: "Data", reqd: 1, default: $card.data("nickname") },
            async function (values) {
                const r = await utils.apiCallAsync("rename_credential", { credential_name: $card.data("name"), nickname: values.nickname });
                r.success ? (utils.showSuccess(__("Renamed.")), load()) : utils.showError(r.message);
            },
            __("Rename Passkey"), __("Save")
        );
    }

    function act(method, $card, question) {
        frappe.confirm(question, async function () {
            const r = await utils.apiCallAsync(method, { credential_name: $card.data("name") });
            r.success ? (utils.showSuccess(r.message), load()) : utils.showError(r.message);
        });
    }
};
