/**
 * After-login passkey registration prompt.
 * Shows a dialog once per session for users with no registered passkeys.
 */
(function () {
    "use strict";

    var SKIP_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days

    function waitForDesk(callback) {
        function check() {
            if (typeof frappe !== "undefined" && frappe.session && frappe.session.user) {
                callback();
            } else {
                setTimeout(check, 200);
            }
        }
        check();
    }

    waitForDesk(function () {
        setTimeout(checkAndShowPopup, 3000);
    });

    async function checkAndShowPopup() {
        var utils = PasskeyAuth.utils;
        if (!utils) {
            console.log("[Passkey Popup] Skipped: utils not loaded");
            return;
        }

        try {
            var user = frappe.session && frappe.session.user;
            if (!user || user === "Guest") {
                console.log("[Passkey Popup] Skipped: not logged in");
                return;
            }

            if (!utils.isWebAuthnSupported()) {
                console.log("[Passkey Popup] Skipped: WebAuthn not supported");
                return;
            }

            var route = (frappe.get_route_str && frappe.get_route_str()) || "";
            if (route.indexOf("my-passkeys") === 0) {
                console.log("[Passkey Popup] Skipped: on the Passkeys page");
                return;
            }

            if (window._passkey_popup_shown) {
                console.log("[Passkey Popup] Skipped: already shown this session");
                return;
            }

            console.log("[Passkey Popup] Checking status for:", user);
            var status = await utils.apiCallAsync("get_status", {});
            console.log("[Passkey Popup] Status:", status);

            if (!status.enabled) {
                console.log("[Passkey Popup] Skipped: passkey auth not enabled");
                return;
            }
            if (status.passkey_count > 0) {
                console.log("[Passkey Popup] Skipped: user already has", status.passkey_count, "passkeys");
                return;
            }

            // A role requires a passkey: always ask, and after the grace period do not allow skipping.
            var enrollment = status.enrollment || {};
            if (enrollment.required && !enrollment.has_passkey) {
                window._passkey_popup_shown = true;
                showRegistrationDialog(enrollment);
                return;
            }

            var skipKey = "passkey_popup_skip_" + user;
            var skipTime = parseInt(localStorage.getItem(skipKey) || "0", 10);
            if (skipTime && Date.now() - skipTime < SKIP_DURATION) {
                console.log("[Passkey Popup] Skipped: suppressed for 7 days");
                return;
            }
            if (!status.password_allowed) {
                console.log("[Passkey Popup] Skipped: password fallback disabled");
                return;
            }

            window._passkey_popup_shown = true;
            showRegistrationDialog(null);
        } catch (e) {
            console.error("[Passkey Popup] Error:", e);
        }
    }

    function showRegistrationDialog(enrollment) {
        var required = !!(enrollment && enrollment.required);
        var mandatory = required && enrollment.overdue;
        var opts = {
            title: mandatory ? __("Passkey Required") : __("Set Up Passkey"),
            indicator: required ? "orange" : "blue",
            size: "small",
            static: true,
            onhide: function () {
                if (d._registered) return;
                if (mandatory) {
                    // Not optional any more: show it again.
                    setTimeout(function () { d.show(); }, 300);
                    return;
                }
                if (!required) {
                    var skipKey = "passkey_popup_skip_" + frappe.session.user;
                    localStorage.setItem(skipKey, String(Date.now()));
                    console.log("[Passkey Popup] Dismissed, skip saved");
                }
            },
            primary_action_label: __("Register Passkey"),
            primary_action: function () {
                handlePopupRegister(d);
            },
        };
        if (!mandatory) {
            opts.secondary_action_label = __("Skip for Now");
            opts.secondary_action = function () { d.hide(); };
        }
        var d = new frappe.ui.Dialog(opts);

        var esc = frappe.utils.escape_html;
        var note;
        if (mandatory) {
            note = __("Your role requires signing in with a passkey. Add one now to keep using this site.");
        } else if (required) {
            note = __("Your role requires a passkey. Please add one within {0} day(s).", [esc(String(enrollment.days_left))]);
        } else {
            note = __("You can always set this up later from Settings > Passkeys.");
        }

        d.$body.html(
            '<div style="padding: 8px 0;">' +
                '<div style="text-align: center; margin-bottom: 16px;">' +
                    '<i class="fa fa-key" style="font-size: 48px; color: #5e64ff;"></i>' +
                "</div>" +
                '<p style="text-align: center; margin-bottom: 12px;">' +
                    __("Register a passkey to sign in with your fingerprint, face, or PIN — no password needed.") +
                "</p>" +
                '<p style="text-align: center; color: #8d99a6; font-size: 12px;">' + note + "</p>" +
            "</div>"
        );
        if (mandatory) d.$wrapper.find(".modal-header .btn-modal-close").hide();

        d.show();
        console.log("[Passkey Popup] Dialog shown");
    }

    async function handlePopupRegister(dialog) {
        var utils = PasskeyAuth.utils;
        if (!utils.isWebAuthnSupported()) {
            utils.showError(__("Your browser does not support passkeys."));
            return;
        }

        try {
            dialog.get_primary_btn().prop("disabled", true).text(__("Registering..."));
            frappe.show_alert({ message: __("Requesting passkey..."), indicator: "blue" });

            var optionsResult = await utils.apiCallAsync("registration_options", {});
            if (optionsResult.stepup_required) {
                // The session is not fresh: the Passkeys page asks the user to confirm it's them.
                dialog._registered = true;
                dialog.hide();
                frappe.set_route("my-passkeys");
                return;
            }
            if (!optionsResult.success) throw new Error(optionsResult.message);

            var options = optionsResult.options;
            var createOptions = {
                publicKey: {
                    rp: options.rp,
                    user: {
                        id: utils.base64urlDecode(options.user.id),
                        name: options.user.name,
                        displayName: options.user.displayName,
                    },
                    challenge: utils.base64urlDecode(options.challenge),
                    pubKeyCredParams: options.pubKeyCredParams,
                    timeout: options.timeout,
                    attestation: options.attestation || "none",
                    authenticatorSelection: options.authenticatorSelection || {},
                },
            };

            if (options.excludeCredentials && options.excludeCredentials.length > 0) {
                createOptions.publicKey.excludeCredentials = options.excludeCredentials.map(function (c) {
                    return { id: utils.base64urlDecode(c.id), type: c.type };
                });
            }

            var credential = await navigator.credentials.create(createOptions);
            var credentialData = {
                id: credential.id,
                rawId: utils.base64urlEncode(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: utils.base64urlEncode(credential.response.clientDataJSON),
                    attestationObject: utils.base64urlEncode(credential.response.attestationObject),
                },
                authenticatorAttachment: credential.authenticatorAttachment,
                clientExtensionResults: credential.getClientExtensionResults(),
            };

            var verifyResult = await utils.apiCallAsync("verify_registration", { credential: credentialData });
            if (verifyResult.success) {
                dialog._registered = true;
                dialog.hide();
                utils.showSuccess(__("Passkey registered: ") + (verifyResult.nickname || ""));
            } else {
                throw new Error(verifyResult.message);
            }
        } catch (error) {
            console.error("[Passkey Popup] Registration error:", error);
            var message = error.name ? utils.mapWebAuthnError(error) : error.message || __("Registration failed.");
            utils.showError(message);
        } finally {
            dialog.get_primary_btn().prop("disabled", false).text(__("Register Passkey"));
        }
    }
})();
