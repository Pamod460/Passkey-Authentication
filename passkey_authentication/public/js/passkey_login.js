/**
 * "Sign in with Passkey" for the website login page (web_include_js).
 * Supports a button (modal prompt) and, when enabled, conditional UI/autofill.
 */
(function () {
    "use strict";

    if (typeof PasskeyAuth === "undefined" || !PasskeyAuth.utils) return;
    const utils = PasskeyAuth.utils;
    const ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-7 8-7s8 3 8 7"/></svg>';
    let conditionalAbort = null;
    let conditionalTimer = null;
    let conditionalEnabled = false;
    let redirecting = false;
    let generation = 0; // bumps on every attempt so a superseded one can tell it is stale
    // Restart a pending autofill request this long before its server challenge expires.
    const REFRESH_MARGIN_MS = 10000;

    if (!utils.isWebAuthnSupported()) return;

    function onLoginPage() {
        return !!document.querySelector(".for-login");
    }

    function init() {
        if (!onLoginPage()) return;
        utils.apiCallAsync("get_status", {}).then(function (status) {
            if (!status.enabled) return;
            addPasskeyButton(status);
            if (status.conditional_ui) {
                conditionalEnabled = true;
                startConditionalUI();
            }
        }).catch(function () { /* passkeys are optional on this page */ });
    }

    function addPasskeyButton() {
        if (document.getElementById("passkey-login-btn")) return;
        // Frappe 16: the submit button sits in .page-card-actions; older versions use a <form>.
        const form = document.querySelector(".for-login .page-card-actions")
            || document.querySelector(".for-login form")
            || document.querySelector(".for-login");
        if (!form) return;

        const container = document.createElement("div");
        container.id = "passkey-login-container";
        container.innerHTML =
            '<div class="text-center text-muted small" style="margin:12px 0">' + __("or") + "</div>";

        const btn = document.createElement("button");
        btn.id = "passkey-login-btn";
        btn.type = "button";
        btn.innerHTML = ICON + "<span>" + __("Sign in with Passkey") + "</span>";
        btn.addEventListener("click", function () { loginWithPasskey(false); });
        container.appendChild(btn);

        const submit = form.querySelector('button[type="submit"], .btn-login');
        if (submit && submit.parentNode) {
            submit.parentNode.insertBefore(container, submit.nextSibling);
        } else {
            form.appendChild(container);
        }
    }

    function startConditionalUI() {
        if (!window.PublicKeyCredential.isConditionalMediationAvailable) return;
        window.PublicKeyCredential.isConditionalMediationAvailable().then(function (ok) {
            if (!ok) return;
            const field = document.querySelector("#login_email, input[type=email], input[name=usr]");
            if (field) field.setAttribute("autocomplete", "username webauthn");
            loginWithPasskey(true);
        });
    }

    function setBusy(busy) {
        const btn = document.getElementById("passkey-login-btn");
        if (!btn) return;
        btn.disabled = busy;
        btn.innerHTML = busy
            ? '<span class="spinner-border spinner-border-sm"></span> ' + __("Authenticating...")
            : ICON + "<span>" + __("Sign in with Passkey") + "</span>";
    }

    function stopConditional() {
        if (conditionalTimer) {
            clearTimeout(conditionalTimer);
            conditionalTimer = null;
        }
        if (conditionalAbort) {
            conditionalAbort.abort();
            conditionalAbort = null;
        }
    }

    // Only same-origin redirects; `new URL` normalises tricks like "/\evil.com" or "/\t/evil.com".
    function safeRedirectTarget(target) {
        try {
            const url = new URL(target || "/app", window.location.origin);
            if (url.origin === window.location.origin) return url.pathname + url.search + url.hash;
        } catch (e) { /* fall through */ }
        return "/app";
    }

    async function loginWithPasskey(conditional) {
        // Any pending conditional request must be cancelled before a new one starts.
        stopConditional();
        const myGeneration = ++generation;
        if (!conditional) setBusy(true);

        try {
            const result = await utils.apiCallAsync("authentication_options", {});
            if (!result.success) throw new Error(result.message);
            if (myGeneration !== generation) return; // a newer attempt started meanwhile

            const request = { publicKey: utils.toRequestOptions(result.options) };
            if (conditional) {
                conditionalAbort = new AbortController();
                request.mediation = "conditional";
                request.signal = conditionalAbort.signal;
                // The browser keeps an autofill request open indefinitely, but the server
                // challenge expires; fetch a fresh one shortly before that happens.
                const ttl = result.options.timeout || 120000;
                conditionalTimer = setTimeout(function () {
                    conditionalTimer = null;
                    loginWithPasskey(true);
                }, Math.max(15000, ttl - REFRESH_MARGIN_MS));
            }

            const assertion = await navigator.credentials.get(request);
            if (conditionalTimer) {
                clearTimeout(conditionalTimer);
                conditionalTimer = null;
            }
            conditionalAbort = null;
            const verify = await utils.apiCallAsync("verify_authentication", {
                credential: utils.serializeAssertion(assertion),
                session_token: result.session_token,
            });
            if (!verify.success) {
                // Expired despite the refresh (e.g. the tab was asleep): just re-arm autofill.
                if (conditional && verify.expired) return startConditionalUI();
                throw new Error(verify.message);
            }

            redirecting = true;
            utils.showSuccess(__("Login successful! Redirecting..."));
            const params = new URLSearchParams(window.location.search);
            window.location.href = safeRedirectTarget(params.get("redirect-to"));
        } catch (error) {
            if (conditional && (error.name === "AbortError" || error.name === "NotAllowedError")) return;
            if (conditional) stopConditional();
            console.error("Passkey login error:", error);
            utils.showError(error.name ? utils.mapWebAuthnError(error) : (error.message || __("Passkey authentication failed.")));
        } finally {
            if (!conditional) {
                setBusy(false);
                // The button cancelled autofill; offer it again unless we are leaving the page.
                if (conditionalEnabled && !redirecting) startConditionalUI();
            }
        }
    }

    function start() {
        // The login form is rendered client-side; wait for it briefly.
        let tries = 0;
        (function wait() {
            if (onLoginPage()) return init();
            if (++tries < 20) setTimeout(wait, 250);
        })();
    }

    // frappe.ready is not available on every page in Frappe 16; fall back to DOM ready.
    if (typeof frappe !== "undefined" && typeof frappe.ready === "function") {
        frappe.ready(start);
    } else if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start);
    } else {
        start();
    }
})();
