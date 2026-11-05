/**
 * Shared passkey helpers: base64url, WebAuthn option building, API calls.
 */
window.PasskeyAuth = window.PasskeyAuth || {};

PasskeyAuth.utils = {
    API: "passkey_authentication.passkey_authentication.api.",

    base64urlEncode: function (buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },

    base64urlDecode: function (str) {
        str = str.replace(/-/g, "+").replace(/_/g, "/");
        while (str.length % 4) {
            str += "=";
        }
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    isWebAuthnSupported: function () {
        return typeof window.PublicKeyCredential === "function" &&
            !!(navigator.credentials && navigator.credentials.get);
    },

    showError: function (message) {
        frappe.msgprint({ title: __("Error"), indicator: "red", message: message });
    },

    showSuccess: function (message) {
        frappe.show_alert({ message: message, indicator: "green" });
    },

    mapWebAuthnError: function (error) {
        const errorMap = {
            NotAllowedError: __("Authentication was cancelled or not allowed."),
            InvalidStateError: __("This passkey is already registered on this device."),
            SecurityError: __("A security error occurred. Ensure you are using HTTPS."),
            NotSupportedError: __("Passkeys are not supported in this browser."),
            ConstraintError: __("The authenticator does not meet the required constraints."),
            AbortError: __("The operation was aborted."),
            OperationError: __("An operation error occurred. Please try again."),
        };
        return errorMap[error.name] || error.message || __("An unexpected error occurred.");
    },

    // Call a whitelisted method of passkey_authentication.passkey_authentication.api. Objects are sent as JSON strings.
    apiCallAsync: function (method, args) {
        const payload = {};
        Object.keys(args || {}).forEach(function (k) {
            const v = args[k];
            payload[k] = v !== null && typeof v === "object" ? JSON.stringify(v) : v;
        });
        return new Promise(function (resolve, reject) {
            frappe.call({
                method: PasskeyAuth.utils.API + method,
                type: "POST",
                args: payload,
                callback: function (r) { resolve(r.message || {}); },
                error: function (r) { reject(r); },
            });
        });
    },

    // Server options (base64url strings) -> navigator.credentials.get() options.
    toRequestOptions: function (options) {
        const pk = {
            challenge: this.base64urlDecode(options.challenge),
            rpId: options.rpId,
            timeout: options.timeout,
            userVerification: options.userVerification,
        };
        if (options.allowCredentials && options.allowCredentials.length) {
            pk.allowCredentials = options.allowCredentials.map(function (c) {
                const entry = { id: PasskeyAuth.utils.base64urlDecode(c.id), type: c.type };
                if (c.transports) entry.transports = c.transports;
                return entry;
            });
        }
        return pk;
    },

    // Server options -> navigator.credentials.create() options.
    toCreationOptions: function (options) {
        const pk = {
            rp: options.rp,
            user: {
                id: this.base64urlDecode(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName,
            },
            challenge: this.base64urlDecode(options.challenge),
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            attestation: options.attestation || "none",
            authenticatorSelection: options.authenticatorSelection || {},
        };
        if (options.excludeCredentials && options.excludeCredentials.length) {
            pk.excludeCredentials = options.excludeCredentials.map(function (c) {
                return { id: PasskeyAuth.utils.base64urlDecode(c.id), type: c.type };
            });
        }
        return pk;
    },

    serializeAssertion: function (assertion) {
        const u = this;
        return {
            id: assertion.id,
            rawId: u.base64urlEncode(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: u.base64urlEncode(assertion.response.clientDataJSON),
                authenticatorData: u.base64urlEncode(assertion.response.authenticatorData),
                signature: u.base64urlEncode(assertion.response.signature),
                userHandle: assertion.response.userHandle ? u.base64urlEncode(assertion.response.userHandle) : null,
            },
            authenticatorAttachment: assertion.authenticatorAttachment || null,
            clientExtensionResults: assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {},
        };
    },

    serializeAttestation: function (credential) {
        const u = this;
        const response = {
            clientDataJSON: u.base64urlEncode(credential.response.clientDataJSON),
            attestationObject: u.base64urlEncode(credential.response.attestationObject),
        };
        if (credential.response.getTransports) {
            response.transports = credential.response.getTransports();
        }
        return {
            id: credential.id,
            rawId: u.base64urlEncode(credential.rawId),
            type: credential.type,
            response: response,
            authenticatorAttachment: credential.authenticatorAttachment || null,
            clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
        };
    },
};
