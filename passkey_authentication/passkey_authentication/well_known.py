"""Serves the app/domain association files generated from Passkey Client App records.

Registered through the ``page_renderer`` hook, so no nginx change is needed as long
as nginx forwards /.well-known/* to Frappe (bench's default config does).
"""
import json

import frappe
from werkzeug.wrappers import Response

from . import client_apps

ROUTES = {
    ".well-known/assetlinks.json": client_apps.assetlinks,
    ".well-known/apple-app-site-association": client_apps.apple_app_site_association,
    ".well-known/webauthn": client_apps.related_origins,
}


class WellKnownRenderer:
    def __init__(self, path=None, http_status_code=None):
        if path is None:
            path = frappe.local.request.path
        self.path = (path or "").strip("/ ")
        self.http_status_code = http_status_code or 200

    def can_render(self):
        return self.path in ROUTES

    def render(self):
        data = ROUTES[self.path]()
        response = Response(json.dumps(data, indent=2), status=200, mimetype="application/json")
        response.headers["Cache-Control"] = "public, max-age=3600"
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response
