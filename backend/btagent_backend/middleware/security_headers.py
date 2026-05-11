"""Security-headers middleware.

Adds the defense-in-depth HTTP response headers that nginx normally injects
at the edge so the backend's defenses don't rely on the ingress being there
(dev, helm-chart-without-nginx, internal cluster ingress, etc.). When the
production nginx ingress sets the same headers, they're idempotent — the
ingress wins.

Closes the Wave 2 audit finding "CORS config without ``allow_credentials``
safeguard + missing security headers" — the ``allow_credentials`` half is
handled in ``main.py`` (wildcard rejection at startup); the header half
lives here.

The CSP policy is intentionally tight enough to mitigate XSS in the
React SPA while still allowing the dev-tool surface (Google Fonts,
inline styles emitted by tailwind/vite-dev). Tighten further when the
inline-style ban + nonce flow lands.
"""

from __future__ import annotations

from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from btagent_backend.config import get_settings

# Documented CSP — the SPA uses Google Fonts (per ``frontend/index.html``)
# and tailwind/vite's inline styles. ``connect-src 'self'`` works for both
# the same-origin XHR/fetch and the WebSocket upgrade (ws: / wss: derive
# from the page origin). ``frame-ancestors 'none'`` is the X-Frame-Options
# replacement that modern browsers honour.
_CSP_DIRECTIVES = (
    "default-src 'self'",
    "script-src 'self'",
    # 'unsafe-inline' here is the Tailwind/Vite-emitted styles; replace
    # with a nonce once the build pipeline supports it.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: https:",
    "connect-src 'self' ws: wss:",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
)
_CSP = "; ".join(_CSP_DIRECTIVES)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Set defense-in-depth HTTP response headers on every response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response: Response = await call_next(request)

        # MIME sniffing protection — prevents the browser from second-guessing
        # the declared Content-Type and rendering an attacker-uploaded file
        # (e.g. a "txt" that's actually HTML) as a different type.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")

        # Click-jacking protection. The frame-ancestors CSP directive below
        # is the modern replacement, but older browsers still honour this
        # header; setting both is safe.
        response.headers.setdefault("X-Frame-Options", "DENY")

        # Don't leak the page URL across origins; the analyst's URL bar
        # can contain investigation IDs, IOC values, etc.
        response.headers.setdefault("Referrer-Policy", "no-referrer")

        # Lock down legacy browser features we don't use. ``Permissions-Policy``
        # superseded ``Feature-Policy`` — both refused-everything values are
        # equivalent for our purposes.
        response.headers.setdefault(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()",
        )

        # Content Security Policy — set ALWAYS so dev and prod share the
        # baseline. The frontend's static-asset pipeline tests against this.
        response.headers.setdefault("Content-Security-Policy", _CSP)

        # Strict-Transport-Security only makes sense over HTTPS — only set
        # in prod. ``includeSubDomains`` is intentional (we control all
        # ``*.btagent.example``); ``preload`` is deliberately omitted until
        # the deploy team adds the apex to https://hstspreload.org/.
        settings = get_settings()
        if settings.env == "prod":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )

        return response
