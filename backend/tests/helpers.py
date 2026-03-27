"""Shared test helpers for BTagent backend tests."""


def auth_header(token: str) -> dict[str, str]:
    """Build an ``Authorization: Bearer <token>`` header dict."""
    return {"Authorization": f"Bearer {token}"}
