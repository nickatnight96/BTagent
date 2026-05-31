# SAML 2.0 SSO (#170)

SAML 2.0 single sign-on for BTagent, the SP-initiated complement to the OIDC SSO
(#168) and the MFA (#167) / admin account-linking (#169) work. It reuses the
`sso_identity` table and the JIT-provisioning gate from the OIDC flow, so a SAML
user is just another `(provider, subject)` identity (`provider="saml"`,
`subject` = the assertion NameID).

> **Optional feature.** The SAML crypto stack (`pysaml2` + the `xmlsec1` system
> binary) is an **optional `backend[saml]` extra**. The default slim image and
> the `backend-tests` CI job do **not** install it; `auth/saml.py` imports
> `pysaml2` lazily, so the core boots fine without it. A SAML route hit on an
> image that lacks the extra returns **503**. Build/deploy the SAML-enabled
> image (below) only where SAML is configured.

## Endpoints

All under `/api/v1/auth/saml/{provider}` (public — the user has no session yet):

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/{provider}/login`    | Build an `<AuthnRequest>`, stash its id + RelayState in a signed httpOnly cookie, 302 to the IdP. |
| `POST` | `/{provider}/acs`      | Assertion Consumer Service — validate the `SAMLResponse`, JIT-provision, mint a session, 302 to the frontend. |
| `GET`  | `/{provider}/metadata` | This SP's metadata XML — register it with the IdP. |

Sessions are minted through the **same** `create_token_pair` / `set_auth_cookies`
as password + OIDC login, so revocation, refresh rotation, and `org_id` scoping
all apply unchanged.

## Configuration

Providers are configured via `BTAGENT_SAML_PROVIDERS` (a JSON dict keyed by the
`{provider}` path segment), mirroring `BTAGENT_OIDC_PROVIDERS`. The default is an
empty dict, so with nothing configured the routes simply 404.

```bash
BTAGENT_SAML_PROVIDERS='{
  "okta": {
    "idp_metadata_url": "https://acme.okta.com/app/abc123/sso/saml/metadata",
    "sp_entity_id": "https://btagent.example.com",
    "acs_url": "https://btagent.example.com/api/v1/auth/saml/okta/acs",
    "role_attr": "Role",
    "role_map": {"soc-admins": "admin", "soc-seniors": "senior_analyst"},
    "default_role": "analyst",
    "email_attr": "mail"
  }
}'
```

Each provider needs the IdP either via **`idp_metadata_url`** (preferred —
fetched + cached per `metadata_ttl_seconds`) **or** the manual triple
**`idp_entity_id` + `sso_url` + `x509cert`** (the IdP signing certificate;
supports the `${secret:...}` / `${env:...}` indirection, resolved lazily). See
`SAMLProviderConfig` in `backend/btagent_backend/config.py` for the full field
list (`name_id_format`, `assertion_skew_seconds`, etc.).

### Registering with the IdP

1. Deploy the SAML-enabled image with the provider configured.
2. Fetch this SP's metadata: `GET /api/v1/auth/saml/{provider}/metadata`.
3. Register that metadata (or its entityID + ACS URL) with the IdP, and add the
   `Role`/email attribute statements your `role_map` / `email_attr` expect.

## Security model

`auth/saml.py::parse_response` (via `pysaml2`) validates, and the route rejects
with **400** on any failure (raw XML/crypto errors are never leaked):

- **Assertion signature** against the IdP cert — `want_assertions_signed`; an
  unsigned assertion is rejected.
- **`Conditions`** `NotBefore` / `NotOnOrAfter` (with `assertion_skew_seconds`).
- **`AudienceRestriction`** == our `sp_entity_id`.
- **`InResponseTo`** — must answer an `<AuthnRequest>` id we issued (stashed in
  the signed-state cookie); `allow_unsolicited=False` forbids IdP-initiated
  responses. This is the replay defense.
- **RelayState** echoed by the IdP must match the stashed value (CSRF on the ACS
  POST), and the ACS must be reached at exactly the configured `acs_url` path.

**Email trust:** SAML has no `email_verified` claim, so a validly *signed*
assertion carrying an email is treated as verified (the signature is the IdP's
non-repudiation guarantee). The no-silent-link-to-password-account gate in
`_jit_provision` still applies — a verified email that matches an existing
**local-password** account is refused with **409**; an admin must link it
explicitly (#169). SSO-only accounts auto-link; new emails are JIT-created.

## Building the SAML-enabled image

```bash
docker build -f infra/docker/Dockerfile.backend.saml -t btagent-backend:saml .
```

It is identical to `Dockerfile.backend` except it `apt-get install`s
`xmlsec1` + `libxmlsec1`/`libxml2` and `pip install`s `backend[saml]`. The
default slim image is unchanged.

## Out of scope (Phase 2)

Encrypted assertions, IdP-initiated SSO (weakens the `InResponseTo` replay
defense), and HTTP-Redirect ACS are deliberately not implemented; SP-initiated +
HTTP-POST ACS + signed assertions is the supported flow. A real-IdP (Keycloak)
end-to-end test is a recommended fast-follow.

## Testing

- `backend/tests/test_saml.py` — protocol layer.
- `backend/tests/test_saml_routes.py` — the routes.

Both split into **layer A** (config / routing / role-mapping / the 503 seam —
runs in the default `backend-tests` job with no xmlsec) and **layer B** (signed
assertions via a real `pysaml2` IdP — gated on the extra; runs in the dedicated
`saml-tests` CI job and on any dev box with `pip install 'btagent-backend[saml]'`
+ the `xmlsec1` binary).
