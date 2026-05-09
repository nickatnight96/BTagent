# Security Policy

## Supported Versions

The following versions of BTagent receive security updates:

| Version | Supported          |
|---------|--------------------|
| 0.3.x   | Yes                |
| 0.2.x   | Yes                |
| 0.1.x   | Security fixes only|
| < 0.1   | No                 |

We recommend running the latest patch release within a supported minor version. Older minor versions receive security patches for 6 months after the next minor version is released.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in BTagent, please report it privately:

1. **Email:** Send a detailed report to **security@btagent.dev**
2. **Subject line:** `[SECURITY] Brief description of the vulnerability`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce (proof of concept if possible)
   - Affected version(s)
   - Potential impact assessment
   - Any suggested fix (optional)

**PGP encryption is available upon request.** Contact security@btagent.dev for our public key.

## Response Timeline

We take all security reports seriously and follow this timeline:

| Stage | Target | Description |
|-------|--------|-------------|
| Acknowledgment | **48 hours** | We confirm receipt of your report and assign a tracking ID |
| Triage | **1 week** | We assess severity, confirm the vulnerability, and determine scope |
| Fix | **30 days** | We develop, test, and release a patch for confirmed vulnerabilities |
| Disclosure | **90 days** | Coordinated public disclosure after the fix is released |

For critical vulnerabilities (CVSS 9.0+), we aim to release a patch within **7 days** of triage confirmation. If we need more time, we will communicate the revised timeline within the triage window.

## Security Update Process

1. **Patch development:** Security fixes are developed in a private branch to prevent exploitation before the fix is available.
2. **Testing:** All security patches go through the full test suite (unit, UAT, security-specific tests) before release.
3. **Release:** Security patches are released as new patch versions (e.g., 0.3.1 -> 0.3.2) with a security advisory.
4. **Advisory:** We publish a GitHub Security Advisory with CVE assignment (when applicable), affected versions, and upgrade instructions.
5. **Notification:** Users watching the repository receive automatic notifications for security advisories.

### Applying Security Updates

```bash
# Check your current version
make --version  # or check your docker-compose image tags

# Pull the latest patch
git pull origin main
make build
make up
```

## Responsible Disclosure Recognition

We value the work of security researchers who help keep BTagent and its users safe. Contributors who responsibly disclose vulnerabilities will be:

- Credited in the security advisory (unless they prefer anonymity)
- Listed in our Security Hall of Fame (coming soon)
- Eligible for our recognition program (details TBD)

We ask that you:

- Give us reasonable time to address the issue before public disclosure
- Make a good-faith effort to avoid impacting other users during your research
- Do not access or modify data belonging to other users
- Do not perform denial-of-service attacks

## Scope

The following are **in scope** for security reports:

- BTagent backend API (`backend/`)
- Agent engine (`agents/`)
- Frontend application (`frontend/`)
- Shared library (`shared/`)
- Infrastructure configurations (`infra/`)
- Authentication and authorization (JWT, RBAC)
- Data handling (TLP enforcement, audit trail integrity)
- Prompt injection vectors
- MCP connector security

The following are **out of scope**:

- Third-party dependencies (report these to the upstream project)
- Issues in development-only configurations (e.g., default Docker Compose passwords)
- Social engineering attacks
- Physical attacks

## Security Audit Reports

We conduct regular security audits of the BTagent codebase. Published audit reports are available in the `docs/` directory:

- [Security Audit Report (Phase 1)](docs/SECURITY_AUDIT.md) -- Full codebase review covering backend, agents, shared, and infrastructure
- [Security Audit Report (Phase 2)](docs/SECURITY_AUDIT_PHASE2.md) -- Phase 2 features including IOC enrichment, knowledge base, playbooks, and MITRE integration

## Security Architecture Overview

BTagent implements multiple layers of security controls:

- **Authentication:** JWT token pairs (access + refresh) with bcrypt password hashing
- **Authorization:** Role-based access control (RBAC) with four hierarchical roles
- **TLP enforcement:** Classification-aware LLM routing prevents data leakage to unauthorized providers
- **Prompt injection defense:** All external data wrapped in `<external-data>` XML tags
- **Scope enforcement:** Agent actions restricted to authorized investigation perimeter
- **Audit trail:** SHA-256 hash-chained audit log with 7-year retention
- **Evidence integrity:** SHA-256 hashing of all tool outputs for forensic chain of custody

For detailed architecture information, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
