# Secure Azure Web Application

**Status: Archived — Azure resources have been decommissioned.**

A secure, full-stack web application deployed on Microsoft Azure, built as part of the *Advanced Cyber Security* course at Fontys University of Applied Sciences. The project covers architecture design, threat modelling, implementation, and post-deployment security testing.

---

## Overview

- **Stack:** Azure App Service (Linux) + Azure SQL + Node.js + GitHub Actions CI/CD
- **Domain:** maanitwebapp.com (no longer live)
- **Security frameworks:** CIS Controls, NIST SP 800-53, OWASP Top 10

---

## Security Features

### Authentication & Access Control
- TOTP-based two-factor authentication (Google/Microsoft Authenticator)
- JWT session management via secure `httpOnly` cookies
- Role-based access control (admin/user)
- NIST SP 800-63B compliant password policy with server-side validation
- IP-based rate limiting on login and registration endpoints

### Application Security
- Azure Front Door with custom WAF rules (SQLi, XSS, SSRF, Command Injection, CSRF, Path Traversal)
- HTTPS enforced end-to-end with HSTS
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- CSRF token protection on all forms
- Parameterised SQL queries throughout

### File Upload
- SAS token-based uploads directly to Azure Blob Storage (storage keys never exposed to client)
- Server-side file extension and MIME type validation with blocklist
- Filename sanitisation to prevent path traversal
- Time-limited, write-only SAS tokens (1-hour expiry)

### Cloud & Infrastructure
- Azure SQL with Transparent Data Encryption (TDE) and Managed Identity access
- Secrets injected via Azure App Service environment variables (no hardcoding)
- Defender for Cloud with vulnerability scanning and compliance monitoring
- Azure Monitor, Log Analytics, and Application Insights with a live security dashboard

### DevSecOps
- GitHub Actions CI/CD pipeline with CodeQL static analysis on every push
- OWASP ZAP dynamic analysis (DAST) performed post-deployment
- Compliance mapping against CIS Controls and NIST SP 800-53

---

## Architecture

The final architecture differs from the original design in a few key areas:

| Component | Original Plan | Final Implementation |
|---|---|---|
| Frontend hosting | Azure Static Web Apps | Azure App Service (Linux) |
| Authentication | Azure AD B2C | Custom TOTP + bcrypt + JWT |
| Secrets management | Azure Key Vault | App Service environment variables |
| Network segmentation | NSGs | Azure Front Door + WAF (perimeter) |
| Encryption at rest | Azure Disk Encryption | SQL Transparent Data Encryption |

Full justification for each change is documented in the Body of Knowledge (`/Documentation`).

---

## Security Testing

The application was subject to two rounds of independent testing:

**OWASP ZAP (DAST)** — Post-deployment dynamic scan. Zero high-severity findings. Four medium-severity findings identified and reviewed (CSP configuration, cookie flags, cache headers).

**Hacking Week (Red Team)** — The application was targeted by red teamers during a dedicated adversarial testing week. Findings and remediation status:

| Finding | Status |
|---|---|
| JWT stored in localStorage; role validation done client-side | Fixed — tokens moved to `httpOnly` cookies with `Secure` and `SameSite` flags |
| 2FA endpoint lacked rate limiting; user IDs enumerable via API | Partially addressed — rate limiting added; enumeration not fully resolved |
| File upload bypass via `.php.jpg` extension and modified `Content-Type` headers | Partially addressed — server-side extension and MIME blocklist added; magic byte inspection not implemented |
| WAF operating in detection mode rather than prevention mode | Fixed — WAF switched to prevention mode with 20+ custom rules |
| IP-based rate limiting bypassed via VPN/Tor | Not fully addressed — requires IP intelligence services beyond project scope |
| CSP uses `unsafe-inline` for `script-src` and `style-src` | Not fully addressed — nonce-based CSP not implemented |
| Slow-rate directory enumeration not detected | Not addressed — requires behavioural anomaly detection |

The full red team report is in the `/Documentation` folder.

---

## Documentation

All technical documentation — Body of Knowledge, architecture diagrams, threat model, data flow, compliance mapping, and OWASP ZAP report — is in the `/Documentation` folder.

---

## Contact

**Maanit Trivedi**
maanit49@gmail.com