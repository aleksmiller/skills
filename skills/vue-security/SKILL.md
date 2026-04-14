---
name: vue-security
description: "Vue.js security analysis, auditing, and hardening using the OWASP Top 10. Trigger for XSS, v-html, CSTI, Vue Router access control, JWT/session storage, CSP, CORS, source maps, npm audit, supply-chain, Vite plugins, or any Vue.js security audit."
---

# Vue.js Security — OWASP Top 10 Applied

This skill provides Vue-specific exploit scenarios, PortSwigger cheat sheet vectors, and production-ready defense patterns for every OWASP Top 10 category. Use it for security audits, code reviews, training materials, and hardening Vue.js applications.

## How to Use This Skill

1. **Identify the threat category** from the user's request
2. **Read the relevant reference file** from `references/` before responding
3. **Apply the patterns** — each reference contains Exploit → Prevention → Use Case for every vulnerability

## Reference Files

Read the appropriate reference file based on what the user needs:

| User Asks About | Read This File |
|---|---|
| XSS, v-html, template injection, CSTI, script gadgets, mutation XSS, CSP bypass, sanitization, DOMPurify | `references/injection-xss.md` |
| Route guards, access control, IDOR, privilege escalation, JWT storage, auth flows, session management, MFA, token rotation | `references/access-auth.md` |
| API keys in bundle, .env secrets, VITE_ exposure, SRI, CDN integrity, Pinia deserialization, CI/CD supply chain, npm audit | `references/data-integrity.md` |
| Source maps, CORS, security headers, CSP configuration, devtools in prod, outdated npm packages, CVEs, dependency hygiene, supply-chain attacks, Vite plugin compromise, malicious Vue plugins, global mixin hijacking, PostCSS/Tailwind build-time risks, lockfile integrity, typosquatting | `references/config-components.md` |
| Client-side business logic, price manipulation, rate limiting, error logging, Sentry, monitoring, SSRF, URL validation | `references/design-logging-ssrf.md` |

**If the request spans multiple categories**, read all relevant files. For a full security audit, read all five.

## Quick Decision Guide

### When Reviewing Code
1. Read the reference file matching the code's concern
2. Check for the **Vulnerable Pattern** — does the code match it?
3. Suggest the **Secure Pattern** as the fix
4. Explain using the **Use Case** scenario for context

### When Creating Training Material
1. Read all five reference files
2. Use the Exploit → Prevention → Use Case structure for each topic
3. Include PortSwigger vectors from `injection-xss.md` for realistic examples
4. Include Vue-specific supply-chain scenarios from `config-components.md` (section 5) for build-time and plugin risks
5. Organize by severity: Critical (A01, A02, A03, A07) → High (A04, A05, A06, A08, A10, Supply Chain) → Medium (A09)

### When Auditing an Application
Walk through this checklist, reading the corresponding reference for details:

1. **Injection (A03)** — Search for `v-html`, dynamic `:href`, `:is`, `v-on` with user input → `injection-xss.md`
2. **Access Control (A01)** — Check if API endpoints enforce auth independently of Vue Router guards → `access-auth.md`
3. **Auth (A07)** — Check token storage (localStorage = bad), refresh rotation, brute-force protection → `access-auth.md`
4. **Crypto (A02)** — Grep for `VITE_` env vars containing secrets, check token storage → `data-integrity.md`
5. **Misconfig (A05)** — Check `vite.config` for sourcemaps, CORS policy, security headers, devtools flag → `config-components.md`
6. **Components (A06)** — Run `npm audit`, check for EOL Vue 2, wildcard versions → `config-components.md`
7. **Design (A04)** — Look for client-side price/limit calculations sent to server → `design-logging-ssrf.md`
8. **Integrity (A08)** — Check CDN scripts for SRI, CI pipeline for lockfile enforcement → `data-integrity.md`
9. **Logging (A09)** — Check for global error handler, auth failure tracking, CSP reporting → `design-logging-ssrf.md`
10. **SSRF (A10)** — Find features accepting user URLs (import, preview, upload) → `design-logging-ssrf.md`
11. **Supply Chain** — Audit Vite plugins, Vue plugins using `app.mixin()`, PostCSS chain, lockfile integrity → `config-components.md`

## Output Formats

Adapt output format to what the user needs:

- **Code review comment**: Point to the vulnerable line, explain the risk, provide the fix inline
- **Audit report**: Use the Severity → Finding → Evidence → Recommendation → Reference structure
- **Training material**: Use the Exploit → Prevention → Use Case structure with code examples
- **Security checklist**: Use the 10-point checklist above with pass/fail for each item
- **Fix PR**: Provide the secure code replacement with a brief explanation of what changed and why

## Key Principles

- **Client-side guards are UX, not security.** Every API endpoint must independently verify authorization.
- **`v-html` with user input is always a vulnerability.** Use `{{ }}` interpolation or DOMPurify with strict allowlists.
- **Vue template expressions execute JavaScript.** If user input reaches a Vue template, it's code execution via `constructor.constructor()`.
- **httpOnly cookies, not localStorage.** Any XSS makes localStorage tokens instantly exfiltrable.
- **Validate on the server.** Client-side computed properties for prices, limits, or roles are trivially bypassed.
- **Source maps expose everything.** Always set `sourcemap: false` for production builds.
- **Vet Vite plugins like server middleware.** They run arbitrary Node.js at build time with full env access — a compromised plugin bypasses all runtime defenses.
- **Prefer composables over app.use() plugins.** Global mixins from `app.use()` run inside every component silently; composables are explicitly scoped.
