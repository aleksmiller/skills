# A05 + A06 — Security Misconfiguration & Vulnerable Components

## Overview

Default Vite/Webpack configs ship source maps, many Vue apps run with permissive CORS and no security headers, and the npm ecosystem has a constant stream of CVEs. These are low-hanging fruit that attackers scan for automatically.

Severity: **High**

---

## 1. Source Maps in Production (A05)

### Vulnerable Pattern
```js
// vite.config.js
defineConfig({
  build: { sourcemap: true }
})
// Attacker loads: https://yoursite.com/assets/app-abc123.js.map
// → Reconstructs every .vue file, route, API endpoint, feature flag
```

### Secure Pattern
```js
defineConfig({
  build: {
    sourcemap: false, // no .map files in production

    // Alternative: 'hidden' — generates .map for error tracking
    // (Sentry) but doesn't reference them in the JS files
    // sourcemap: 'hidden',

    rollupOptions: {
      output: {
        manualChunks: undefined, // avoid predictable chunk names
      }
    }
  }
})
```

### Use Case
A learning platform deploys with default Vite settings. An attacker loads the `.map` file and reconstructs the entire Vue source — discovering hidden admin routes, API endpoint structures, and hardcoded feature flags used for A/B testing premium features.

---

## 2. CORS Misconfiguration (A05)

### Vulnerable Pattern
```js
// ❌ Any origin can make cross-origin requests
app.use(cors({ origin: '*' }))

// ❌ Reflecting Origin header (even worse with credentials)
app.use(cors({
  origin: req.headers.origin,
  credentials: true
}))
```

### Secure Pattern
```js
const ALLOWED = ['https://app.mylearning.com', 'https://admin.mylearning.com']

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED.includes(origin)) cb(null, true)
    else cb(new Error('CORS blocked'))
  },
  credentials: true,
  maxAge: 86400
}))
```

---

## 3. Missing Security Headers (A05)

### Vulnerable Pattern
```
// ❌ No Content-Security-Policy
// ❌ No X-Frame-Options (clickjacking)
// ❌ No Strict-Transport-Security (SSL stripping)
// ❌ No X-Content-Type-Options (MIME sniffing)
// ❌ Vue devtools enabled in production
app.config.devtools = true
```

### Secure Pattern
```js
import helmet from 'helmet'

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", "https://api.mylearning.com"],
    }
  },
  hsts: { maxAge: 63072000, includeSubDomains: true },
  frameguard: { action: 'deny' },
}))

// ✅ Disable devtools in production (main.js)
app.config.devtools = import.meta.env.DEV
app.config.performance = import.meta.env.DEV
```

---

## 4. Outdated & Vulnerable npm Packages (A06)

### Vulnerable Pattern
```json
{
  "dependencies": {
    "vue": "2.6.11",         // EOL since Dec 2023, unpatched XSS
    "axios": "0.19.0",       // SSRF CVE-2020-28168
    "lodash": "4.17.15",     // prototype pollution CVE-2021-23337
    "vue-markdown": "*",     // wildcard = uncontrolled
    "marked": "0.3.9",       // ReDoS + XSS via malformed markdown
  }
}
```

### Secure Pattern
```bash
# Regular auditing
npm audit --production
npx npm-check-updates -u

# CI gate — block deploy on high+ CVEs
npm audit --audit-level=high || exit 1

# Verify package provenance
npm audit signatures
```
```json
// Pin exact versions
"vue": "3.4.21",

// Override transitive vulnerabilities
"overrides": { "nth-check": ">=2.0.1" }
```

### Dependabot Configuration
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

### Use Case
The platform uses a markdown rendering library with a known XSS CVE. A student crafts a specially formatted lesson note that triggers XSS through the outdated library. Since the library renders within a trusted component, it bypasses any input sanitization applied at the application level.

### Checklist
1. Upgrade Vue 2 → Vue 3 immediately (Vue 2 is EOL)
2. Run `npm audit` weekly in CI
3. Set up Dependabot or Snyk
4. Use `npm overrides` for transitive fixes
5. Review changelogs before upgrading — especially for security changes
6. Pin exact versions, no `^` or `~`
