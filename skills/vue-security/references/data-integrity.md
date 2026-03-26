# A02 + A08 — Cryptographic Failures & Software Integrity

## Overview

Vue/Vite applications have unique exposure points: `VITE_` prefixed env vars are compiled into the production bundle, tokens stored in localStorage are XSS-accessible, CDN scripts without SRI hashes are supply-chain risks, and unvalidated state restoration from localStorage lets attackers control Pinia stores.

Severity: **Critical** (A02) / **High** (A08)

---

## 1. Secrets in the Frontend Bundle (A02)

### Vulnerable Pattern
```env
# ❌ .env — these are compiled INTO the JS bundle
VITE_STRIPE_SECRET_KEY=sk_live_abc123...
VITE_DB_PASSWORD=supersecret
VITE_ADMIN_API_KEY=ak_prod_xyz789...
```
```js
// ❌ Used directly in component
const stripe = Stripe(import.meta.env.VITE_STRIPE_SECRET_KEY)
```

### Exploit
```bash
# After build, secrets are plaintext in the bundle
npm run build
grep -r "VITE_" dist/assets/*.js
# Or: browser Sources tab → search for "sk_live" / "api_key"
```

### Secure Pattern
```env
# ✅ Only public values get VITE_ prefix
VITE_PUBLIC_API_URL=https://api.myapp.com
VITE_PUBLIC_STRIPE_PUBLISHABLE=pk_live_...

# ✅ Secrets stay server-side (NO VITE_ prefix — Vite ignores them)
STRIPE_SECRET_KEY=sk_live_abc123...
DATABASE_URL=postgres://...
```
```js
// ✅ Proxy sensitive calls through your backend
// Vue calls: POST /api/checkout
// Server calls Stripe with the secret key
await axios.post('/api/checkout', { items })
```

### Use Case
A developer stores `VITE_ADMIN_SECRET` in the .env file. Vite inlines it into the production JS. Any student extracts the key from the browser Sources tab and gains admin-level API access.

---

## 2. Insecure Token Storage (A02)

### Vulnerable Pattern
```js
// ❌ Any XSS reads these instantly
localStorage.setItem('access_token', jwt)
sessionStorage.setItem('refresh_token', refreshJwt)

// ❌ "Encrypted" storage is theater — key is in the JS
localStorage.setItem('token', CryptoJS.AES.encrypt(jwt, 'key123'))
```

### Secure Pattern
```js
// ✅ Server sets httpOnly cookie — JS can never access the token
// Express:
res.cookie('session', jwt, {
  httpOnly: true,
  secure: true,
  sameSite: 'Strict',
  maxAge: 900000, // 15 minutes
  path: '/api',
})

// ✅ Vue — enable credentials
const api = axios.create({ withCredentials: true })
```

---

## 3. CDN Scripts Without SRI (A08)

### Vulnerable Pattern
```html
<!-- ❌ If CDN is compromised, all users execute attacker code -->
<script src="https://cdn.example.com/chart.min.js"></script>
<script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
```

### Secure Pattern
```html
<!-- ✅ Browser rejects script if hash doesn't match -->
<script
  src="https://cdn.example.com/chart.min.js"
  integrity="sha384-abc123def456..."
  crossorigin="anonymous"
></script>
```

Generate SRI hashes:
```bash
shasum -b -a 384 chart.min.js | xxd -r -p | base64
# Or use: https://www.srihash.org
```

### Use Case
A learning platform loads a chart library from a public CDN without SRI. The CDN gets compromised — the script is replaced with one that also exfiltrates form data. Every student submitting quiz answers unknowingly sends inputs to the attacker.

---

## 4. Unsafe Deserialization into Pinia (A08)

### Vulnerable Pattern
```js
// ❌ Whatever is in localStorage goes directly into state
const saved = localStorage.getItem('appState')
if (saved) store.$patch(JSON.parse(saved))

// Attacker sets via XSS or DevTools:
// {"user":{"role":"admin","id":1},"features":{"billing":true}}
```

### Secure Pattern
```js
import { z } from 'zod'

const AppStateSchema = z.object({
  theme: z.enum(['light', 'dark']),
  lang: z.string().max(5),
  sidebarOpen: z.boolean(),
}).strict() // reject unknown keys like "user" or "role"

try {
  const raw = JSON.parse(localStorage.getItem('appState') || '{}')
  const safe = AppStateSchema.parse(raw)
  store.$patch(safe)
} catch {
  localStorage.removeItem('appState') // corrupted → reset
}
```

---

## 5. CI/CD Pipeline Integrity (A08)

### Vulnerable Pattern
```bash
# ❌ Dependencies can change between builds
npm install              # resolves latest within semver range
npm run build && deploy
```
```json
// ❌ Wildcard or loose versions
"vue-markdown": "*",
"lodash": "^4.0.0"    // could auto-upgrade to malicious patch
```

### Secure Pattern
```bash
# ✅ Frozen lockfile — fails if deps would change
npm ci --frozen-lockfile

# ✅ Audit in CI — block deploy on critical CVEs
npm audit --audit-level=high || exit 1

# ✅ Verify package provenance (npm v9+)
npm audit signatures
```
```json
// ✅ Pin exact versions
"vue": "3.4.21",

// ✅ Override transitive vulnerabilities
"overrides": { "nth-check": ">=2.0.1" }
```

### Defense Summary
1. Always use `npm ci --frozen-lockfile` in CI
2. Pin exact versions (no `^` or `~`)
3. Add SRI hashes for all CDN resources
4. Validate deserialized data shapes with Zod
5. Enable Dependabot or Snyk for automated scanning
6. Review `npm audit` before every deploy
