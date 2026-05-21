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

> **Note:** the supply-chain subsections below describe attacker *capabilities and behaviors to audit for*. They deliberately contain no working malicious implementations — only the red-flag patterns a reviewer should look for in third-party plugin source.

### 5a. Malicious Vite Plugins (Build-Time Compromise)

A Vite plugin runs arbitrary Node.js during the build process. It can read environment variables, modify source files, inject code into the final bundle, and make network requests — all before your app reaches production. This is more powerful than a runtime dependency compromise because the injected code ships inside your legitimate bundle, passing SRI checks and CSP policies.

#### Vulnerable Pattern

The classic entry point is a **typosquatted plugin** — a package whose name differs from a popular one by a transposed or dropped character (for example, a one-character variation on `vite-plugin-vue-devtools`). A developer installs it by mistake and registers it in `vite.config.js`, where it runs arbitrary Node.js during every build.

Indicators that a Vite plugin in your config is worth scrutinizing:

- The package name is a near-match of a well-known plugin but has a tiny spelling difference.
- It was published recently, has a low download count, or has no linked source repository.
- It is pinned with a loose range (`^`/`~`) rather than an exact version.

#### What a Malicious Vite Plugin Can Do (Detection Reference)

You do not need to read malicious source to defend against it — you audit for *behaviors*. When reviewing a Vite plugin, treat the following combinations as red flags. Each describes a capability, not an implementation:

- **`configResolved` / `config` hooks that touch environment data.** A plugin that reads `config.env` or `process.env` has access to every server-side secret present at build time. Combined with any outbound network call, that is an exfiltration path.
- **`transform` or `load` hooks that rewrite `.vue` or `.js` modules.** Legitimate transforms compile or optimize. A compromised one concatenates extra code into the output — that injected code ships inside your trusted bundle and passes SRI/CSP.
- **Any outbound network activity at build time** to a domain that is not the plugin's documented service.
- **Filesystem reads outside the project directory** (home directory, credential files, CI secret mounts).

Audit procedure: read the plugin's published source on npm, diff it against its GitHub repo, and confirm the two match. A mismatch between the published tarball and the public repo is the strongest single signal of compromise.

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
A developer searches for a popular Vite devtools plugin and installs a typosquatted package whose name differs by a single character. Because Vite plugins run during `npm run build`, the package executes with access to the build environment — including any non-`VITE_`-prefixed secrets that were safe from client exposure until that point. The compromise is invisible at runtime: the only defenses that would have caught it are name verification before install, exact version pinning, and provenance checks.

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

#### What a Malicious Vue Plugin Can Do (Detection Reference)

When you call `app.use(plugin)`, the plugin's `install(app)` function receives the application instance and can register global behavior. Audit for *capability*, not for specific code. Treat these registrations as red flags when they appear in a third-party plugin that advertises a narrow purpose (analytics, tooltips, formatting):

- **`app.mixin()` with lifecycle hooks.** A global mixin's `beforeCreate`/`mounted`/`updated` hooks run inside *every* component. A plugin that reads component props or options inside such a hook can see data from your login form, payment form, and admin panel. Paired with any outbound request, that is mass interception.
- **`$emit` wrapping or overriding.** Intercepting emitted events lets a plugin observe `submit`, `login`, or `payment` events application-wide.
- **`app.directive()` that reads DOM values on update.** A global directive can read `input` values — including password and card fields — on every render cycle.
- **Background transmission primitives** (`fetch`, `XMLHttpRequest`, image-beacon requests, `navigator.sendBeacon`) that fire outside any feature the plugin documents.
- **Dynamic code execution** (`eval`, the `Function` constructor, `setTimeout`/`setInterval` called with a string argument).

A legitimate analytics plugin tracks the events you configure and nothing else. A plugin that quietly registers a global mixin to inspect props in components unrelated to analytics is exfiltration.

#### Secure Pattern
```js
// ✅ Audit plugin source before app.use() — check for:
//   - app.mixin() calls (global lifecycle hooks)
//   - app.directive() calls (DOM access)
//   - app.component() calls (global component injection)
//   - Background HTTP requests (fetch, XMLHttpRequest, Image beacons)
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
A learning platform installs a "Vue analytics" plugin that advertises simple page-view tracking. In addition to that, the plugin registers a global `beforeCreate` mixin that runs inside every component — including the login form, the payment form, and the admin panel. Because the mixin's scope is application-wide rather than limited to the analytics feature, it can observe sensitive form state far outside what the plugin claims to do. The fix is structural: prefer explicitly scoped composables over `app.use()` plugins, and audit any plugin that registers global mixins, directives, or event interception before trusting it.

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

A compromised PostCSS plugin runs with full Node.js privileges during the build, so it can read files and environment variables in the build environment. Separately, because PostCSS emits the CSS your app ships, a malicious plugin could inject style rules that leak what a user types — CSS attribute-selector tricks can request a background resource based on the current value of an input, turning styling into a covert data channel. Both risks come from the same root cause: an unvetted plugin in the build chain.

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
