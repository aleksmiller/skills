# A04 + A09 + A10 — Insecure Design, Logging Failures & SSRF

## Overview

Client-side business logic (prices, limits, roles) is trivially bypassed via DevTools or Burp Suite. Most Vue apps log nothing — making attacks invisible. URL-accepting features (import, preview, upload) create SSRF vectors when the backend fetches user-supplied URLs without validation.

Severity: **High** (A04, A10) / **Medium** (A09)

---

## 1. Client-Side Business Logic (A04)

### Vulnerable Pattern
```js
// ❌ Price calculated in browser, sent to server
const total = computed(() =>
  cart.items.reduce((sum, i) => sum + i.price * i.qty, 0)
)
async checkout() {
  await axios.post('/api/order', {
    items: cart.items,
    total: total.value  // Burp: change 199.99 → 0.01
  })
}

// ❌ Quiz retake limit in Vue state only
const attempts = ref(0)
const canSubmit = computed(() => attempts.value < 3)
// DevTools: attempts.value = 0 → unlimited retakes

// ❌ Feature gate in client
const isPremium = computed(() => user.plan === 'premium')
// DevTools: user.plan = 'premium' → free access

// ❌ Rate limiting only in the UI
const canSubmit = ref(true)
const submitQuiz = () => {
  if (!canSubmit.value) return
  canSubmit.value = false // trivially bypassed
}
```

### Secure Pattern
```js
// ✅ Only send item IDs + quantities — server looks up prices
async checkout() {
  await axios.post('/api/order', {
    items: cart.items.map(i => ({ id: i.id, qty: i.qty }))
    // NO price, NO total — server calculates from DB
  })
}

// ✅ Server tracks quiz attempts in DB
// ✅ Server checks subscription tier per request
// ✅ Server-side rate limiting:
// app.use('/api/quiz', rateLimit({ windowMs: 60000, max: 3 }))
```

### Use Case
A learning platform checkout page calculates discounted prices client-side. A student intercepts the POST with Burp Suite, changes `"total": 199.99` to `"total": 0.01`, and purchases the premium course for a penny. The same technique bypasses quiz retake limits, download counters, and enrollment caps.

---

## 2. Security Logging & Monitoring (A09)

### Vulnerable Pattern
```js
// ❌ Errors swallowed — only visible in user's browser
try {
  await submitAnswer(data)
} catch (e) {
  console.log(e) // goes nowhere useful
}

// ❌ No tracking of:
//   - Failed login attempts (credential stuffing)
//   - Admin endpoint probing by student accounts
//   - Rapid-fire API calls (scraping/abuse)
//   - CSP violations (XSS attempts)
//   - JavaScript errors in production
```

### Secure Pattern
```js
// ✅ Global Vue error handler → Sentry
app.config.errorHandler = (err, instance, info) => {
  Sentry.captureException(err, {
    extra: {
      component: instance?.$options?.name,
      info,
      route: router.currentRoute.value.fullPath
    }
  })
}

// ✅ Track auth failures in API interceptor
axios.interceptors.response.use(null, (err) => {
  if ([401, 403].includes(err.response?.status)) {
    analytics.track('auth_failure', {
      url: err.config.url,
      status: err.response.status,
      timestamp: new Date().toISOString()
    })
  }
  return Promise.reject(err)
})

// ✅ CSP violation reporting
// Content-Security-Policy-Report-Only:
//   default-src 'self'; report-uri /api/csp-report

// ✅ Unhandled promise rejections
window.addEventListener('unhandledrejection', (e) => {
  Sentry.captureException(e.reason)
})
```

### Monitoring Checklist
1. Sentry or Datadog for JS error tracking
2. Log all 401/403 responses server-side
3. Alert on >5 failed logins per IP/minute
4. CSP report-uri for XSS attempt detection
5. API anomaly detection (unusual request patterns)
6. Audit trail for sensitive operations (grade changes, role assignments, data exports)

### Use Case
An attacker runs credential-stuffing against the login endpoint for 3 weeks. No logging, no alerting, no rate limiting — 200 student accounts compromised before detection. With monitoring, an alert fires after the 5th failed attempt from the same IP.

---

## 3. Server-Side Request Forgery — SSRF (A10)

### Vulnerable Pattern
```vue
<template>
  <input v-model="importUrl" placeholder="Paste resource URL" />
  <button @click="importResource">Import</button>
</template>

<script setup>
async function importResource() {
  // Backend fetches whatever URL user provides
  await axios.post('/api/import', { url: importUrl.value })
}
</script>
```

### Exploit Payloads
```
# AWS metadata — steal IAM credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Internal service probing
http://localhost:6379/        # Redis
http://localhost:27017/       # MongoDB
http://internal-admin.corp:8080/api/users  # internal admin API

# DNS rebinding — bypass IP validation
# (domain resolves to internal IP after initial DNS check passes)
```

### Secure Pattern
```js
// ✅ Client: basic URL pre-validation
const isValidUrl = (url) => {
  try {
    const u = new URL(url)
    return u.protocol === 'https:'
  } catch { return false }
}

// ✅ Server: strict domain allowlist + IP block
const ALLOWED_HOSTS = ['youtube.com', 'github.com', 'wikipedia.org']
const BLOCKED_RANGES = [
  '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
  '169.254.0.0/16', '127.0.0.0/8', '0.0.0.0/8'
]

// ✅ Resolve DNS FIRST, then verify resolved IP isn't internal
// (prevents DNS rebinding)
const { address } = await dns.resolve(parsedUrl.hostname)
if (isPrivateIP(address)) throw new Error('Blocked')

// ✅ Use a sandboxed HTTP client (Lambda/Cloud Function)
// with no access to internal network

// ✅ Set strict limits
// - Timeout: 5 seconds
// - Max response size: 5MB
// - Follow max 2 redirects
// - Never return raw response body to client
```

### Use Case
Teachers can "Import from URL" to add external learning resources. A malicious user submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The backend fetches it and returns AWS credentials — giving the attacker access to S3 buckets with student data, the RDS database, and the deployment pipeline.

### SSRF Defense Summary
1. Allowlist specific domains server-side
2. Block all internal/private IP ranges
3. Resolve DNS before fetching, then verify the IP
4. Use a sandboxed fetcher with no internal network access
5. Set strict timeouts and response size limits
6. Never return raw fetch responses to the client
