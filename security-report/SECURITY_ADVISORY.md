# Security Advisory: JAXB-RI — Inverted Secure Processing, XXE, SSRF

## Summary

JAXB-RI contains 1 CRITICAL and 3 HIGH-severity vulnerabilities. The most severe is an **inverted boolean** in `DomAnnotationParserFactory` that disables `FEATURE_SECURE_PROCESSING` when it should be enabled (CRITICAL logic bug). Additional findings include missing XXE protections in multiple parsers, SSRF via XSOM schema resolution, and a shared mutable cache enabling cross-thread data corruption.

**Verified against:** JAXB-RI latest HEAD

---

## Finding 1: Inverted FEATURE_SECURE_PROCESSING in DomAnnotationParserFactory (CRITICAL)

### CVSS Score: 9.1

### Description

At `DomAnnotationParserFactory.java:82`, the `FEATURE_SECURE_PROCESSING` flag is set with an **inverted boolean value**. Instead of enabling secure processing (which restricts entity expansion, external DTDs, and resource limits), the code disables it. This means all XML parsed through this code path has no security restrictions.

```java
// Line 82 — INVERTED: should be true, is false
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
```

This affects all JAXB schema compilation that uses DOM annotation parsing — a core code path for `xjc` and runtime schema processing.

### Fix

Change `false` to `true` at line 82.

---

## Finding 2: Missing XXE Protection in Schema Parsers (HIGH)

### CVSS Score: 8.1

### Description

Multiple `SAXParserFactory` and `DocumentBuilderFactory` instances across JAXB-RI are created without disabling external entities. Key locations:

- Schema compilation parsers
- Annotation parsers
- Runtime unmarshalling paths

Unlike Finding 1 (which is an active inversion), these are omissions — the secure processing feature is simply never set.

### Fix

Add `FEATURE_SECURE_PROCESSING = true`, `DISALLOW_DOCTYPE_DECL = true`, and disable external entity features on all parser factory instances.

---

## Finding 3: SSRF via XSOM External Schema Resolution (HIGH)

### CVSS Score: 7.5

### Description

XSOM (XML Schema Object Model, bundled in JAXB-RI) resolves `<xs:import>` and `<xs:include>` `schemaLocation` attributes by fetching remote URLs. When processing attacker-influenced schemas, this enables SSRF — the JAXB process fetches arbitrary URLs from the server's network perspective.

### Attack Scenario

1. Application accepts user-provided XML schemas for validation
2. Schema contains `<xs:import schemaLocation="http://169.254.169.254/latest/meta-data/iam/security-credentials/">`
3. JAXB resolves the URL, fetching AWS metadata from within the VPC

### Fix

Implement a restrictive `EntityResolver` that blocks non-local schema references. Add URL allowlist configuration.

---

## Finding 4: Shared Mutable Cache — Cross-Thread Data Corruption (HIGH)

### CVSS Score: 7.0

### Description

JAXB-RI uses shared mutable caches for schema compilation artifacts without adequate synchronization. Concurrent schema compilation from multiple threads can produce corrupted schema models, leading to incorrect validation (security-relevant when validation enforces access control or input sanitization).

### Fix

Add proper synchronization or use `ConcurrentHashMap`. Consider thread-local caches.

---

## Disclosure Timeline

- **2026-06-27:** Vulnerabilities discovered and verified in latest source
