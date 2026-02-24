# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, **do not open a public issue.**

Contact: **security@fthtrading.com**

We will acknowledge receipt within 24 hours and provide a detailed response within 72 hours.

---

## Security Model

Doc-Intelligence operates under a defense-in-depth model with the following controls:

### Network Layer

| Control | Description |
|---------|-------------|
| **Zero Exposed Ports** | No service binds to a public-facing port. All ingress routes through Cloudflare Tunnel. |
| **Cloudflare Zero Trust** | Access requires email-verified identity through Cloudflare Access. Device posture rules enforced. |
| **Rate Limiting** | Per-IP sliding window rate limiting with automatic block escalation. Global burst protection. |
| **Webhook Validation** | All inbound webhooks (Telnyx) verified via HMAC signature with replay window enforcement. |
| **IP Allowlisting** | Webhook endpoints restricted to known Telnyx IP ranges. |

### Application Layer

| Control | Description |
|---------|-------------|
| **OTP Enforcement** | Every viewer access and signing ceremony requires a fresh one-time password. |
| **Tiered Governance** | Three-tier approval system. Fund operations require manual Tier 2 approval. |
| **Session Isolation** | Every signing session is cryptographically isolated with unique session IDs. |
| **Access Tokens** | Time-limited, single-use tokens for document viewing. Non-transferable. |
| **Export Policy** | Per-document export restrictions enforced at the viewer layer. |

### Cryptographic Layer

| Control | Description |
|---------|-------------|
| **AES-256-GCM** | All documents encrypted at rest. Key derivation via PBKDF2 (100,000 iterations, SHA-512). |
| **Hash-Chained Ledgers** | Every event log entry is chained via SHA-256. Tampering detection is automatic. |
| **Deterministic Canonicalization** | Documents are canonicalized before hashing to ensure reproducible fingerprints. |
| **Document Fingerprinting** | Every document carries a unique canonical fingerprint for lifecycle tracking. |
| **ESIGN/UETA Signatures** | Legally binding digital signatures with full certificate chain. |
| **Forensic Watermarking** | Invisible per-recipient watermarks embedded in every document view. |

### Operational Layer

| Control | Description |
|---------|-------------|
| **Encrypted Backups** | Automated every 15 minutes. AES-256-GCM encryption. Integrity-verified on creation. |
| **Backup Retention** | Configurable retention policy with automated pruning. |
| **Chain Integrity Verification** | Ledger chain integrity verified on demand and via operator dashboard. |
| **Perimeter Ledger** | All perimeter security events logged to a hash-chained audit trail. |
| **Monitoring Dashboard** | Real-time operator visibility into tunnel health, rate limiting, and ledger integrity. |

---

## Determinism Guarantee

Every document processed through the pipeline produces an identical output hash given identical input, regardless of:

- Execution timestamp
- Machine hostname or platform
- Node.js runtime version
- Filesystem ordering

This is verified by an automated test suite executing **20,000 hash computations** across **10 test vectors** with **zero drift tolerance**.

```bash
npm run test:determinism
```

---

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Unauthorized document access | Zero Trust gating + OTP + access tokens |
| Document tampering | Hash-chained ledgers + deterministic fingerprinting |
| Webhook spoofing | HMAC signature verification + replay prevention |
| Brute force access | Rate limiting + IP blocking + OTP |
| Data exfiltration | Forensic watermarking + export policy + copy prevention |
| Backup compromise | AES-256-GCM encryption + integrity hashing |
| Insider tampering | Hash chain verification + immutable ledger entries |
| Network interception | Cloudflare Tunnel (TLS) + no exposed ports |

### Out of Scope

- Physical device security of end-user devices
- Cloudflare infrastructure compromise
- Telnyx carrier-level interception
- Social engineering attacks against operators

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.0.x   | ✅ Active |
| < 4.0   | ❌ No     |

---

## Compliance

This system supports but does not guarantee compliance with:

- ESIGN Act (15 U.S.C. § 7001)
- UETA (Uniform Electronic Transactions Act)
- SEC Rule 17a-4 (record retention principles)
- SOC 2 Type II (control alignment)

Operators are responsible for compliance determination in their jurisdiction.

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
