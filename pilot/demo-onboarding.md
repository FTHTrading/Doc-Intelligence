# Onboarding Demonstration

## Document: Structured Finance Offering Memorandum

**Status:** Processed · Signed · Anchored  
**Format:** PDF → Canonical JSON → Signed PDF  
**Fingerprint:** `sha256:a4b8c1...redacted...f9e2d7`

---

## Processing Pipeline (Completed)

```
Step 1 — Ingest
  Format: PDF (42 pages)
  Size: 2.8 MB
  Timestamp: 2026-02-24T10:00:00.000Z

Step 2 — Parse
  Parser: PDF parser (structured extraction)
  Sections: 14 identified
  Tables: 8 extracted
  Status: ✅ Complete

Step 3 — Canonicalize
  Normalization: Whitespace, encoding, structure
  Hash (pre-transform): sha256:b7c9d2...
  Deterministic: ✅ Verified (3 passes, identical hash)

Step 4 — Transform
  Governance: DAO compliance headers injected
  Compliance: SEC disclosure footer added
  Brand: FTH Trading styling applied
  Status: ✅ Complete

Step 5 — Export
  Template: institutional-memo-v2
  Output: PDF (branded, compliant)
  Pages: 44 (2 added by transforms)

Step 6 — Fingerprint
  Algorithm: SHA-256
  Document hash: sha256:a4b8c1...redacted...f9e2d7
  Metadata hash: sha256:e3f1a8...redacted...c4d6b2
  Combined fingerprint: sha256:91c7e4...redacted...a2b5f8

Step 7 — Sign
  Session: DEMO-SESSION-001
  Signers: 2 of 2 (threshold met)
  OTP verified: ✅ Both signers
  Certificate: ESIGN/UETA compliant

Step 8 — Encrypt
  Algorithm: AES-256-GCM
  Key derivation: PBKDF2 (100,000 iterations)
  IV: Unique per document

Step 9 — IPFS Push
  CID: bafybeig...redacted...7xq
  Kubo node: Connected (peers: 47)

Step 10 — Ledger Anchor
  Chain position: #142
  Previous hash: sha256:d8e2f1...
  Entry hash: sha256:91c7e4...
  Lifecycle: ACTIVE
```

---

## Viewer Session (Simulated)

```
Access Token: tok_demo_...redacted
Expires: 2026-02-24T11:00:00.000Z (1 hour)
Viewer Controls:
  Copy: DISABLED
  Print: DISABLED
  Download: DISABLED
  Screenshot: BLOCKED
  Watermark: ENABLED (per-session, invisible)
```

---

## Signing Certificate (Summary)

```
Certificate ID: cert-demo-001
Document: Structured Finance Offering Memorandum
Signers:
  1. [REDACTED] — Managing Partner — OTP verified
  2. [REDACTED] — Compliance Officer — OTP verified
Threshold: 2 of 2 ✅
Timestamp: 2026-02-24T10:15:32.000Z
Standard: ESIGN Act (2000) + UETA
Integrity: sha256:a4b8c1...redacted...f9e2d7
```

---

*This document contains synthetic data for demonstration purposes only.*
