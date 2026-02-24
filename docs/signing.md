# 🟡 Signing Gateway

## Overview

The Signing Gateway manages multi-signature ceremonies with OTP enforcement. Every signature produces an ESIGN/UETA-compliant certificate and is logged across multiple ledgers.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| Signing Gateway | `gateway/signingGateway.ts` | HTTP signing server (port 3002) |
| Signing Session | `gateway/signingSession.ts` | Multi-sig session management |
| OTP Engine | `gateway/otpEngine.ts` | One-time password generation and verification |
| Distribution Engine | `gateway/distributionEngine.ts` | Signed document distribution |
| Intent Logger | `gateway/intentLogger.ts` | Signing intent recording |

## Signing Flow

```
Signer requests signing
        │
        ▼
┌─────────────────────┐
│  Session Created     │
│  Signers registered  │
│  Threshold set       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  OTP Challenge       │
│  Sent to signer      │
│  Time-limited        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  OTP Verified        │
│  Identity confirmed  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Signature Applied   │
│  Hash of document    │
│  Signer identity     │
│  Timestamp           │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Certificate Gen     │
│  ESIGN/UETA          │
│  Certificate chain   │
│  Legal standing      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Ledger Updates      │
│  accessLedger        │
│  conversationLedger  │
│  perimeterLedger     │
└─────────────────────┘
```

## Multi-Sig Sessions

Sessions support configurable signer thresholds:

| Parameter | Description |
|-----------|-------------|
| Session ID | Cryptographically unique identifier |
| Document Hash | SHA-256 of the document being signed |
| Required Signers | Minimum threshold for completion |
| Registered Signers | List of authorized signers |
| Status | `pending` → `active` → `completed` / `expired` |
| Expiry | Auto-expiration after configurable window |

## OTP Engine

| Feature | Detail |
|---------|--------|
| Algorithm | TOTP-compatible |
| Delivery | SMS via Telnyx |
| Validity | Time-limited window |
| Reuse | Single-use — consumed on verification |
| Per-ceremony | Fresh OTP for each signing ceremony (not reused from viewer) |

## Signature Certificate

Each signed document receives a certificate:

```json
{
  "certificateId": "CERT-2026-001",
  "documentHash": "sha256:a3f8c1...",
  "signedAt": "2026-02-24T14:30:00.000Z",
  "signers": [
    {
      "identity": "investor@example.com",
      "signedAt": "2026-02-24T14:30:00.000Z",
      "otpVerified": true
    }
  ],
  "legalBasis": "ESIGN Act (15 U.S.C. § 7001), UETA",
  "certificateHash": "sha256:b4e9d2..."
}
```

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
