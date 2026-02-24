# Investor Onboarding

## Overview

This document describes the end-to-end onboarding flow for a single accredited HNW allocator during pilot phase. Every step is logged, gated, and verifiable.

---

## End-to-End Flow

```
┌──────────────────────────────────────────────────────────────┐
│                    INVESTOR ONBOARDING FLOW                   │
│                                                               │
│  Step 1    Investor texts ONBOARD to +1-844-669-6333         │
│     │                                                         │
│     ▼                                                         │
│  Step 2    SCA creates onboarding session                    │
│     │      AI classifies intent → ONBOARD                    │
│     │      Logged to conversationLedger                      │
│     │      Secure onboarding link generated                  │
│     │      SDC-protected packet prepared                     │
│     │                                                         │
│     ▼                                                         │
│  Step 3    Investor receives link via SMS                    │
│     │      Links to viewer.fthtrading.com                    │
│     │                                                         │
│     ▼                                                         │
│  Step 4    IDENTITY GATE                                     │
│     │      Cloudflare Zero Trust → email verification        │
│     │      OTP challenge issued                              │
│     │      Device recorded in accessLedger                   │
│     │                                                         │
│     ▼                                                         │
│  Step 5    DOCUMENT DELIVERY                                 │
│     │      Secure Viewer renders document                    │
│     │      Forensic watermark applied (per-recipient)        │
│     │      Unique fingerprint embedded                       │
│     │      Copy prevention active                            │
│     │      Screenshot deterrence active                      │
│     │      SDC_VIEW_GRANTED logged                           │
│     │                                                         │
│     ▼                                                         │
│  Step 6    SIGNING CEREMONY                                  │
│     │      Multi-sig session created                         │
│     │      OTP challenge issued (fresh)                      │
│     │      Signature applied                                 │
│     │      SignatureCertificate generated (ESIGN/UETA)       │
│     │      Events logged to:                                 │
│     │        • accessLedger                                  │
│     │        • conversationLedger                            │
│     │        • perimeterLedger                               │
│     │                                                         │
│     ▼                                                         │
│  Step 7    FUNDING INTENT (optional)                         │
│            Investor texts: FUND BOND01                       │
│            Tier 2 governance triggered                       │
│            Operator reviews in dashboard                     │
│            Manual approve/reject                             │
│            Settlement instructions released on approval      │
└──────────────────────────────────────────────────────────────┘
```

---

## Step Details

### Step 1 — First Contact

The investor sends a text message to the FTH Trading number:

```
To: +1-844-669-6333
Message: ONBOARD
```

The Sovereign Comms Agent receives this via Telnyx webhook, routes through Cloudflare, validates the webhook signature, and passes to the AI Intent Engine.

### Step 2 — Session Creation

The AI Intent Engine classifies the message as `ONBOARD` intent:

- Creates an onboarding session in the lifecycle registry
- Logs the interaction to the conversation ledger
- Generates a time-limited access token
- Prepares the SDC-protected document packet
- Composes a response with the secure viewer link

### Step 3 — Link Delivery

The investor receives an SMS response containing a link to the secure viewer:

```
viewer.fthtrading.com/view?token=<access-token>
```

This token is:
- **Time-limited** — expires after configured window
- **Single-use** — consumed on first successful access
- **Non-transferable** — bound to the originating phone number

### Step 4 — Identity Gate

When the investor clicks the link:

1. **Cloudflare Zero Trust** intercepts the request
2. Investor must verify their email address
3. **OTP challenge** is issued to their registered device
4. On successful verification:
   - Device fingerprint recorded in `accessLedger`
   - Access session created
   - Perimeter event logged

### Step 5 — Document Viewing

The Secure Document Control layer renders the document:

- **Forensic watermark** embedded (invisible, per-recipient)
- **Canonical fingerprint** applied for tamper detection
- **Copy prevention** — clipboard disabled, right-click disabled
- **Screenshot deterrence** — CSS overlay protection
- **Export policy** enforced — download restrictions per document
- `SDC_VIEW_GRANTED` event logged to access ledger

### Step 6 — Signing

If the investor proceeds to sign:

1. **Multi-sig session** created in signing gateway
2. **Fresh OTP** challenge issued (not reused from viewer)
3. Investor applies signature
4. **Signature Certificate** generated:
   - ESIGN/UETA compliant
   - Hash of signed document
   - Timestamp
   - Signer identity
   - Certificate chain
5. Events logged to access ledger, conversation ledger, and perimeter ledger

### Step 7 — Funding Intent (Optional)

If the investor texts a funding command:

```
FUND BOND01
```

This triggers **Tier 2 governance**:

1. AI Intent Engine classifies as `FUND` intent
2. Action Engine prepares funding packet
3. Request queued for **manual operator approval**
4. Operator reviews in monitoring dashboard
5. On approval: settlement instructions released
6. On rejection: investor notified with reason
7. All decisions logged to governance ledger

---

## Security Controls During Onboarding

| Control | Enforcement |
|---------|-------------|
| Webhook validation | Telnyx HMAC signature verified |
| Rate limiting | Per-IP and global limits enforced |
| Zero Trust | Cloudflare Access required |
| OTP | Required for viewer + signing (separate challenges) |
| Forensic tracking | Every view watermarked and fingerprinted |
| Chain integrity | Every event hash-chained to previous |
| Tier 2 gating | Fund operations require manual approval |
| Backup | All ledger state backed up every 15 minutes |

---

## Operator Actions During Onboarding

| When | Action |
|------|--------|
| Investor texts ONBOARD | Monitor conversation ledger |
| Investor accesses viewer | Check access ledger for successful gate |
| Investor signs | Verify signing session completion |
| Investor texts FUND | Review and approve/reject in dashboard |
| Daily | Check perimeter ledger, verify chain, review backup |

---

## Dry Run Protocol

Before inviting the real investor:

1. Use a different phone number to text `ONBOARD`
2. Use a different email for Zero Trust verification
3. Complete the full flow end-to-end
4. Attempt abuse scenarios:
   - Forward the viewer link to another device
   - Reuse an expired access token
   - Access from an unauthorized email
   - Send excessive requests (trigger rate limiter)
5. Verify all ledger entries are correct
6. Verify backup captured the test data
7. Clear test data before real onboarding

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
