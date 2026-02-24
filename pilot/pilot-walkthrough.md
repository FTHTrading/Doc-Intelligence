# Pilot Walkthrough

## Session Guide for Allocator-01

This walkthrough describes the complete pilot session from operator preparation through investor document delivery. All steps reference the live system — no simulation or mock infrastructure.

---

## Pre-Session (Operator)

### 1. System Verification

```bash
# Verify all services are running
docker compose ps

# Expected: 4 services, all healthy
#   fth-engine    — Running
#   ipfs-kubo     — Running
#   cloudflared   — Running
#   fth-backup    — Running

# Check monitoring dashboard
npx ts-node app.ts --monitor-health

# Verify IPFS connectivity
npx ts-node app.ts --ipfs-status
```

### 2. Document Preparation

```bash
# Process the offering memorandum
npx ts-node app.ts --input offering-memorandum.pdf --output-dir ./output

# Verify deterministic processing (run 3x, compare hashes)
npx ts-node app.ts --determinism-test offering-memorandum.pdf

# Expected: 3 identical SHA-256 hashes
```

### 3. Signing Session Creation

```bash
# Create multi-sig session
npx ts-node app.ts --create-session \
  --doc offering-memorandum.pdf \
  --signers 2 \
  --threshold 2

# Session ID generated: [recorded internally]
```

### 4. Tunnel Verification

```bash
# Verify Cloudflare tunnel is active
npx ts-node app.ts --tunnel-status

# Expected: tunnel healthy, Zero Trust policy active
```

---

## Investor Session

### 5. Access Link Delivery

The operator generates a time-limited, access-controlled viewing link:

```
Link type:     Cloudflare Zero Trust tunnel URL
Expiration:    Single-use, 60-minute window
Authentication: Email identity verification at Cloudflare edge
OTP gate:      6-digit code, 5-minute window
```

The link is delivered through an encrypted, pre-agreed channel — not email, not SMS.

### 6. Investor Arrives

When the investor clicks the link:

1. **Cloudflare Edge** — Identity verified against Zero Trust policy
2. **Rate Limiter** — Request passes rate check
3. **Tunnel Transit** — Encrypted passage to internal services
4. **OTP Challenge** — 6-digit code sent to verified phone
5. **SDC Viewer Opens** — Document displayed with full protection

### 7. Document Viewing

The investor sees the document in the Secure Document Control viewer:

- **Copy/paste:** Disabled
- **Print:** Disabled
- **Download:** Disabled
- **Screenshot:** Blocked (CSS + JS overlay)
- **Watermark:** Invisible, per-session forensic mark
- **Timer:** Session expiration shown

### 8. Signing Ceremony

If the investor proceeds to sign:

1. OTP re-verification (fresh challenge)
2. Document hash displayed for confirmation
3. Signature applied (click-to-sign with identity binding)
4. Certificate generated (ESIGN/UETA compliant)
5. Counter-signature by operator (OTP verified)
6. Threshold met → session closes

### 9. Post-Signing

```
Certificate:    Generated and anchored to ledger
IPFS:           Signed document pushed to Kubo node
CID:            Registered in CID registry
Ledger:         Hash-chain entry appended
Lifecycle:      Status → SIGNED
Access Ledger:  Session recorded with all events
```

---

## Post-Session (Operator)

### 10. Verification

```bash
# Verify backup captured the session
npx ts-node app.ts --backup-status

# Verify ledger integrity
npx ts-node app.ts --verify-chain

# Review access ledger
npx ts-node app.ts --sdc-ledger all

# Check perimeter events
npx ts-node app.ts --perimeter-status
```

### 11. Reporting

All session data is available through the monitoring dashboard on port 3005:

- Signing session status
- Access token usage
- Perimeter events
- IPFS storage confirmation
- Backup verification

---

## Security Guarantees

| Control | Status |
|---------|--------|
| Zero exposed ports | Verified |
| Cloudflare Zero Trust | Active |
| OTP per signing action | Enforced |
| Document copy/print/download | Blocked |
| Forensic watermark | Applied |
| Hash-chain integrity | Unbroken |
| Encrypted backup | Current |

---

*This walkthrough describes the production system. No mock or simulated components are used.*
