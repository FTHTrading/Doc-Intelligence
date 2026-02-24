# 🟠 Perimeter Security

## Overview

The perimeter security layer controls all external access to the system. No request reaches the application without passing through Cloudflare Zero Trust, the rate limiter, and webhook validation.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| Cloudflare Config | `perimeter/cloudflareConfig.ts` | Zero Trust configuration and policies |
| Tunnel Manager | `perimeter/tunnelManager.ts` | Tunnel lifecycle management |
| Webhook Validator | `perimeter/webhookValidator.ts` | HMAC signature verification |
| Rate Limiter | `perimeter/rateLimiter.ts` | Per-IP and global rate limiting |
| Perimeter Ledger | `perimeter/perimeterLedger.ts` | Hash-chained security event log |

## Network Architecture

```
Internet
    │
    ▼
Cloudflare Edge
    │
    ├── Zero Trust Access Policy (email gating)
    ├── WAF Rules
    ├── DDoS Protection
    │
    ▼
Cloudflare Tunnel (encrypted)
    │
    ▼
Docker Internal Network (fth-internal)
    │
    ├── fth-engine (ports 3001-3005, internal only)
    ├── ipfs-kubo (ports 5001, 8081, internal only)
    └── fth-backup (no ports)
```

**Zero exposed ports.** The `fth-internal` Docker network has `internal: true` — no external connectivity. Only `cloudflared` bridges to the Cloudflare edge via the `fth-tunnel` network.

## Zero Trust Access

| Parameter | Configuration |
|-----------|--------------|
| Authentication | Email OTP |
| Allowed Identities | Whitelist only |
| Session Duration | 1 hour |
| Device Posture | Optional (recommended for production) |
| Geography | Configurable country restrictions |

## Rate Limiter

| Feature | Description |
|---------|-------------|
| Algorithm | Sliding window counter |
| Per-IP Limit | Configurable requests/window |
| Global Limit | Configurable burst cap |
| Block Duration | Escalating (1m → 5m → 15m → 1h) |
| Whitelist | Operator IPs excluded |
| Persistence | In-memory with perimeter ledger backup |

## Webhook Validation

| Control | Description |
|---------|-------------|
| HMAC Verification | SHA-256 HMAC of webhook body against Telnyx secret |
| Timestamp Window | Reject webhooks older than 5 minutes |
| IP Allowlist | Only known Telnyx IP ranges accepted |
| Replay Prevention | Nonce tracking within validation window |
| Failure Logging | All rejections logged to perimeter ledger |

## Perimeter Ledger

All security events recorded in a hash-chained ledger:

| Event Type | Description |
|------------|-------------|
| `validation-pass` | Webhook signature verified |
| `validation-fail` | Webhook signature rejected |
| `rate-limit-warning` | IP approaching rate limit |
| `rate-limit-blocked` | IP blocked by rate limiter |
| `tunnel-started` | Cloudflare tunnel connected |
| `tunnel-stopped` | Cloudflare tunnel disconnected |
| `tunnel-error` | Tunnel connection error |
| `access-granted` | Zero Trust access approved |
| `access-denied` | Zero Trust access rejected |

Chain integrity is verifiable:

```bash
npx ts-node app.ts --verify-perimeter-chain
```

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
