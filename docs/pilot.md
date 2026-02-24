# 🟢 Pilot Configuration

## Overview

The pilot is configured for a single accredited HNW allocator. Maximum security discipline. Minimum attack surface. Full auditability.

## Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Investor Count | 1 | Validate every layer before scaling |
| Profile | Accredited / HNW | Institutional compliance required |
| OTP | Every access | No session caching |
| Tier 2 | Manual gating | No automated fund operations |
| Backup | Every 15 min | Ledger state always recoverable |
| Perimeter Checks | Daily | Proactive, not reactive |
| Zero Trust | Email + device | Cloudflare Access enforced |
| Exposed Ports | 0 | All ingress via tunnel |
| UX Concessions | None | Friction signals seriousness |

## Security Posture: Maximum Discipline

- OTP required on **every viewer access**
- OTP required on **every signing ceremony** (separate challenge)
- Tier 2 approval required for:
  - `FUND` operations
  - New onboarding
  - Vault role assignment
- Viewer behind Cloudflare Zero Trust
- Backup every 15 minutes
- Perimeter ledger verified daily

This is not retail UX. This is allocator-grade compliance posture.

## Pre-Invite Checklist

Before inviting the investor:

| # | Task | Command |
|---|------|---------|
| 1 | Start backup daemon | `--backup-daemon` |
| 2 | Launch dashboard | `--dashboard` |
| 3 | Start tunnel | `--tunnel-start` |
| 4 | Confirm Zero Trust gating | Cloudflare Dashboard |
| 5 | Run dry onboarding (different phone + email) | Text `ONBOARD` |
| 6 | Attempt link forwarding | Should fail |
| 7 | Attempt expired token reuse | Should fail |
| 8 | Attempt unauthorized device | Should fail |
| 9 | Trigger rate limiter | Should block |
| 10 | Verify all ledger entries | `--perimeter-ledger report` |

## What This Proves

If the investor completes:

- Onboarding
- Secure document viewing
- Signing ceremony
- Funding intent (optional)
- Ledger verification

Without friction, confusion, or breakage — then the system validates:

- AI governance logic
- Perimeter enforcement
- Identity gating
- Ledger integrity
- Backup reliability
- Telecom routing
- End-to-end chain of custody

That is the institutional minimum viable infrastructure.

## Scaling

After successful pilot with 1 investor:

1. Expand to 5-10 allocators
2. Add per-investor access policies
3. Enable multi-operator approval
4. Implement webhook-based alerting
5. Add geographic access restrictions
6. Enable device posture enforcement

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
