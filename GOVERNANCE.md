# Governance Model

## Overview

Doc-Intelligence enforces a three-tier governance model that controls every operation in the system. No action bypasses governance — from document viewing to fund settlement.

---

## Tier Structure

### Tier 0 — Automatic

Operations that require no human intervention:

| Operation | Example |
|-----------|---------|
| Status queries | `--help`, `--audit-trail`, `--backup-status` |
| Read-only inspection | `--sdc-ledger`, `--perimeter-ledger`, `--session-status` |
| Health checks | Dashboard API, tunnel status |
| Determinism verification | `npm run test:determinism` |

**Approval:** None required. Logged automatically.

### Tier 1 — OTP Verified

Operations that require identity verification:

| Operation | Example |
|-----------|---------|
| Document viewing | Secure viewer access via SDC |
| Signature initiation | Signing gateway session creation |
| Document download | Export policy-controlled retrieval |
| Session creation | Multi-sig signing ceremony start |

**Approval:** OTP challenge issued and verified. Access token generated. Event logged to access ledger.

### Tier 2 — Manual Operator Approval

Operations that require explicit human authorization:

| Operation | Example |
|-----------|---------|
| Fund operations | `FUND BOND01` — funding intent processing |
| Investor onboarding | New allocator provisioning |
| Vault role assignment | Permission escalation |
| Settlement release | Final settlement instruction delivery |

**Approval:** System queues request. Operator reviews in dashboard. Manual approve/reject. All decisions logged to governance ledger with operator signature.

---

## Pilot Configuration

During institutional pilot:

- **Tier 2 is permanently gated.** No automated fund operations.
- **Every Tier 1 operation requires fresh OTP.** No cached sessions.
- **Single operator model.** One authorized approver.
- **All governance events are hash-chained.** Tamper-evident audit trail.

---

## Governance Ledger

Every governance decision is recorded in a hash-chained ledger:

```
{
  "sequence": 1,
  "timestamp": "2026-02-24T14:30:00.000Z",
  "tier": 2,
  "operation": "FUND_INTENT",
  "subject": "BOND01",
  "requestedBy": "investor@example.com",
  "decision": "APPROVED",
  "approvedBy": "operator@fthtrading.com",
  "previousHash": "0000000000000000",
  "hash": "a3f8c1d2..."
}
```

Each entry chains to the previous via SHA-256 hash. Any modification to historical entries breaks the chain and is detectable.

---

## DAO Governance Layer

The system includes a DAO governance module for on-chain anchoring:

- **Proposal Compiler** — Structures governance proposals for chain submission
- **Voting Schema** — Defines voting rules and quorum requirements
- **On-Chain Anchor** — Anchors governance decisions to distributed ledge

These modules are available for future multi-party governance expansion beyond single-operator pilot.

---

## Escalation Path

```
Tier 0 (Auto) → Tier 1 (OTP) → Tier 2 (Manual) → Reject/Approve
                                                        │
                                                        ▼
                                              Governance Ledger
                                                        │
                                                        ▼
                                              Hash Chain Verified
```

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
