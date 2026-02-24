# ⚫ Governance Architecture

## Three-Tier Model

Doc-Intelligence enforces three governance tiers. Every operation is classified and gated accordingly.

### Tier 0 — Automatic

No human intervention required.

- Status queries (`--help`, `--audit-trail`)
- Health checks (dashboard API)
- Read-only ledger inspection
- Determinism verification

### Tier 1 — OTP Verified

Identity verification required.

- Document viewing (Secure Viewer)
- Signing initiation
- Document download (export policy controlled)
- Session creation

### Tier 2 — Manual Approval

Operator must explicitly approve.

- Fund operations (`FUND <SKU>`)
- Investor onboarding (`ONBOARD`)
- Vault role assignment
- Settlement instruction release

## Governance Ledger

Every governance decision is hash-chained:

| Field | Description |
|-------|-------------|
| `sequence` | Monotonic counter |
| `timestamp` | ISO 8601 |
| `tier` | 0, 1, or 2 |
| `operation` | Operation type |
| `requestedBy` | Identity of requester |
| `decision` | `APPROVED` or `REJECTED` |
| `approvedBy` | Operator identity (Tier 2 only) |
| `previousHash` | SHA-256 of previous entry |
| `hash` | SHA-256 of current entry |

## DAO Governance Modules

For future multi-party governance:

| Module | Purpose |
|--------|---------|
| `governance/proposalCompiler.ts` | Structure governance proposals |
| `governance/votingSchema.ts` | Define voting rules and quorum |
| `governance/onchainAnchor.ts` | Anchor decisions to distributed ledger |

## Pilot Override

During pilot phase:
- **Tier 2 is permanently manually gated**
- No automated fund movements
- Single operator model
- All overrides logged

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
