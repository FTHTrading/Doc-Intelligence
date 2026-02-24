# Doc-Intelligence

**Sovereign Document Infrastructure for Institutional Capital Markets**

Built by [From The Hart](https://fthtrading.com) · `v4.0.0`

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build: Deterministic](https://img.shields.io/badge/build-deterministic-brightgreen.svg)](#determinism)
[![Security: Zero Trust](https://img.shields.io/badge/security-zero%20trust-critical.svg)](#security-posture)
[![Pilot: Institutional](https://img.shields.io/badge/pilot-institutional-gold.svg)](#pilot-configuration)

---

## Executive Overview

Doc-Intelligence is sovereignty-first document infrastructure. It ingests, parses, transforms, signs, encrypts, distributes, and archives documents through a fully deterministic pipeline — producing cryptographically verifiable chains of custody from raw file to immutable ledger entry.

Every output is reproducible. Every access is logged. Every signature is legally binding under ESIGN/UETA. Every document is forensically watermarked, fingerprinted, and anchored to distributed storage with AES-256-GCM encryption.

This is not a document editor. This is institutional plumbing.

---

## System Architecture

```
                           ┌─────────────────────────────────┐
                           │         INVESTOR DEVICE          │
                           └──────────────┬──────────────────┘
                                          │
                              ┌───────────┴───────────┐
                              │   Telnyx SMS/Voice     │
                              │   +1-844-669-6333      │
                              └───────────┬───────────┘
                                          │
                              ┌───────────┴───────────┐
                              │   Cloudflare Edge      │
                              │   Zero Trust Access    │
                              │   Rate Limiting        │
                              │   Webhook Validation   │
                              └───────────┬───────────┘
                                          │
                              ┌───────────┴───────────┐
                              │   Cloudflare Tunnel    │
                              │   (No Exposed Ports)   │
                              └───────────┬───────────┘
                                          │
          ┌───────────────────────────────┼───────────────────────────────┐
          │                               │                               │
┌─────────┴─────────┐        ┌───────────┴───────────┐        ┌─────────┴─────────┐
│  🔴 SCA Layer      │        │  🔵 Document Engine    │        │  🟣 SDC Layer      │
│  AI Intent Engine  │        │  Ingest → Parse →      │        │  Secure Viewer     │
│  Action Engine     │        │  Transform → Export    │        │  Forensic Watermark│
│  Response Composer │        │  Fingerprint → Sign    │        │  Access Tokens     │
│  Conversation      │        │  Encrypt → IPFS        │        │  Export Policy     │
│  Ledger            │        │  Anchor → Registry     │        │  Access Ledger     │
└───────────────────┘        └───────────┬───────────┘        └───────────────────┘
                                          │
          ┌───────────────────────────────┼───────────────────────────────┐
          │                               │                               │
┌─────────┴─────────┐        ┌───────────┴───────────┐        ┌─────────┴─────────┐
│  🟡 Signing        │        │  🟠 Perimeter          │        │  ⚫ Ledger Systems  │
│  Gateway           │        │  Cloudflare Config     │        │  Hash-Chained      │
│  Multi-Sig         │        │  Tunnel Manager        │        │  Event Logs        │
│  OTP Engine        │        │  Webhook Validator     │        │  CID Registry      │
│  Session Manager   │        │  Rate Limiter          │        │  Lifecycle Registry│
│  Distribution      │        │  Perimeter Ledger      │        │  Backup Ledger     │
└───────────────────┘        └───────────────────────┘        └───────────────────┘
                                          │
                              ┌───────────┴───────────┐
                              │  ⚙️ Ops Infrastructure  │
                              │  Backup Agent (AES)    │
                              │  Monitor Dashboard     │
                              │  Docker Compose        │
                              │  IPFS/Kubo Node        │
                              └───────────────────────┘
```

---

## Module Map

| Color | Layer | Modules | Status |
|:-----:|-------|---------|:------:|
| 🟢 | **Infrastructure** | Docker, IPFS/Kubo, Cloudflare Tunnel | `OPERATIONAL` |
| 🔵 | **Document Engine** | Ingest, Parse, Transform, Export, Fingerprint, Canonicalize | `OPERATIONAL` |
| 🟣 | **Secure Document Control** | Secure Viewer, Forensic Watermark, Access Tokens, Export Policy, Access Ledger | `OPERATIONAL` |
| 🟡 | **Signing Gateway** | Multi-Sig Sessions, OTP Engine, Distribution Engine, Signature Certificates | `OPERATIONAL` |
| 🔴 | **Sovereign Comms Agent** | AI Intent Engine, Action Engine, Inbound Router, Response Composer, Conversation Ledger | `OPERATIONAL` |
| 🟠 | **Perimeter Security** | Cloudflare Config, Tunnel Manager, Webhook Validator, Rate Limiter, Perimeter Ledger | `OPERATIONAL` |
| ⚫ | **Ledger Systems** | Hash-Chained Event Logs, CID Registry, Lifecycle Registry, Backup Ledger | `OPERATIONAL` |
| ⚙️ | **Ops & Monitoring** | Backup Agent (AES-256-GCM), Monitor Dashboard, Docker Compose | `OPERATIONAL` |

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [Architecture](ARCHITECTURE.md) | Full system architecture and data flow |
| [Security Posture](SECURITY.md) | Cryptographic guarantees and threat model |
| [Governance](GOVERNANCE.md) | Tiered governance and approval logic |
| [Deployment](DEPLOYMENT.md) | Docker Compose deployment and tunnel setup |
| [Monitoring](MONITORING.md) | Operator dashboard and backup procedures |
| [Onboarding](ONBOARDING.md) | Investor onboarding flow |
| [Contributing](CONTRIBUTING.md) | Development standards and contribution policy |

### Subsystem Documentation

| Document | Layer |
|----------|-------|
| [docs/architecture.md](docs/architecture.md) | 🔵 Engine pipeline deep dive |
| [docs/sdc.md](docs/sdc.md) | 🟣 Secure Document Control |
| [docs/signing.md](docs/signing.md) | 🟡 Signing Gateway |
| [docs/telecom.md](docs/telecom.md) | 🔴 Sovereign Comms Agent |
| [docs/perimeter.md](docs/perimeter.md) | 🟠 Cloudflare Perimeter |
| [docs/governance.md](docs/governance.md) | ⚫ Governance tiers |
| [docs/backup.md](docs/backup.md) | ⚙️ Backup and recovery |
| [docs/pilot.md](docs/pilot.md) | 🟢 Pilot configuration |

### Flow Diagrams

| Diagram | Description |
|---------|-------------|
| [diagrams/system-flow.md](diagrams/system-flow.md) | End-to-end system flow |
| [diagrams/telecom-flow.md](diagrams/telecom-flow.md) | Inbound message routing |
| [diagrams/signing-flow.md](diagrams/signing-flow.md) | Multi-sig signing ceremony |
| [diagrams/perimeter-flow.md](diagrams/perimeter-flow.md) | Perimeter validation chain |

---

## Security Posture

| Control | Implementation |
|---------|---------------|
| **Deterministic Output** | Every pipeline run produces identical output for identical input — verified across 20,000 hash computations |
| **Hash-Chained Ledgers** | All event logs use SHA-256 chain hashing — any tampering breaks the chain |
| **Zero Exposed Ports** | All ingress via Cloudflare Tunnel — no direct port binding to public internet |
| **Cloudflare Zero Trust** | Email-gated access with device posture enforcement |
| **OTP Enforcement** | Time-based one-time passwords required for viewer access and signing |
| **AES-256-GCM Encryption** | Documents encrypted at rest with PBKDF2 key derivation (100k iterations, SHA-512) |
| **Forensic Watermarking** | Per-recipient invisible watermarks embedded in every viewed document |
| **Document Fingerprinting** | Canonical fingerprints enable tamper detection across document lifecycle |
| **Multi-Signature Support** | Signing sessions require configurable signer thresholds |
| **ESIGN/UETA Compliance** | Digital signatures carry legal standing under US electronic signature law |
| **Encrypted Backups** | Automated every 15 minutes with AES-256-GCM, integrity-verified, retention-enforced |
| **Rate Limiting** | Per-IP and global rate limiting with automatic blocking |
| **Webhook Validation** | Telnyx signature verification with replay attack prevention |

See [SECURITY.md](SECURITY.md) for the complete security model.

---

## Governance Tiers

The engine enforces a three-tier governance model:

| Tier | Scope | Approval |
|------|-------|----------|
| **Tier 0** | Read-only operations, status queries | Automatic |
| **Tier 1** | Standard document operations, viewing, signing | OTP verification |
| **Tier 2** | Fund operations, onboarding, vault role assignment | Manual operator approval |

During pilot: **Tier 2 is manually gated.** No automated fund movements.

See [GOVERNANCE.md](GOVERNANCE.md) for the complete governance specification.

---

## Determinism

Every document processed through the engine produces an identical canonical fingerprint regardless of:

- Processing time
- Machine hostname
- Node.js version
- Filesystem state

Verified by automated CI:

```
10 tests · 20,000 hash computations · Zero drift tolerance
```

```bash
npm run test:determinism
```

---

## Deployment

```bash
# Clone
git clone https://github.com/FTHTrading/Doc-Intelligence.git
cd Doc-Intelligence

# Configure
cp .env.example .env
# Edit .env with your credentials

# Deploy
docker compose up -d

# Verify
docker compose ps
docker compose logs fth-engine --tail 50
```

Four containerized services:
- `fth-engine` — Core document intelligence engine
- `ipfs-kubo` — Distributed storage node
- `cloudflared` — Tunnel daemon (zero exposed ports)
- `fth-backup` — Encrypted backup agent

See [DEPLOYMENT.md](DEPLOYMENT.md) for full deployment instructions.

---

## Pilot Configuration

Current deployment: **Single accredited HNW allocator**

| Parameter | Setting |
|-----------|---------|
| Investor Count | 1 |
| OTP Required | Every access |
| Tier 2 Approval | Manual |
| Backup Interval | 15 minutes |
| Perimeter Verification | Daily |
| Zero Trust Gating | Email + device |
| Exposed Ports | None |

See [ONBOARDING.md](ONBOARDING.md) for the end-to-end investor flow.

---

## Repository Structure

```
doc-intelligence-engine/
├── app.ts                    # CLI entry point (~3200 lines)
├── ingest/                   # Format detection + file intake
├── parser/                   # PDF, DOCX, HTML, image OCR parsing
├── transform/                # Governance, compliance, brand transforms
├── export/                   # Multi-format output generation
├── schema/                   # Document structure schemas
├── sovereign/                # IPFS, encryption, ledger, backup, dashboard
├── signature/                # Fingerprinting + deterministic hashing
├── registry/                 # CID registry + SKU engine
├── gateway/                  # Signing gateway + OTP + distribution
├── sdc/                      # Secure Document Control layer
├── telecom/                  # Sovereign Comms Agent (AI + Telnyx)
├── perimeter/                # Cloudflare perimeter security
├── governance/               # DAO governance + on-chain anchoring
├── agreements/               # Agreement state engine
├── research/                 # Research & publication OS
├── batch/                    # Batch processing engine
├── web/                      # Sovereign portal
├── styles/                   # Brand styling engine
├── ipfs/                     # IPFS configuration
├── archive/                  # Archive management
├── test/                     # Determinism test suite
├── docs/                     # Technical documentation
├── diagrams/                 # Architecture flow diagrams
├── assets/                   # Branding assets
└── .github/workflows/        # CI/CD automation
```

---

## License

MIT License. See [LICENSE](LICENSE).

## Compliance Disclaimer

This system is designed to support institutional compliance workflows including ESIGN/UETA-compliant digital signatures, AML/KYC-compatible onboarding flows, and auditable document chains of custody. It does not constitute legal, financial, or regulatory advice. Operators are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction.

---

## Repository Disclosure

This repository describes the architecture and operational model of the Doc-Intelligence system.

Operational deployments include additional configuration layers, access controls, and security measures not exposed in this repository. No production secrets, private ledger data, API keys, or tunnel credentials are contained herein.

All runtime state — signing sessions, access ledgers, IPFS data, backup archives, and environment configuration — is excluded via `.gitignore` and never committed to version control.

---

**From The Hart** · Sovereign Infrastructure · [fthtrading.com](https://fthtrading.com)
