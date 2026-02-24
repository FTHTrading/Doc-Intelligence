# Doc-Intelligence Documentation

## Overview

Doc-Intelligence is sovereign document infrastructure for institutional capital markets. This documentation covers every layer of the system — from document processing to perimeter security.

---

## Documentation Index

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Document processing pipeline and data flow |
| [Secure Document Control](sdc.md) | Viewer security, watermarking, access control |
| [Signing Gateway](signing.md) | Multi-sig signing, OTP, certificate generation |
| [Sovereign Comms Agent](telecom.md) | AI-powered SMS/voice routing |
| [Perimeter Security](perimeter.md) | Cloudflare Zero Trust, rate limiting, webhook validation |
| [Governance](governance.md) | Three-tier governance model |
| [Backup & Recovery](backup.md) | Encrypted backup automation |
| [Pilot Configuration](pilot.md) | Institutional pilot setup |

## Quick Reference

| Layer | Color | Port | Key Module |
|-------|:-----:|------|------------|
| Infrastructure | 🟢 | — | Docker Compose |
| Document Engine | 🔵 | — | `ingest/`, `parser/`, `transform/` |
| Secure Document Control | 🟣 | 3003 | `sdc/secureViewer.ts` |
| Signing Gateway | 🟡 | 3002 | `gateway/signingGateway.ts` |
| Sovereign Comms Agent | 🔴 | 3004 | `telecom/inboundRouter.ts` |
| Perimeter Security | 🟠 | — | `perimeter/tunnelManager.ts` |
| Ledger Systems | ⚫ | — | `sovereign/lifecycleRegistry.ts` |
| Ops & Monitoring | ⚙️ | 3005 | `sovereign/monitorDashboard.ts` |

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
