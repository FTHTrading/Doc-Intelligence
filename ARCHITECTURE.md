# Architecture

## System Overview

Doc-Intelligence is a multi-layered sovereign document infrastructure system. Each layer operates independently with well-defined interfaces, unified by hash-chained ledger systems that provide tamper-evident audit trails across every operation.

---

## Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL BOUNDARY                                │
│  Telnyx SMS/Voice ──→ Cloudflare Edge ──→ Cloudflare Tunnel            │
│                       (Zero Trust)         (No Exposed Ports)           │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
┌────────────────────────────────┼────────────────────────────────────────┐
│                        APPLICATION LAYER                                │
│                                │                                        │
│  ┌──────────────┐  ┌──────────┴──────────┐  ┌──────────────────────┐   │
│  │ 🔴 SCA       │  │ 🔵 DOCUMENT ENGINE  │  │ 🟣 SDC              │   │
│  │              │  │                     │  │                      │   │
│  │ inboundRouter│  │ ingest/detector     │  │ secureViewer         │   │
│  │ aiIntentEng  │  │ parser/pdf,docx,    │  │ watermarkEngine      │   │
│  │ actionEngine │  │   html,image        │  │ forensicFingerprint  │   │
│  │ responseCmps │  │ transform/governanc │  │ accessTokenService   │   │
│  │ convLedger   │  │   compliance,brand  │  │ exportPolicyEngine   │   │
│  │ telecomReg   │  │ export/multi-format │  │ accessLedger         │   │
│  └──────────────┘  │ signature/fingerprt │  │ documentIntakeEngine │   │
│                    │ canonicalizer       │  └──────────────────────┘   │
│                    └──────────┬──────────┘                              │
│                               │                                         │
│  ┌──────────────┐  ┌──────────┴──────────┐  ┌──────────────────────┐   │
│  │ 🟡 SIGNING   │  │ 🟠 PERIMETER       │  │ ⚫ LEDGER           │   │
│  │              │  │                     │  │                      │   │
│  │ signingGtwy  │  │ cloudflareConfig   │  │ lifecycleRegistry    │   │
│  │ signingSession│ │ tunnelManager      │  │ cidRegistry (IPFS)   │   │
│  │ otpEngine    │  │ webhookValidator   │  │ ledgerAnchor         │   │
│  │ distribution │  │ rateLimiter        │  │ ledgerAdapter        │   │
│  │ intentLogger │  │ perimeterLedger    │  │ backupLedger         │   │
│  └──────────────┘  └────────────────────┘  └──────────────────────┘   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ ⚙️ OPERATIONS                                                    │   │
│  │ backupAgent · monitorDashboard · Docker Compose · IPFS/Kubo     │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Document Processing Pipeline

```
Input File
    │
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│   INGEST    │────→│    PARSE    │────→│    CANONICALIZE      │
│ Format Det. │     │ Extract     │     │ Deterministic norm.  │
│ .pdf .docx  │     │ Structure   │     │ Volatile strip       │
│ .png .html  │     │ Metadata    │     │ Whitespace collapse  │
└─────────────┘     └─────────────┘     └──────────┬──────────┘
                                                    │
    ┌───────────────────────────────────────────────┘
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│  TRANSFORM  │────→│   EXPORT    │────→│   FINGERPRINT       │
│ Governance  │     │ JSON, MD    │     │ SHA-256 canonical    │
│ Compliance  │     │ HTML, PDF   │     │ Merkle root          │
│ Brand style │     │ Template    │     │ Version tracking     │
└─────────────┘     └─────────────┘     └──────────┬──────────┘
                                                    │
    ┌───────────────────────────────────────────────┘
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│    SIGN     │────→│   ENCRYPT   │────→│    IPFS PUSH        │
│ ESIGN/UETA │     │ AES-256-GCM │     │ Kubo pinning         │
│ Hash chain  │     │ PBKDF2 key  │     │ CID registry         │
│ Certificate │     │ derivation  │     │ Gateway verify       │
└─────────────┘     └─────────────┘     └──────────┬──────────┘
                                                    │
                                                    ▼
                                        ┌─────────────────────┐
                                        │   LEDGER ANCHOR     │
                                        │ Hash-chained entry   │
                                        │ Lifecycle registry   │
                                        │ Deterministic memo   │
                                        └─────────────────────┘
```

### Telecom Inbound Flow

```
SMS from Investor
    │
    ▼
Telnyx Webhook ──→ Cloudflare Edge ──→ Tunnel ──→ Webhook Validator
                                                        │
                                          ┌─────────────┘
                                          ▼
                                    Inbound Router
                                          │
                              ┌───────────┼───────────┐
                              ▼           ▼           ▼
                         Compliance   AI Intent    Direct
                         (STOP/HELP)  Engine       Route
                              │           │           │
                              ▼           ▼           ▼
                         Auto Reply   Action Eng   Handler
                              │           │           │
                              └─────┬─────┘───────────┘
                                    ▼
                            Conversation Ledger
                                    │
                                    ▼
                            Response Composer ──→ Telnyx SMS Out
```

---

## Module Inventory

### 🔵 Document Engine (`ingest/`, `parser/`, `transform/`, `export/`, `schema/`)

| Module | Purpose |
|--------|---------|
| `formatDetector.ts` | Detect input file format (PDF, DOCX, PNG, JPG, HTML, TXT, MD) |
| `pdfParser.ts` | Extract text and structure from PDF documents |
| `docxParser.ts` | Parse DOCX files using mammoth |
| `htmlParser.ts` | Parse HTML using cheerio |
| `imageParser.ts` | OCR extraction using Tesseract.js |
| `governanceTransform.ts` | Apply DAO governance sections |
| `complianceTransform.ts` | Apply compliance headers and disclosures |
| `brandTransform.ts` | Apply FTH brand styling |
| `templateExport.ts` | Multi-format output generation |

### 🟣 Secure Document Control (`sdc/`)

| Module | Purpose |
|--------|---------|
| `secureViewer.ts` | Protected document viewing server (port 3003) |
| `watermarkEngine.ts` | Invisible forensic watermark embedding |
| `forensicFingerprint.ts` | Per-recipient document fingerprinting |
| `accessTokenService.ts` | Time-limited, single-use access tokens |
| `exportPolicyEngine.ts` | Per-document export restrictions |
| `accessLedger.ts` | Hash-chained access event log |
| `documentIntakeEngine.ts` | Controlled document intake flow |

### 🟡 Signing Gateway (`gateway/`)

| Module | Purpose |
|--------|---------|
| `signingGateway.ts` | HTTP signing gateway server (port 3002) |
| `signingSession.ts` | Multi-sig session management |
| `otpEngine.ts` | OTP generation, delivery, and verification |
| `distributionEngine.ts` | Signed document distribution |
| `intentLogger.ts` | Signing intent recording |

### 🔴 Sovereign Comms Agent (`telecom/`)

| Module | Purpose |
|--------|---------|
| `inboundRouter.ts` | SMS/webhook routing and compliance filtering |
| `aiIntentEngine.ts` | Natural language intent classification |
| `actionEngine.ts` | Intent-to-action execution |
| `responseComposer.ts` | Contextual response generation |
| `conversationLedger.ts` | Hash-chained conversation log |
| `telecomRegistry.ts` | Carrier and number management |

### 🟠 Perimeter Security (`perimeter/`)

| Module | Purpose |
|--------|---------|
| `cloudflareConfig.ts` | Cloudflare Zero Trust configuration |
| `tunnelManager.ts` | Tunnel lifecycle management |
| `webhookValidator.ts` | HMAC signature verification + replay prevention |
| `rateLimiter.ts` | Per-IP and global rate limiting |
| `perimeterLedger.ts` | Hash-chained security event log |

### ⚫ Sovereign Infrastructure (`sovereign/`)

| Module | Purpose |
|--------|---------|
| `canonicalizer.ts` | Deterministic document normalization |
| `encryptedIPFS.ts` | AES-256-GCM encryption + IPFS push |
| `ledgerAnchor.ts` | Deterministic ledger memo anchoring |
| `ledgerAdapter.ts` | Multi-chain ledger abstraction |
| `lifecycleRegistry.ts` | Document lifecycle state tracking |
| `signatureCertificate.ts` | ESIGN/UETA certificate generation |
| `keyProvider.ts` | Cryptographic key management |
| `documentDiff.ts` | Document version diff engine |
| `backupAgent.ts` | Encrypted backup daemon (AES-256-GCM) |
| `monitorDashboard.ts` | Operator monitoring dashboard |

---

## Service Ports (Internal Only)

All ports are internal to the Docker network. No port is exposed to the public internet.

| Port | Service | Description |
|------|---------|-------------|
| 3001 | Sovereign Portal | Main portal + health endpoint |
| 3002 | Signing Gateway | Multi-sig signing ceremony |
| 3003 | Secure Viewer | SDC-protected document viewer |
| 3004 | SCA Webhook | Telnyx inbound webhook receiver |
| 3005 | Dashboard | Operator monitoring dashboard |
| 5001 | IPFS RPC | Kubo API (internal) |
| 8081 | IPFS Gateway | Kubo HTTP gateway (internal) |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Node.js v24+ |
| Language | TypeScript (ES2020, strict mode) |
| PDF Parsing | pdf-parse |
| DOCX Parsing | mammoth |
| HTML Parsing | cheerio |
| OCR | Tesseract.js |
| Image Processing | sharp |
| PDF Generation | Puppeteer (Chromium) |
| Encryption | Node.js crypto (AES-256-GCM, PBKDF2) |
| Distributed Storage | IPFS/Kubo v0.33.2 |
| Tunnel | Cloudflare cloudflared |
| Telecom | Telnyx SMS/Voice API |
| Containers | Docker Compose 3.9 |
| Base Image | node:22-bookworm-slim |

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
