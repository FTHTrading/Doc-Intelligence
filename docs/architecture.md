# 🔵 Document Engine — Architecture

## Pipeline

The document processing pipeline is a linear, deterministic flow:

```
Input → Ingest → Parse → Canonicalize → Transform → Export → Fingerprint → Sign → Encrypt → IPFS → Anchor
```

Every stage is stateless and reproducible. Given identical input, the pipeline produces identical output — verified across 20,000 hash computations with zero drift.

## Ingest Layer

**Module:** `ingest/formatDetector.ts`

Supported input formats:

| Format | Extension | Parser |
|--------|-----------|--------|
| PDF | `.pdf` | pdf-parse |
| DOCX | `.docx` | mammoth |
| HTML | `.html` | cheerio |
| PNG | `.png` | Tesseract.js (OCR) |
| JPG | `.jpg` | Tesseract.js (OCR) |
| Plain Text | `.txt` | Native |
| Markdown | `.md` | Native |

## Parse Layer

**Modules:** `parser/pdfParser.ts`, `parser/docxParser.ts`, `parser/htmlParser.ts`, `parser/imageParser.ts`

Extracts structured content:
- Sections and headings
- Body text with hierarchy
- Metadata (author, date, title)
- Tables and lists
- Embedded references

## Canonicalization

**Module:** `sovereign/canonicalizer.ts`

Deterministic normalization:
- Strip volatile fields (timestamps, hostnames, PIDs)
- Collapse whitespace runs
- Normalize Unicode
- Stabilize numeric precision
- Sort object keys deterministically

## Transform Layer

**Modules:** `transform/governanceTransform.ts`, `transform/complianceTransform.ts`, `transform/brandTransform.ts`

| Transform | Purpose |
|-----------|---------|
| Governance | Insert DAO governance sections, voting provisions |
| Compliance | Add regulatory headers, disclaimers, disclosures |
| Brand | Apply FTH Trading visual identity and styling |

## Export Layer

**Module:** `export/templateExport.ts`

Output formats: JSON, Markdown, HTML, PDF (via Puppeteer/Chromium)

## Fingerprinting

**Module:** `signature/documentFingerprint.ts`

- SHA-256 canonical fingerprint
- Merkle root computation (order-independent)
- Version tracking across document lifecycle

## Signing

**Module:** `sovereign/signatureCertificate.ts`

- Hash-chain signature
- ESIGN/UETA-compliant certificate
- Full certificate chain with signer identity, timestamp, and document hash

## Encryption & Storage

**Module:** `sovereign/encryptedIPFS.ts`

- AES-256-GCM encryption with PBKDF2 key derivation
- Push to IPFS/Kubo node
- CID registered in `sovereign/cidRegistry`
- Ledger anchor with deterministic memo

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
