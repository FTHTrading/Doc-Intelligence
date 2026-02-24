// ─────────────────────────────────────────────────────────────
// Document Intelligence Engine — Main Application Controller
// ─────────────────────────────────────────────────────────────
//
// Usage:
//   npx ts-node app.ts <file> [options]
//   npx ts-node app.ts --batch ./input [options]
//   npx ts-node app.ts --watch ./input [options]
//   npx ts-node app.ts --serve [options]
//
// Examples:
//   npx ts-node app.ts ./input/document.pdf
//   npx ts-node app.ts ./input/contract.docx --mode governance --brand fth
//   npx ts-node app.ts ./input/worksheet.png --mode compliance --pdf
//   npx ts-node app.ts ./input/memo.txt --mode brand --brand fth --pdf --docx
//   npx ts-node app.ts --batch ./input --mode brand --brand fth --pdf
//   npx ts-node app.ts --watch ./input --mode template
//   npx ts-node app.ts --serve --port 3000
//   npx ts-node app.ts --verify ./output
//
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import crypto from "crypto";
import http from "http";
import { ExportMode, DocumentObject } from "./schema/documentSchema";
import { ingestDocument } from "./ingest";
import { buildDocumentObject } from "./parser/sectionHierarchyBuilder";
import { suggestTransformations } from "./parser/semanticClassifier";
import { applyBranding } from "./transform/brandingEngine";
import { injectComplianceClauses, injectSignatureBlocks } from "./transform/clauseInjector";
import { exportHTML } from "./export/htmlExport";
import { exportPDF } from "./export/pdfExport";
import { exportDOCX } from "./export/docxExport";
import { exportJSON, generateFingerprint, exportFingerprint } from "./export/jsonExport";
import { compileProposal } from "./governance/proposalCompiler";
import { anchorDocument } from "./governance/onchainAnchor";
import { getBrand } from "./styles/brandConfig";
import { processBatch, printBatchSummary } from "./batch/batchProcessor";
import { watchDirectory } from "./batch/watchMode";
import { startWebServer } from "./web/server";
import { createArchive, verifyArchive } from "./archive/archiveBundler";
import { getIPFSClient } from "./ipfs/ipfsClient";
import { getRegistry } from "./registry/cidRegistry";
import { getEventLog } from "./registry/eventLog";
import { generateSKU, generateSKUFromMode } from "./registry/skuEngine";
import { getSignatureEngine, SignerIdentity } from "./signature/signatureEngine";
import { generateVerificationQR, generateQRHTMLBlock, QRPayload } from "./signature/qrGenerator";
import { buildAuditPackage, exportAuditJSON, exportAuditHTML } from "./signature/auditTrail";
// Research & Publication Layer
import { getKnowledgeMemory } from "./research/knowledgeMemory";
import { composePaper, paperToDocumentObject } from "./research/paperComposer";
import { formatBibliography, formatReferencesHTML } from "./research/formattingEngine";
import { simulatePeerReview, formatReviewSummary, formatReviewHTML } from "./research/peerReviewEngine";
import { PaperFormat, CitationStyle, ReviewerType } from "./schema/researchSchema";
// Agreement State Layer
import { getAgreementEngine } from "./agreements/agreementState";
import { createDocumentFolder, organizeOutputFiles, getFolderTree, generateFolderManifest } from "./agreements/folderManager";
// Sovereign Hardening Layer
import { canonicalizeDocument, canonicalHash, canonicalMerkleRoot, computeCanonicalFingerprint, verifyReplay, runHashStabilityTest } from "./sovereign/canonicalizer";
import { getLifecycleRegistry } from "./sovereign/lifecycleRegistry";
import { encryptBuffer, encryptWithSignerKey, decryptPayload, getKeyVault, EncryptedPayload } from "./sovereign/encryptedIPFS";
import { generateCertificate, generateCertificatesForState, verifyCertificate, formatCertificateText } from "./sovereign/signatureCertificate";
import { getLedgerAnchorEngine, buildAnchorMemo } from "./sovereign/ledgerAnchor";
import { MemoryConsolidationEngine } from "./research/memoryConsolidation";
import { getMemoryWeightEngine } from "./research/semanticWeighting";
import { getMultiSigEngine } from "./signature/multiSigWorkflow";
import { startSovereignPortal } from "./web/sovereignPortal";
import { diffDocuments, formatDiffReport } from "./sovereign/documentDiff";
import { generateWhitepaper, formatWhitepaperText } from "./research/whitepaperGenerator";
// Signing Gateway Layer
import { getSigningSessionEngine, ContactChannel } from "./gateway/signingSession";
import { getIntentLogger } from "./gateway/intentLogger";
import { getOTPEngine } from "./gateway/otpEngine";
import { DistributionEngine } from "./gateway/distributionEngine";
import { startSigningGateway } from "./gateway/signingGateway";
// Secure Document Control Layer
import { getDocumentIntakeEngine, DocumentClassification, RiskTier } from "./sdc/documentIntakeEngine";
import { getWatermarkEngine, WatermarkRecipient } from "./sdc/watermarkEngine";
import { getAccessTokenService } from "./sdc/accessTokenService";
import { getExportPolicyEngine, ExportFormat } from "./sdc/exportPolicyEngine";
import { getAccessLedger } from "./sdc/accessLedger";
import { getForensicFingerprintEngine } from "./sdc/forensicFingerprint";
import { startSecureViewer } from "./sdc/secureViewer";
// Sovereign Comms Agent (SCA) Layer
import { getTelecomRegistry, TelecomMode, NumberPurpose } from "./telecom/telecomRegistry";
import { getInboundRouter, sendTelnyxMessage } from "./telecom/inboundRouter";
import { getAIIntentEngine } from "./telecom/aiIntentEngine";
import { getActionEngine } from "./telecom/actionEngine";
import { getResponseComposer } from "./telecom/responseComposer";
import { getConversationLedger } from "./telecom/conversationLedger";
// Cloudflare Perimeter Security Layer
import { getCloudflareConfig } from "./perimeter/cloudflareConfig";
import { getTunnelManager } from "./perimeter/tunnelManager";
import { getWebhookValidator } from "./perimeter/webhookValidator";
import { getRateLimiter } from "./perimeter/rateLimiter";
import { getPerimeterLedger } from "./perimeter/perimeterLedger";
// Sovereign Operations Layer
import { getBackupAgent } from "./sovereign/backupAgent";
import { startDashboardServer, formatDashboard } from "./sovereign/monitorDashboard";

// ── CLI Argument Parsing ─────────────────────────────────────

interface CLIOptions {
  filePath: string;
  mode: ExportMode;
  brand: string;
  exportPDF: boolean;
  exportDOCX: boolean;
  anchor: string | null;
  outputDir: string;
  author: string;
  // Batch / watch / serve
  batch: boolean;
  watch: boolean;
  serve: boolean;
  verify: string | null;
  port: number;
  recursive: boolean;
  // Sovereignty layers
  sign: boolean;
  signerName: string;
  signerEmail: string;
  signerRole: string;
  sku: boolean;
  ipfsPush: boolean;
  registry: boolean;
  audit: boolean;
  qr: boolean;
  ipfsStatus: boolean;
  // Research & Publication Layer
  ingestMemory: boolean;
  memorySearch: string | null;
  memoryStats: boolean;
  paperType: PaperFormat | null;
  paperTitle: string | null;
  formatStyle: CitationStyle;
  peerReview: boolean;
  reviewers: ReviewerType[];
  // Agreement State Layer
  agreementStatus: boolean;
  agreementCreate: string | null;
  clientName: string | null;
  organizeFolder: boolean;
  // Sovereign Hardening Layer
  canonicalize: boolean;
  lifecycle: boolean;
  encrypt: boolean;
  signCert: boolean;
  ledgerAnchor: string | null;
  consolidateMemory: boolean;
  hashStability: boolean;
  lifecycleStatus: boolean;
  lifecycleReport: string | null;
  // Multi-Sig Workflow
  requireSignatures: number;
  counterparties: string[];
  sigOrdering: "strict" | "any";
  multiSigStatus: boolean;
  portal: boolean;
  portalPort: number;
  memoryWeights: boolean;
  // Document Diff Engine
  diffWith: string | null;
  // Whitepaper
  generateWhitepaper: boolean;
  // Signing Gateway Layer
  createSession: boolean;
  sessionSigners: string[];
  sessionChannels: ContactChannel[];
  sendSession: string | null;
  sessionStatus: string | null;
  gateway: boolean;
  gatewayPort: number;
  sessionThreshold: number;
  requireOTP: boolean;
  // Secure Document Control Layer
  sdcIntake: boolean;
  sdcClassify: string | null;
  sdcTokenIssue: boolean;
  sdcTokenRecipient: string | null;
  sdcExport: ExportFormat | null;
  sdcViewer: boolean;
  sdcViewerPort: number;
  sdcRevoke: string | null;
  sdcStatus: boolean;
  sdcLedger: string | null;
  sdcFingerprint: boolean;
  sdcIdentifyLeak: string | null;
  // Sovereign Comms Agent (SCA) Layer
  scaRegister: string | null;
  scaRegisterMode: TelecomMode | null;
  scaRegisterPurpose: NumberPurpose | null;
  scaRegisterEntity: string | null;
  scaStatus: boolean;
  scaWebhook: boolean;
  scaWebhookPort: number;
  scaSimulate: string | null;
  scaSimulateFrom: string | null;
  scaSend: string | null;
  scaSendTo: string | null;
  scaLedger: string | null;
  scaApprovals: boolean;
  scaApprove: string | null;
  scaReject: string | null;
  // Cloudflare Perimeter Security Layer
  perimeterStatus: boolean;
  perimeterLedger: string | null;
  perimeterConfig: boolean;
  tunnelStart: boolean;
  tunnelStop: boolean;
  tunnelStatus: boolean;
  tunnelSetup: boolean;
  tunnelDomain: string | null;
  tunnelId: string | null;
  // Sovereign Operations
  backupNow: boolean;
  backupDaemon: boolean;
  backupList: boolean;
  backupVerify: string | null;
  backupRestore: string | null;
  backupStatus: boolean;
  dashboard: boolean;
  dashboardPort: number;
  dashboardSnapshot: boolean;
}

function parseArgs(): CLIOptions {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  const getFlag = (flag: string): string | null => {
    const idx = args.indexOf(flag);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  };

  // Determine the file path: skip flags and their values
  let filePath = "";
  const flagsWithValues = new Set([
    "--mode", "--brand", "--anchor", "--output", "--author", "--port", "--verify",
    "--signer-name", "--signer-email", "--signer-role",
    "--memory-search", "--paper-type", "--paper-title", "--format-style",
    "--reviewers", "--agreement-create", "--client",
    "--ledger-anchor", "--lifecycle-report",
    "--require-signatures", "--counterparty", "--sig-ordering", "--portal-port",
    "--diff-with",
    "--send-session", "--session-status", "--gateway-port", "--session-threshold",
    "--session-channels", "--session-signer",
    "--sdc-classify", "--sdc-recipient", "--sdc-export", "--sdc-viewer-port",
    "--sdc-revoke", "--sdc-ledger", "--sdc-identify-leak",
    "--sca-register", "--sca-register-mode", "--sca-register-purpose", "--sca-register-entity",
    "--sca-webhook-port", "--sca-simulate", "--sca-simulate-from",
    "--sca-send", "--sca-send-to", "--sca-ledger", "--sca-approve", "--sca-reject",
    "--perimeter-ledger", "--tunnel-domain", "--tunnel-id",
    "--backup-verify", "--backup-restore", "--dashboard-port",
  ]);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      if (flagsWithValues.has(arg)) i++; // skip the value too
      continue;
    }
    filePath = arg;
    break;
  }

  return {
    filePath,
    mode: (getFlag("--mode") as ExportMode) || "template",
    brand: getFlag("--brand") || "clean",
    exportPDF: args.includes("--pdf"),
    exportDOCX: args.includes("--docx"),
    anchor: getFlag("--anchor"),
    outputDir: getFlag("--output") || "./output",
    author: getFlag("--author") || "System",
    batch: args.includes("--batch"),
    watch: args.includes("--watch"),
    serve: args.includes("--serve"),
    verify: getFlag("--verify"),
    port: parseInt(getFlag("--port") || "3000", 10),
    recursive: args.includes("--recursive"),
    // Sovereignty flags
    sign: args.includes("--sign"),
    signerName: getFlag("--signer-name") || getFlag("--author") || "System",
    signerEmail: getFlag("--signer-email") || "",
    signerRole: getFlag("--signer-role") || "author",
    sku: args.includes("--sku"),
    ipfsPush: args.includes("--ipfs-push") || args.includes("--ipfs"),
    registry: args.includes("--registry"),
    audit: args.includes("--audit"),
    qr: args.includes("--qr"),
    ipfsStatus: args.includes("--ipfs-status"),
    // Research & Publication flags
    ingestMemory: args.includes("--ingest-memory"),
    memorySearch: getFlag("--memory-search"),
    memoryStats: args.includes("--memory-stats"),
    paperType: (getFlag("--paper-type") as PaperFormat) || null,
    paperTitle: getFlag("--paper-title"),
    formatStyle: (getFlag("--format-style") as CitationStyle) || "apa",
    peerReview: args.includes("--peer-review"),
    reviewers: getFlag("--reviewers")
      ? (getFlag("--reviewers")!.split(",") as ReviewerType[])
      : ["academic", "legal", "technical", "economic"],
    // Agreement State flags
    agreementStatus: args.includes("--agreement-status"),
    agreementCreate: getFlag("--agreement-create"),
    clientName: getFlag("--client"),
    organizeFolder: args.includes("--organize"),
    // Sovereign Hardening flags
    canonicalize: args.includes("--canonicalize"),
    lifecycle: args.includes("--lifecycle"),
    encrypt: args.includes("--encrypt"),
    signCert: args.includes("--sign-cert"),
    ledgerAnchor: getFlag("--ledger-anchor"),
    consolidateMemory: args.includes("--consolidate-memory"),
    hashStability: args.includes("--hash-stability"),
    lifecycleStatus: args.includes("--lifecycle-status"),
    lifecycleReport: getFlag("--lifecycle-report"),
    // Multi-Sig Workflow
    requireSignatures: parseInt(getFlag("--require-signatures") || "0", 10),
    counterparties: args.reduce<string[]>((acc, arg, i) => {
      if (arg === "--counterparty" && i + 1 < args.length) acc.push(args[i + 1]);
      return acc;
    }, []),
    sigOrdering: (getFlag("--sig-ordering") as "strict" | "any") || "any",
    multiSigStatus: args.includes("--multisig-status"),
    portal: args.includes("--portal"),
    portalPort: parseInt(getFlag("--portal-port") || "3001", 10),
    memoryWeights: args.includes("--memory-weights"),
    // Document Diff Engine
    diffWith: getFlag("--diff-with"),
    // Whitepaper
    generateWhitepaper: args.includes("--whitepaper"),
    // Signing Gateway Layer
    createSession: args.includes("--create-session"),
    sessionSigners: args.reduce<string[]>((acc, arg, i) => {
      if (arg === "--session-signer" && i + 1 < args.length) acc.push(args[i + 1]);
      return acc;
    }, []),
    sessionChannels: (getFlag("--session-channels") || "email").split(",") as ContactChannel[],
    sendSession: getFlag("--send-session"),
    sessionStatus: getFlag("--session-status"),
    gateway: args.includes("--gateway"),
    gatewayPort: parseInt(getFlag("--gateway-port") || "3002", 10),
    sessionThreshold: parseInt(getFlag("--session-threshold") || "0", 10),
    requireOTP: args.includes("--require-otp"),
    // Secure Document Control Layer
    sdcIntake: args.includes("--sdc-intake"),
    sdcClassify: getFlag("--sdc-classify"),
    sdcTokenIssue: args.includes("--sdc-token"),
    sdcTokenRecipient: getFlag("--sdc-recipient"),
    sdcExport: (getFlag("--sdc-export") as ExportFormat) || null,
    sdcViewer: args.includes("--sdc-viewer"),
    sdcViewerPort: parseInt(getFlag("--sdc-viewer-port") || "3003", 10),
    sdcRevoke: getFlag("--sdc-revoke"),
    sdcStatus: args.includes("--sdc-status"),
    sdcLedger: getFlag("--sdc-ledger"),
    sdcFingerprint: args.includes("--sdc-fingerprint"),
    sdcIdentifyLeak: getFlag("--sdc-identify-leak"),
    // Sovereign Comms Agent (SCA) Layer
    scaRegister: getFlag("--sca-register"),
    scaRegisterMode: (getFlag("--sca-register-mode") as TelecomMode) || null,
    scaRegisterPurpose: (getFlag("--sca-register-purpose") as NumberPurpose) || null,
    scaRegisterEntity: getFlag("--sca-register-entity"),
    scaStatus: args.includes("--sca-status"),
    scaWebhook: args.includes("--sca-webhook"),
    scaWebhookPort: parseInt(getFlag("--sca-webhook-port") || "3004", 10),
    scaSimulate: getFlag("--sca-simulate"),
    scaSimulateFrom: getFlag("--sca-simulate-from"),
    scaSend: getFlag("--sca-send"),
    scaSendTo: getFlag("--sca-send-to"),
    scaLedger: getFlag("--sca-ledger"),
    scaApprovals: args.includes("--sca-approvals"),
    scaApprove: getFlag("--sca-approve"),
    scaReject: getFlag("--sca-reject"),
    // Cloudflare Perimeter Security Layer
    perimeterStatus: args.includes("--perimeter-status"),
    perimeterLedger: getFlag("--perimeter-ledger"),
    perimeterConfig: args.includes("--perimeter-config"),
    tunnelStart: args.includes("--tunnel-start"),
    tunnelStop: args.includes("--tunnel-stop"),
    tunnelStatus: args.includes("--tunnel-status"),
    tunnelSetup: args.includes("--tunnel-setup"),
    tunnelDomain: getFlag("--tunnel-domain"),
    tunnelId: getFlag("--tunnel-id"),
    // Sovereign Operations
    backupNow: args.includes("--backup-now"),
    backupDaemon: args.includes("--backup-daemon"),
    backupList: args.includes("--backup-list"),
    backupVerify: getFlag("--backup-verify"),
    backupRestore: getFlag("--backup-restore"),
    backupStatus: args.includes("--backup-status"),
    dashboard: args.includes("--dashboard"),
    dashboardPort: parseInt(getFlag("--dashboard-port") || "3005", 10),
    dashboardSnapshot: args.includes("--dashboard-snapshot"),
  };
}

function printHelp(): void {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║         DOCUMENT INTELLIGENCE ENGINE v4.0.0                 ║
║         Sovereign Knowledge Production Engine               ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
  npx ts-node app.ts <file> [options]
  npx ts-node app.ts --batch <dir> [options]
  npx ts-node app.ts --watch <dir> [options]
  npx ts-node app.ts --serve [options]
  npx ts-node app.ts --verify <dir>
  npx ts-node app.ts --ipfs-status
  npx ts-node app.ts --memory-stats
  npx ts-node app.ts --memory-search <query>
  npx ts-node app.ts --agreement-status
  npx ts-node app.ts --lifecycle-status
  npx ts-node app.ts --consolidate-memory
  npx ts-node app.ts --hash-stability
  npx ts-node app.ts --paper-type <type> --paper-title <title>

CORE OPTIONS:
  --mode <mode>       Export mode (default: template)
                      template | governance | compliance | brand | web | archive

  --brand <name>      Brand config to apply (default: clean)
                      fth | clean

  --pdf               Also export as PDF
  --docx              Also export as DOCX (XML)
  --output <dir>      Output directory (default: ./output)
  --author <name>     Author name (default: System)

SOVEREIGNTY LAYER:
  --ipfs-push         Push document to IPFS (via local Kubo node)
  --ipfs              Alias for --ipfs-push
  --ipfs-status       Show IPFS node status and exit

  --sku               Generate sovereign document identity code
                      e.g. BOND-INDENTURE-US-2026-V1-8F3A

  --sign              Sign document with digital signature
  --signer-name       Signer full name (default: --author value)
  --signer-email      Signer email address
  --signer-role       Signer role: author | approver | witness | notary

  --registry          Register document in CID registry
  --qr                Generate verification QR code
  --audit             Generate full audit trail package (JSON + HTML)

  --anchor <chain>    Anchor document hash on-chain
                      xrpl | stellar | ethereum | polygon | ipfs

RESEARCH & PUBLICATION:
  --ingest-memory     Ingest file into persistent knowledge memory
  --memory-stats      Show knowledge memory statistics and exit
  --memory-search <q> Search knowledge memory for a query and exit

  --paper-type <type> Compose a paper from knowledge memory
                      academic | whitepaper | regulatory
  --paper-title <t>   Title for composed paper (required with --paper-type)
  --format-style <s>  Citation formatting style (default: apa)
                      apa | mla | chicago | ieee | bluebook | sec | arxiv | grant | board-memo

  --peer-review       Run peer review simulation on output document
  --reviewers <list>  Comma-separated reviewer types (default: all)
                      academic,legal,technical,economic

AGREEMENT ENGINE:
  --agreement-create <name>  Create a new agreement state for this document
  --agreement-status         Show all agreement statuses and exit
  --client <name>            Client name for folder organization
  --organize                 Organize output files into structured folders

SOVEREIGN HARDENING:
  --canonicalize             Run deterministic canonical serialization
  --lifecycle                Track document through full lifecycle registry
  --encrypt                  Encrypt document content (AES-256-GCM) before IPFS push
  --sign-cert                Generate ESIGN/UETA signature certificate
  --ledger-anchor <chain>    Deterministic ledger anchor with memo embedding
                             xrpl | stellar | ethereum | polygon | ipfs
  --hash-stability           Run hash stability test suite (standalone) and exit
  --lifecycle-status         Show lifecycle registry status and exit
  --lifecycle-report <id>    Show full lifecycle report for a document and exit
  --consolidate-memory       Run memory consolidation engine and exit
  --memory-weights           Compute semantic memory weights and exit

MULTI-SIGNATURE WORKFLOW:
  --require-signatures <N>   Require N signatures before finalization
  --counterparty <email>     Add counterparty (repeatable for multiple)
  --sig-ordering <mode>      strict (ordered) or any (parallel, default)
  --multisig-status          Show active multi-sig workflows and exit
  --portal                   Launch Sovereign Portal (signing/verification HTTP server)
  --portal-port <N>          Portal port (default: 3001)

DOCUMENT DIFF ENGINE:
  --diff-with <path>         Compare input file against another document (forensic diff)

WHITEPAPER:
  --whitepaper               Auto-generate sovereign architecture whitepaper and exit

SIGNING GATEWAY:
  --gateway                  Launch Signing Gateway HTTP server (port 3002)
  --gateway-port <N>         Gateway port (default: 3002)
  --create-session           Create a signing session for the input document
  --session-signer <spec>    Add signer (format: name:email:role, repeatable)
  --session-channels <list>  Comma-separated channels: email,sms,whatsapp,telegram,qr
  --session-threshold <N>    Required signatures (default: all required signers)
  --require-otp              Require OTP verification before signing
  --send-session <id>        Distribute signing links for session ID
  --session-status <id>      Show session status and exit

SECURE DOCUMENT CONTROL (SDC):
  --sdc-intake               Run document through SDC intake (classify, risk-tier, assign policy)
  --sdc-classify <type>      Override auto-classification (legal, financial, compliance, ip, etc.)
  --sdc-token                Issue access token for recipient
  --sdc-recipient <spec>     Recipient (format: name:email:org for --sdc-token / --sdc-export)
  --sdc-export <format>      Controlled export (pdf, html, docx, json)
  --sdc-fingerprint          Apply forensic fingerprint (zero-width, homoglyph, spacing)
  --sdc-viewer               Launch SDC Secure Viewer HTTP server (port 3003)
  --sdc-viewer-port <N>      Secure viewer port (default: 3003)
  --sdc-revoke <id>          Revoke document or token by ID
  --sdc-status               Show SDC status (intake, tokens, ledger stats) and exit
  --sdc-ledger <id>          Show access ledger for document ID (or 'all' / 'report') and exit
  --sdc-identify-leak <id>   Run forensic leak identification for document ID

BATCH & AUTOMATION:
  --batch             Process all documents in a directory
  --recursive         Include subdirectories (with --batch)
  --watch             Watch directory for new/changed files
  --serve             Launch web dashboard
  --port <number>     Web server port (default: 3000)
  --verify <dir>      Verify archive integrity

  --help, -h          Show this help message

SUPPORTED INPUT FORMATS:
  PDF (.pdf)          DOCX (.docx, .doc)
  PNG (.png)          JPG (.jpg, .jpeg)
  HTML (.html, .htm)  TXT (.txt)
  Markdown (.md)

EXAMPLES:
  npx ts-node app.ts ./input/contract.pdf --sku --ipfs-push --registry --audit
  npx ts-node app.ts ./input/bond.docx --mode governance --sign --qr --audit
  npx ts-node app.ts ./input/nda.pdf --sign --signer-name "John" --signer-email "j@co.io"
  npx ts-node app.ts --batch ./input --mode brand --brand fth --sku --ipfs-push
  npx ts-node app.ts --ipfs-status

  RESEARCH:
  npx ts-node app.ts ./input/paper.pdf --ingest-memory
  npx ts-node app.ts --memory-stats
  npx ts-node app.ts --memory-search "blockchain governance"
  npx ts-node app.ts --paper-type whitepaper --paper-title "Sovereign Infrastructure"
  npx ts-node app.ts ./input/draft.pdf --peer-review --reviewers academic,legal

  AGREEMENTS:
  npx ts-node app.ts ./input/contract.pdf --agreement-create "NDA-Acme" --sku --sign
  npx ts-node app.ts --agreement-status
  npx ts-node app.ts ./input/contract.pdf --organize --client "Acme Corp"

  SOVEREIGN HARDENING:
  npx ts-node app.ts ./input/doc.pdf --canonicalize --lifecycle --sign --encrypt --ipfs
  npx ts-node app.ts ./input/doc.pdf --sign --sign-cert --ledger-anchor ipfs
  npx ts-node app.ts --hash-stability
  npx ts-node app.ts --lifecycle-status
  npx ts-node app.ts --consolidate-memory

  MULTI-SIGNATURE:
  npx ts-node app.ts ./input/contract.pdf --sign --require-signatures 3 --counterparty alice@co.io --counterparty bob@co.io
  npx ts-node app.ts --multisig-status

  SECURE DOCUMENT CONTROL:
  npx ts-node app.ts ./input/contract.pdf --sdc-intake --sdc-fingerprint
  npx ts-node app.ts ./input/nda.pdf --sdc-intake --sdc-classify legal --sdc-token --sdc-recipient "John:john@co.io:Acme"
  npx ts-node app.ts ./input/term-sheet.pdf --sdc-intake --sdc-export pdf --sdc-recipient "Jane:jane@co.io:MegaCorp"
  npx ts-node app.ts --sdc-status
  npx ts-node app.ts --sdc-ledger all
  npx ts-node app.ts --sdc-viewer

SOVEREIGN COMMS AGENT (SCA):
  --sca-register <number>    Register a Telnyx number in the SCA registry
  --sca-register-mode <m>    Mode: INFRA, ISSUER, VENUE, ONBOARDING, CUSTODY, DEAL
  --sca-register-purpose <p> Purpose: signing, onboarding, compliance, deal-routing, etc.
  --sca-register-entity <e>  Entity binding (e.g. "FTH Trading")
  --sca-status               Show SCA registry, ledger, and approval stats
  --sca-webhook              Launch SCA inbound webhook server
  --sca-webhook-port <N>     Webhook port (default: 3004)
  --sca-simulate <text>      Simulate an inbound SMS (for testing)
  --sca-simulate-from <num>  Sender phone for simulation (default: +15551234567)
  --sca-send <text>          Send outbound SMS
  --sca-send-to <number>     Recipient for outbound SMS
  --sca-ledger <filter>      Show conversation ledger (all, report, or phone number)
  --sca-approvals            Show pending Tier 2 approvals
  --sca-approve <id>         Approve a pending action
  --sca-reject <id>          Reject a pending action

EXAMPLES (SCA):
  npx ts-node app.ts --sca-register "+15551234567" --sca-register-mode INFRA --sca-register-purpose signing --sca-register-entity "FTH Trading"
  npx ts-node app.ts --sca-status
  npx ts-node app.ts --sca-simulate "STATUS" --sca-simulate-from "+15559876543"
  npx ts-node app.ts --sca-send "Your signing link is ready" --sca-send-to "+15559876543"
  npx ts-node app.ts --sca-ledger all
  npx ts-node app.ts --sca-approvals
  npx ts-node app.ts --sca-webhook

CLOUDFLARE PERIMETER SECURITY:
  --perimeter-status         Show perimeter security status (WAF, tunnel, rate limiter, ledger)
  --perimeter-config         Show current Cloudflare perimeter configuration
  --perimeter-ledger <f>     Show perimeter security ledger (all, recent, report)
  --tunnel-start             Start Cloudflare Tunnel (requires cloudflared)
  --tunnel-stop              Stop Cloudflare Tunnel
  --tunnel-status            Show tunnel status and route health
  --tunnel-setup             Generate tunnel setup guide
  --tunnel-domain <domain>   Set base domain (e.g. fthtrading.com)
  --tunnel-id <id>           Set Cloudflare Tunnel ID

EXAMPLES (PERIMETER):
  npx ts-node app.ts --perimeter-status
  npx ts-node app.ts --perimeter-config
  npx ts-node app.ts --tunnel-setup
  npx ts-node app.ts --tunnel-domain "fthtrading.com" --tunnel-id "abc123"
  npx ts-node app.ts --tunnel-start
  npx ts-node app.ts --tunnel-status
  npx ts-node app.ts --perimeter-ledger recent

SOVEREIGN OPERATIONS:
  --backup-now               Create an encrypted ledger backup immediately
  --backup-daemon            Start backup daemon (runs every 15 min)
  --backup-list              List all available backups
  --backup-verify <file>     Verify a backup archive's integrity
  --backup-restore <file>    Restore ledger data from a backup (DESTRUCTIVE)
  --backup-status            Show backup agent status and history
  --dashboard                Launch operator monitoring dashboard (port 3005)
  --dashboard-port <N>       Dashboard port (default: 3005)
  --dashboard-snapshot       Print JSON system snapshot and exit

EXAMPLES (OPS):
  npx ts-node app.ts --backup-now
  npx ts-node app.ts --backup-daemon
  npx ts-node app.ts --backup-list
  npx ts-node app.ts --backup-status
  npx ts-node app.ts --dashboard
  npx ts-node app.ts --dashboard-snapshot
  `);
}

// ── Main Pipeline ────────────────────────────────────────────

async function main(): Promise<void> {
  const options = parseArgs();

  // ── Special modes (no file required) ────────────────────────

  // IPFS node status
  if (options.ipfsStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  IPFS NODE STATUS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const ipfs = getIPFSClient();
    const online = await ipfs.isOnline();
    if (!online) {
      console.log("  Status: OFFLINE — Kubo node not reachable at localhost:5001");
      process.exit(1);
    }
    const info = await ipfs.getNodeInfo();
    const stats = await ipfs.getStats();
    console.log(`  Status: ONLINE`);
    console.log(`  Peer ID: ${info.id}`);
    console.log(`  Agent: ${info.agentVersion}`);
    console.log(`  Addresses: ${info.addresses.length}`);
    console.log(`  Repo Size: ${(stats.repoSize / (1024 * 1024)).toFixed(1)} MiB`);
    console.log(`  Objects: ${stats.numObjects}`);
    console.log("");
    process.exit(0);
  }

  // Knowledge Memory stats
  if (options.memoryStats) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  KNOWLEDGE MEMORY — STATISTICS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const memory = getKnowledgeMemory();
    const stats = memory.getStats();
    console.log(`  Total nodes: ${stats.totalNodes}`);
    console.log(`  Source types: ${Object.entries(stats.bySourceType).map(([k, v]) => `${k}(${v})`).join(", ") || "none"}`);
    console.log(`  Topics: ${Object.entries(stats.byTopic).map(([k, v]) => `${k}(${v})`).join(", ") || "none"}`);
    console.log(`  Total evidence fragments: ${stats.totalEvidence}`);
    console.log(`  Total citations: ${stats.totalCitations}`);
    if (stats.newestNode) {
      console.log(`  Last ingested: ${stats.newestNode}`);
    }
    console.log("");
    process.exit(0);
  }

  // Knowledge Memory search
  if (options.memorySearch) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log(`  KNOWLEDGE MEMORY — SEARCH: "${options.memorySearch}"`);
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const memory = getKnowledgeMemory();
    const results = memory.search(options.memorySearch);
    if (results.length === 0) {
      console.log("  No matching nodes found.");
    } else {
      for (const node of results) {
        console.log(`  [${node.sourceType.toUpperCase()}] ${node.title}`);
        console.log(`    Topic: ${node.topic} | Keywords: ${node.keywords.slice(0, 5).join(", ")}`);
        console.log(`    Evidence: ${node.supportingEvidence.length} fragments | Citations: ${node.citations.length}`);
        console.log(`    Ingested: ${node.ingestedAt}`);
        console.log("");
      }
      console.log(`  Total results: ${results.length}`);
    }
    console.log("");
    process.exit(0);
  }

  // Lifecycle registry status
  if (options.lifecycleStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  DOCUMENT LIFECYCLE REGISTRY — STATUS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const registry = getLifecycleRegistry();
    const stats = registry.getStats();
    console.log(`  Total documents: ${stats.totalDocuments}`);
    console.log(`  By stage: ${Object.entries(stats.byStage).filter(([,v]) => (v as number) > 0).map(([k,v]) => `${k}(${v})`).join(", ") || "none"}`);
    console.log(`  Integrity: ${stats.securedCount}/${stats.totalDocuments} secured`);
    if (stats.signedCount > 0) console.log(`    Signed: ${stats.signedCount} | Encrypted: ${stats.encryptedCount} | Anchored: ${stats.anchoredCount}`);
    console.log("");
    const all = registry.getAllLifecycles();
    for (const lc of all) {
      console.log(`  [${lc.currentStage.toUpperCase()}] ${lc.title || lc.sourceFile}`);
      console.log(`    ID: ${lc.documentId.substring(0, 12)}... | Version: ${lc.version}`);
      if (lc.sku) console.log(`    SKU: ${lc.sku}`);
      console.log(`    Transitions: ${lc.transitions.length}`);
      console.log("");
    }
    process.exit(0);
  }

  // Multi-sig workflow status (standalone)
  if (options.multiSigStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  MULTI-SIGNATURE WORKFLOWS — STATUS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const msEngine = getMultiSigEngine();
    const stats = msEngine.getStats();
    console.log(`  Total workflows: ${stats.totalWorkflows}`);
    console.log(`  By status: ${Object.entries(stats.byStatus).map(([k,v]) => `${k}(${v})`).join(", ") || "none"}`);
    console.log(`  Avg signatures: ${stats.averageSignatures.toFixed(1)}`);
    console.log(`  Completion rate: ${(stats.completionRate * 100).toFixed(0)}%`);
    console.log("");
    const active = msEngine.getActiveWorkflows();
    for (const w of active) {
      console.log(`  [${w.status.toUpperCase()}] ${w.documentId.substring(0, 12)}...`);
      console.log(`    Workflow: ${w.workflowId.substring(0, 12)}...`);
      console.log(`    Threshold: ${w.signatureCount}/${w.config.requiredSignatures}`);
      console.log(`    Counterparties: ${w.counterparties.length}`);
      const pending = w.counterparties.filter(c => !c.signedAt && !c.rejectedAt);
      if (pending.length > 0) {
        console.log(`    Awaiting: ${pending.map(c => c.email).join(", ")}`);
      }
      console.log("");
    }
    if (active.length === 0) {
      console.log("  No active workflows.");
      console.log("");
    }
    process.exit(0);
  }

  // Lifecycle report for a specific document
  if (options.lifecycleReport) {
    console.log("");
    const registry = getLifecycleRegistry();
    const report = registry.generateReport(options.lifecycleReport);
    if (!report) {
      console.log(`  Document "${options.lifecycleReport}" not found in lifecycle registry.`);
      process.exit(1);
    }
    console.log(report);
    process.exit(0);
  }

  // Hash stability test
  if (options.hashStability) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  HASH STABILITY TEST SUITE");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    // Build a test document from an existing lifecycle or a synthetic one
    const testDoc: DocumentObject = {
      metadata: {
        title: "Hash Stability Test",
        type: "txt" as const,
        pageCount: 1,
        sourceFile: "synthetic-test",
        ingestedAt: new Date().toISOString(),
        language: "en",
      },
      structure: [
        { id: "test-1", type: "paragraph" as any, depth: 0, label: "Section One", content: "This is deterministic test content for hash stability verification.", children: [], style: {} } as any,
        { id: "test-2", type: "paragraph" as any, depth: 0, label: "Section Two", content: "  Multiple   spaces   and   whitespace   variations.  ", children: [], style: {} } as any,
      ],
      semanticTags: ["test", "stability", "canonical"],
      components: [],
      styles: { primaryFont: "serif", secondaryFont: "sans-serif", headingSize: "18px", bodySize: "12px", primaryColor: "#000", secondaryColor: "#333", accentColor: "#007", backgroundColor: "#fff", lineHeight: "1.5" },
    };
    const result = runHashStabilityTest(testDoc, 100);
    console.log(`  Rounds: ${result.rounds}`);
    console.log(`  Stable: ${result.stable ? "YES — ALL HASHES IDENTICAL" : "NO — HASH DRIFT DETECTED"}`);
    console.log(`  Hash: ${result.hashes[0]}`);
    console.log(`  Merkle Root: ${result.merkleRoots[0]}`);
    if (result.driftRound !== undefined) {
      console.log(`  Drift at round: ${result.driftRound}`);
    }
    console.log("");
    process.exit(result.stable ? 0 : 1);
  }

  // Memory consolidation (standalone)
  if (options.consolidateMemory) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  MEMORY CONSOLIDATION ENGINE");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const memory = getKnowledgeMemory();
    const consolidator = new MemoryConsolidationEngine(memory);
    const report = consolidator.consolidate();
    console.log(`  Nodes: ${report.stats.totalNodes}`);
    console.log(`  Evidence: ${report.stats.totalEvidence}`);
    console.log(`  Citations: ${report.stats.totalCitations}`);
    console.log(`  Cross-refs: ${report.stats.totalCrossRefs}`);
    console.log("");
    console.log("  CLUSTERS:");
    for (const c of report.clusters) {
      console.log(`    [${c.domain}] ${c.nodeCount} nodes, ${c.totalEvidence} evidence, coherence: ${c.coherence.toFixed(2)}`);
    }
    console.log("");
    if (report.duplicates.length > 0) {
      console.log(`  DUPLICATES: ${report.duplicates.length} groups detected`);
      for (const d of report.duplicates) {
        console.log(`    Primary: ${d.primaryNodeId} + ${d.duplicateNodeIds.length} duplicates (${d.method}, ${d.similarity.toFixed(2)})`);
      }
      console.log("");
    }
    if (report.contradictions.length > 0) {
      console.log(`  CONTRADICTIONS: ${report.contradictions.length} detected`);
      for (const c of report.contradictions) {
        console.log(`    ${c.type}: ${c.description}`);
      }
      console.log("");
    }
    console.log(`  TOP CONCEPTS:`);
    for (const c of report.topConcepts.slice(0, 10)) {
      console.log(`    ${c.concept} (freq: ${c.frequency}, nodes: ${c.nodeIds.length})`);
    }
    console.log("");
    console.log(`  CONFIDENCE SCORES:`);
    for (const s of report.confidenceScores) {
      console.log(`    [${s.score}/100] ${s.title}`);
    }
    console.log("");
    console.log(`  Actions taken: ${report.actions.length}`);
    console.log(`  Report hash: ${report.reportHash.substring(0, 16)}...`);
    console.log("");
    process.exit(0);
  }

  // Memory weighting (standalone)
  if (options.memoryWeights) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SEMANTIC MEMORY WEIGHT ENGINE");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const weightEngine = getMemoryWeightEngine();
    const weightReport = weightEngine.computeWeights();
    console.log(weightEngine.formatReport(weightReport));
    process.exit(0);
  }

  // Whitepaper generation (standalone)
  if (options.generateWhitepaper) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN ARCHITECTURE WHITEPAPER GENERATOR");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const wpDoc = generateWhitepaper({ author: options.author });
    console.log(formatWhitepaperText(wpDoc));

    // Also export to output dir
    const wpOutDir = options.outputDir || "./output";
    if (!fs.existsSync(wpOutDir)) {
      fs.mkdirSync(wpOutDir, { recursive: true });
    }
    const wpJsonPath = path.join(wpOutDir, "whitepaper.json");
    fs.writeFileSync(wpJsonPath, JSON.stringify(wpDoc, null, 2));
    console.log(`  [SAVED] ${wpJsonPath}`);

    // Export HTML
    const brand = getBrand(options.brand);
    const { htmlPath: wpHtmlPath } = await exportHTML(wpDoc, wpOutDir, { brand });
    console.log(`  [SAVED] ${wpHtmlPath}`);
    console.log("");
    process.exit(0);
  }

  // Agreement status report
  if (options.agreementStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  AGREEMENT STATE ENGINE — STATUS REPORT");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const engine = getAgreementEngine();
    const allAgreements = engine.getAllAgreements();
    if (allAgreements.length === 0) {
      console.log("  No agreements tracked.");
    } else {
      for (const ag of allAgreements) {
        console.log(`  [${ag.status.toUpperCase()}] ${ag.title}`);
        console.log(`    ID: ${ag.agreementId.substring(0, 12)}...`);
        if (ag.sku) console.log(`    SKU: ${ag.sku}`);
        console.log(`    Parties: ${ag.parties.map(p => p.name).join(", ") || "none"}`);
        const pendingObs = ag.obligations.filter(o => o.status === "pending" || o.status === "overdue");
        const fulfilledObs = ag.obligations.filter(o => o.status === "fulfilled");
        console.log(`    Obligations: ${ag.obligations.length} (fulfilled: ${fulfilledObs.length}, pending/overdue: ${pendingObs.length})`);
        const paidTriggers = ag.paymentTriggers.filter(p => p.status === "paid");
        console.log(`    Payments: ${ag.paymentTriggers.length} (confirmed: ${paidTriggers.length})`);
        console.log(`    Created: ${ag.createdAt}`);
        console.log("");
      }
      const stats = engine.getStats();
      console.log(`  Total agreements: ${stats.total}`);
      console.log(`  By status: ${Object.entries(stats.byStatus).filter(([,v]) => (v as number) > 0).map(([k,v]) => `${k}(${v})`).join(", ")}`);
    }
    console.log("");
    process.exit(0);
  }

  // Paper composition (standalone — no input file needed)
  if (options.paperType && !options.filePath) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log(`  PAPER COMPOSER — ${options.paperType.toUpperCase()}`);
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const memory = getKnowledgeMemory();
    const nodes = memory.getAllNodes();
    if (nodes.length === 0) {
      console.log("  [ERROR] Knowledge memory is empty. Ingest documents first with --ingest-memory.");
      process.exit(1);
    }
    const title = options.paperTitle || `${options.paperType.charAt(0).toUpperCase() + options.paperType.slice(1)} Paper`;
    const paper = composePaper({
      title,
      format: options.paperType,
      sourceNodes: nodes,
      authors: [options.author],
      citationStyle: options.formatStyle,
    });
    const doc = paperToDocumentObject(paper);

    // Export
    if (!fs.existsSync(options.outputDir)) {
      fs.mkdirSync(options.outputDir, { recursive: true });
    }
    const brand = getBrand(options.brand);
    await exportHTML(doc, options.outputDir, { brand });
    await exportJSON(doc, options.outputDir);

    // Bibliography
    const struct = paper.structure as any;
    const paperCitations: import("./schema/researchSchema").Citation[] = struct.references || [];
    const bibText = formatBibliography(paperCitations, options.formatStyle);
    const bibPath = path.join(options.outputDir, "bibliography.txt");
    fs.writeFileSync(bibPath, bibText, "utf-8");

    const bibHTML = formatReferencesHTML(paperCitations, options.formatStyle);
    const bibHTMLPath = path.join(options.outputDir, "bibliography.html");
    fs.writeFileSync(bibHTMLPath, bibHTML, "utf-8");

    console.log(`  Title: ${paper.title}`);
    console.log(`  Format: ${paper.format}`);
    console.log(`  Word count: ${paper.wordCount.total}`);
    console.log(`  Citations: ${paperCitations.length}`);
    console.log(`  Output: ${path.resolve(options.outputDir)}`);
    console.log("");

    // Optional peer review
    if (options.peerReview) {
      console.log("─── PEER REVIEW ────────────────────────────────────");
      const reviewPkg = simulatePeerReview(paper, {
        reviewers: options.reviewers,
      });
      const summary = formatReviewSummary(reviewPkg);
      console.log(summary);

      const reviewHTML = formatReviewHTML(reviewPkg);
      const reviewPath = path.join(options.outputDir, "peer-review.html");
      fs.writeFileSync(reviewPath, reviewHTML, "utf-8");
      console.log(`  Review report → ${reviewPath}`);
      console.log("");
    }

    process.exit(0);
  }

  // Verify archive
  if (options.verify) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  ARCHIVE VERIFICATION");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const result = verifyArchive(options.verify);
    console.log(`  Files checked: ${result.checked}`);
    if (result.valid) {
      console.log("  Status: VALID — all files intact");
    } else {
      console.log("  Status: COMPROMISED");
      for (const err of result.errors) {
        console.log(`    - ${err}`);
      }
    }
    console.log("");
    process.exit(result.valid ? 0 : 1);
  }

  // Serve dashboard
  if (options.serve) {
    startWebServer({
      port: options.port,
      outputDir: options.outputDir,
      brand: options.brand,
    });
    return; // Keep process alive
  }

  // Sovereign Portal
  if (options.portal) {
    startSovereignPortal({ port: options.portalPort });
    return; // Keep process alive
  }

  // Signing Gateway
  if (options.gateway) {
    startSigningGateway({ port: options.gatewayPort });
    return; // Keep process alive
  }

  // Session status (standalone)
  if (options.sessionStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SIGNING SESSION — STATUS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const sessEngine = getSigningSessionEngine();
    sessEngine.expireStale();

    if (options.sessionStatus === "all") {
      const stats = sessEngine.getStats();
      console.log(`  Total sessions: ${stats.total}`);
      console.log(`  Active: ${stats.active} | Completed: ${stats.completed} | Expired: ${stats.expired}`);
      console.log(`  Total signatures: ${stats.totalSignatures}`);
      console.log("");
      const all = sessEngine.getAllSessions();
      for (const s of all) {
        console.log(sessEngine.formatSessionSummary(s));
        console.log("");
      }
    } else {
      const session = sessEngine.getSession(options.sessionStatus);
      if (!session) {
        console.log(`  Session not found: ${options.sessionStatus}`);
        process.exit(1);
      }
      console.log(sessEngine.formatSessionSummary(session));
      console.log("");

      // Show intent evidence
      const intentLog = getIntentLogger();
      const log = intentLog.getSessionLog(session.sessionId);
      if (log.totalActions > 0) {
        console.log(`  Intent Log: ${log.totalActions} actions | Chain: ${log.chainValid ? "VALID" : "BROKEN"}`);
        console.log(`  First activity: ${log.firstActivity}`);
        console.log(`  Last activity: ${log.lastActivity}`);
        console.log("");
      }
    }
    process.exit(0);
  }

  // Send session (distribute signing links)
  if (options.sendSession) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SIGNING SESSION — DISTRIBUTE");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const sessEngine = getSigningSessionEngine();
    const session = sessEngine.getSession(options.sendSession);
    if (!session) {
      console.log(`  Session not found: ${options.sendSession}`);
      process.exit(1);
    }
    const distEngine = new DistributionEngine(sessEngine);
    const result = await distEngine.distributeSession(session);
    console.log(`  Document: ${session.documentTitle}`);
    console.log(`  Total signers: ${result.total}`);
    console.log(`  Sent: ${result.sent} | Failed: ${result.failed}`);
    console.log("");
    for (const r of result.results) {
      const icon = r.result.success ? "✓" : "✗";
      console.log(`  [${icon}] ${r.signer} → ${r.channel} (${r.result.success ? r.result.messageId : r.result.error})`);
    }
    console.log("");

    // Show adapter status
    const adapters = distEngine.getAdapterStatus();
    console.log("  Channel Adapters:");
    for (const a of adapters) {
      console.log(`    ${a.channel}: ${a.configured ? "CONFIGURED" : "LOCAL MODE"}`);
    }
    console.log("");
    process.exit(0);
  }

  // ── Secure Document Control (standalone modes) ──────────────

  // SDC Viewer server
  if (options.sdcViewer) {
    startSecureViewer({ port: options.sdcViewerPort });
    return; // Keep process alive
  }

  // SDC Status
  if (options.sdcStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SECURE DOCUMENT CONTROL — STATUS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const intakeEngine = getDocumentIntakeEngine();
    const tokenService = getAccessTokenService();
    const ledger = getAccessLedger();
    const fpEngine = getForensicFingerprintEngine();

    const intakeStats = intakeEngine.getStats();
    const tokenStats = tokenService.getStats();
    const ledgerStats = ledger.getStats();
    const fpStats = fpEngine.getStats();
    const integrity = ledger.verifyIntegrity();

    console.log("  ── Document Intake ──");
    console.log(`    Total documents: ${intakeStats.total}`);
    console.log(`    By risk: LOW=${intakeStats.byRiskTier["LOW"] || 0} HIGH=${intakeStats.byRiskTier["HIGH"] || 0} CRITICAL=${intakeStats.byRiskTier["CRITICAL"] || 0}`);
    console.log("");

    console.log("  ── Access Tokens ──");
    console.log(`    Total issued: ${tokenStats.total}`);
    console.log(`    Active: ${tokenStats.active} | Expired: ${tokenStats.expired} | Revoked: ${tokenStats.revoked}`);
    console.log("");

    console.log("  ── Access Ledger ──");
    console.log(`    Total entries: ${ledgerStats.totalEntries}`);
    console.log(`    Unique documents: ${ledgerStats.uniqueDocuments}`);
    console.log(`    Unique actors: ${ledgerStats.uniqueActors}`);
    console.log(`    Denials: ${ledgerStats.denialCount}`);
    console.log(`    Chain integrity: ${integrity.verified ? "VERIFIED ✓" : "BROKEN ✗"}`);
    console.log("");

    console.log("  ── Forensic Fingerprints ──");
    console.log(`    Total fingerprints: ${fpStats.totalFingerprints}`);
    console.log(`    Unique documents: ${fpStats.uniqueDocuments}`);
    console.log(`    Unique recipients: ${fpStats.uniqueRecipients}`);
    console.log("");

    process.exit(0);
  }

  // SDC Ledger query
  if (options.sdcLedger) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SDC ACCESS LEDGER");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const ledger = getAccessLedger();

    if (options.sdcLedger === "report") {
      console.log(ledger.generateComplianceReport());
    } else if (options.sdcLedger === "all") {
      const stats = ledger.getStats();
      console.log(`  Total entries: ${stats.totalEntries}`);
      console.log(`  Chain intact: ${stats.chainIntact ? "YES" : "NO"}`);
      console.log("");
      const entries = ledger.query({ limit: 50 });
      for (const e of entries) {
        const icon = e.result === "denied" ? "✗" : e.result === "granted" ? "✓" : "·";
        console.log(`  ${icon} [${e.timestamp}] ${e.action} by ${e.actor} — ${e.details}`);
      }
    } else {
      const timeline = ledger.getTimeline(options.sdcLedger);
      if (timeline.length === 0) {
        console.log(`  No ledger entries for document: ${options.sdcLedger}`);
      } else {
        for (const line of timeline) {
          console.log(`  ${line}`);
        }
      }
    }
    console.log("");
    process.exit(0);
  }

  // SDC Revoke
  if (options.sdcRevoke) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SDC — REVOKE");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const tokenService = getAccessTokenService();
    const intakeEngine = getDocumentIntakeEngine();
    const ledger = getAccessLedger();

    // Try revoking as token first
    const tokensBefore = tokenService.getByDocument(options.sdcRevoke);
    if (tokensBefore.length > 0) {
      const revoked = tokenService.revokeAllForDocument(options.sdcRevoke);
      console.log(`  Revoked ${revoked} access tokens for document: ${options.sdcRevoke.substring(0, 16)}`);
      ledger.record({
        documentId: options.sdcRevoke,
        action: "token-revoked",
        actor: "system",
        details: `Bulk revocation: ${revoked} tokens revoked`,
        result: "info",
      });
    }

    // Try revoking intake record
    const intakeRecord = intakeEngine.getByDocumentId(options.sdcRevoke);
    if (intakeRecord) {
      intakeEngine.revoke(intakeRecord.intakeId, "System", "CLI revocation");
      console.log(`  Revoked intake record: ${intakeRecord.intakeId.substring(0, 16)}`);
    }

    if (tokensBefore.length === 0 && !intakeRecord) {
      console.log(`  No records found for ID: ${options.sdcRevoke}`);
    }

    console.log("");
    process.exit(0);
  }

  // ── Sovereign Comms Agent (SCA) Standalone Handlers ──────

  // SCA Status
  if (options.scaStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN COMMS AGENT — STATUS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const registry = getTelecomRegistry();
    const convLedger = getConversationLedger();
    const actionEng = getActionEngine();

    const regStats = registry.getStats();
    console.log("  📡 Telecom Registry:");
    console.log(`    Total numbers: ${regStats.total}`);
    console.log(`    Active: ${regStats.active}`);
    console.log(`    Suspended: ${regStats.suspended}`);
    console.log(`    By mode: ${Object.entries(regStats.byMode).map(([k, v]) => `${k}=${v}`).join(", ")}`);
    console.log("");

    const ledgerStats = convLedger.getStats();
    console.log("  📋 Conversation Ledger:");
    console.log(`    Total entries: ${ledgerStats.totalEntries}`);
    console.log(`    Inbound: ${ledgerStats.inbound} | Outbound: ${ledgerStats.outbound} | Internal: ${ledgerStats.internal}`);
    console.log(`    Unique threads: ${ledgerStats.uniqueThreads}`);
    console.log(`    Unique senders: ${ledgerStats.uniqueSenders}`);
    console.log(`    Chain integrity: ${ledgerStats.chainValid ? "VERIFIED" : "BROKEN"}`);
    console.log("");

    if (Object.keys(ledgerStats.intents).length > 0) {
      console.log("  🧠 Intent Distribution:");
      for (const [intent, count] of Object.entries(ledgerStats.intents)) {
        console.log(`    ${intent}: ${count}`);
      }
      console.log("");
    }

    const approvalStats = actionEng.getApprovalStats();
    console.log("  ⏳ Approval Queue:");
    console.log(`    Total: ${approvalStats.total} | Pending: ${approvalStats.pending} | Approved: ${approvalStats.approved} | Rejected: ${approvalStats.rejected}`);
    console.log("");
    process.exit(0);
  }

  // SCA Register Number
  if (options.scaRegister) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SCA — REGISTER NUMBER");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const registry = getTelecomRegistry();
    const number = registry.register({
      number: options.scaRegister,
      label: `SCA-${(options.scaRegisterMode || "INFRA")}-${Date.now()}`,
      entity: options.scaRegisterEntity || "FTH Trading",
      mode: options.scaRegisterMode || "INFRA",
      purpose: options.scaRegisterPurpose || "general",
    });

    console.log(`  ✅ Registered: ${number.number}`);
    console.log(`    Registry ID: ${number.registryId}`);
    console.log(`    Entity: ${number.entity}`);
    console.log(`    Mode: ${number.mode}`);
    console.log(`    Purpose: ${number.purpose}`);
    console.log(`    Persona: ${number.persona.name}`);
    console.log("");
    process.exit(0);
  }

  // SCA Simulate Inbound
  if (options.scaSimulate) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SCA — SIMULATE INBOUND MESSAGE");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const router = getInboundRouter();
    const intentEngine = getAIIntentEngine();
    const actionEng = getActionEngine();
    const composer = getResponseComposer();
    const convLedger = getConversationLedger();
    const threadId = crypto.randomBytes(8).toString("hex");

    const fromPhone = options.scaSimulateFrom || "+15551234567";
    const registry = getTelecomRegistry();
    const allNumbers = registry.getAllActive();
    const targetNum = allNumbers.length > 0 ? allNumbers[0].number : "+15550000000";

    console.log(`  From: ${fromPhone}`);
    console.log(`  To: ${targetNum}`);
    console.log(`  Message: "${options.scaSimulate}"`);
    console.log("");

    // Route through inbound router (direct parse with compliance checks)
    const routeResult = router.routeDirect(fromPhone, targetNum, options.scaSimulate);
    console.log(`  Route: ${routeResult.handledAs} — ${routeResult.reason}`);

    if (routeResult.handledAs === "compliance") {
      console.log(`  Auto-response: ${routeResult.autoResponse || "(none)"}`);
      convLedger.recordCompliance({
        from: fromPhone,
        to: targetNum,
        keyword: routeResult.message?.keyword || "",
        action: routeResult.reason,
        threadId,
      });
    } else if (routeResult.message && routeResult.handledAs === "intent") {
      const msg = routeResult.message;
      convLedger.recordInbound(msg, threadId);

      // Classify intent
      const intent = intentEngine.classify(msg);
      console.log(`  Intent: ${intent.intent} (Tier ${intent.tier}, ${intent.confidence} confidence, ${intent.method})`);
      console.log(`  Requires approval: ${intent.requiresApproval}`);
      console.log(`  Auto-execute: ${intent.autoExecute}`);
      convLedger.recordClassification(msg, intent, threadId);

      // Execute action
      const action = await actionEng.execute(intent, msg);
      console.log(`  Action: ${action.status} — ${action.summary}`);
      convLedger.recordAction(msg, action, threadId);

      // Compose response
      const response = composer.compose(action, msg);
      console.log("");
      console.log("  ── Outbound Response ──");
      console.log(`  To: ${response.to}`);
      console.log(`  Segments: ${response.segments}`);
      console.log(`  Text:`);
      console.log(`  ${response.text.split("\n").join("\n  ")}`);
      convLedger.recordResponse(response, threadId);
    }

    console.log("");
    process.exit(0);
  }

  // SCA Send Outbound
  if (options.scaSend && options.scaSendTo) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SCA — SEND OUTBOUND SMS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const registry = getTelecomRegistry();
    const allNumbers = registry.getAllActive();
    const fromNum = allNumbers.length > 0 ? allNumbers[0].number : "+15550000000";

    console.log(`  From: ${fromNum}`);
    console.log(`  To: ${options.scaSendTo}`);
    console.log(`  Text: "${options.scaSend}"`);
    console.log("");

    const result = await sendTelnyxMessage({
      from: fromNum,
      to: options.scaSendTo,
      text: options.scaSend,
    });

    console.log(`  Result: ${result.success ? "SENT" : "FAILED"}`);
    if (result.messageId) console.log(`  Message ID: ${result.messageId}`);
    if (result.error) console.log(`  Error: ${result.error}`);
    console.log("");
    process.exit(0);
  }

  // SCA Ledger
  if (options.scaLedger) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SCA — CONVERSATION LEDGER");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const convLedger = getConversationLedger();

    if (options.scaLedger === "report") {
      console.log(convLedger.formatSummary());
    } else if (options.scaLedger === "all") {
      const entries = convLedger.query({});
      if (entries.length === 0) {
        console.log("  No conversation entries recorded yet.");
      } else {
        for (const entry of entries.slice(-50)) {
          console.log(`  [${entry.sequence}] ${entry.timestamp} | ${entry.eventType} | ${entry.direction} | ${entry.from} → ${entry.to}`);
          console.log(`       ${entry.summary}`);
        }
        if (entries.length > 50) {
          console.log(`  ... and ${entries.length - 50} more entries`);
        }
      }
    } else {
      // Filter by phone number
      const threads = convLedger.getThreadsForNumber(options.scaLedger);
      if (threads.length === 0) {
        console.log(`  No conversations found for: ${options.scaLedger}`);
      } else {
        for (const thread of threads) {
          console.log(`  Thread: ${thread.threadId}`);
          console.log(`    Events: ${thread.eventCount} | Intents: ${thread.intents.join(", ") || "none"}`);
          console.log(`    Period: ${thread.firstEvent} → ${thread.lastEvent}`);
          if (thread.hasEscalation) console.log(`    ⚠ Has escalation`);
          if (thread.hasCompliance) console.log(`    📋 Has compliance event`);
        }
      }
    }

    console.log("");
    process.exit(0);
  }

  // SCA Approvals
  if (options.scaApprovals) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SCA — PENDING APPROVALS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const actionEng = getActionEngine();
    const pending = actionEng.getPendingApprovals();

    if (pending.length === 0) {
      console.log("  No pending approvals.");
    } else {
      for (const a of pending) {
        console.log(`  [${a.approvalId}] Tier ${a.tier} | ${a.intent}`);
        console.log(`    From: ${a.from} | Action: ${a.suggestedAction}`);
        console.log(`    Message: "${a.messageText}"`);
        console.log(`    Created: ${a.createdAt} | Expires: ${a.expiresAt}`);
        console.log("");
      }
    }
    process.exit(0);
  }

  // SCA Approve
  if (options.scaApprove) {
    const actionEng = getActionEngine();
    const result = actionEng.approveAction(options.scaApprove, "cli-operator");
    if (result) {
      console.log(`  ✅ Approved: ${result.approvalId} — ${result.suggestedAction}`);
    } else {
      console.log(`  ❌ Approval not found or already resolved: ${options.scaApprove}`);
    }
    process.exit(0);
  }

  // SCA Reject
  if (options.scaReject) {
    const actionEng = getActionEngine();
    const result = actionEng.rejectAction(options.scaReject, "cli-operator");
    if (result) {
      console.log(`  ✅ Rejected: ${result.approvalId} — ${result.suggestedAction}`);
    } else {
      console.log(`  ❌ Approval not found or already resolved: ${options.scaReject}`);
    }
    process.exit(0);
  }

  // ── Cloudflare Perimeter Standalone Handlers ───────────────

  // Perimeter Configuration (set domain / tunnel ID)
  if (options.tunnelDomain || options.tunnelId) {
    const cfConfig = getCloudflareConfig();
    if (options.tunnelDomain) {
      cfConfig.setBaseDomain(options.tunnelDomain);
      console.log(`  ✅ Base domain set: ${options.tunnelDomain}`);
    }
    if (options.tunnelId) {
      cfConfig.setTunnelId(options.tunnelId);
      console.log(`  ✅ Tunnel ID set: ${options.tunnelId}`);
    }
    const pLedger = getPerimeterLedger();
    pLedger.recordConfigChange("CLI config update", {
      ...(options.tunnelDomain ? { domain: options.tunnelDomain } : {}),
      ...(options.tunnelId ? { tunnelId: options.tunnelId } : {}),
    });
    process.exit(0);
  }

  // Perimeter Status
  if (options.perimeterStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  CLOUDFLARE PERIMETER — STATUS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const cfConfig = getCloudflareConfig();
    console.log(cfConfig.formatSummary());
    console.log("");

    const tunnel = getTunnelManager();
    console.log(tunnel.formatStatus());
    console.log("");

    const rateLimiter = getRateLimiter();
    console.log(rateLimiter.formatStatus());
    console.log("");

    const pLedger = getPerimeterLedger();
    console.log(pLedger.formatStatus());
    console.log("");

    const chain = pLedger.verifyChainIntegrity();
    console.log(`  Chain Integrity: ${chain.intact ? "✓ VERIFIED" : "✗ BROKEN — " + chain.details}`);
    console.log("");
    process.exit(0);
  }

  // Perimeter Config Display
  if (options.perimeterConfig) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  CLOUDFLARE PERIMETER — CONFIGURATION");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const cfConfig = getCloudflareConfig();
    console.log(cfConfig.formatSummary());
    console.log("");
    const integrity = cfConfig.verifyIntegrity();
    console.log(`  Config Integrity: ${integrity.valid ? "✓ Valid" : "✗ Invalid — hash mismatch (expected: " + integrity.computedHash.substring(0, 16) + "..., stored: " + integrity.storedHash.substring(0, 16) + "...)"}`);
    console.log("");
    process.exit(0);
  }

  // Perimeter Ledger
  if (options.perimeterLedger) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  CLOUDFLARE PERIMETER — SECURITY LEDGER");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const pLedger = getPerimeterLedger();

    if (options.perimeterLedger === "report" || options.perimeterLedger === "all") {
      console.log(pLedger.formatStatus());
    } else if (options.perimeterLedger === "recent") {
      console.log(pLedger.formatRecent(20));
    } else {
      // Try as event type filter
      const entries = pLedger.query({ eventType: options.perimeterLedger as any, limit: 50 });
      if (entries.length > 0) {
        for (const e of entries) {
          console.log(`  [${e.sequence}] ${e.timestamp} ${e.severity.toUpperCase()} ${e.eventType}: ${e.description}`);
        }
      } else {
        console.log(`  No entries matching filter: ${options.perimeterLedger}`);
      }
    }
    console.log("");
    process.exit(0);
  }

  // Tunnel Setup Guide
  if (options.tunnelSetup) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  CLOUDFLARE TUNNEL — SETUP GUIDE");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const tunnel = getTunnelManager();
    console.log(tunnel.generateSetupGuide());
    console.log("");
    process.exit(0);
  }

  // Tunnel Status
  if (options.tunnelStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  CLOUDFLARE TUNNEL — STATUS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const tunnel = getTunnelManager();
    console.log(tunnel.formatStatus());
    console.log("");

    const routes = await tunnel.checkRoutes();
    console.log("  Route Health:");
    for (const route of routes) {
      const icon = route.reachable ? "✓" : "✗";
      console.log(`    ${icon} ${route.service.padEnd(20)} ${route.hostname} — ${route.reachable ? "UP" : "DOWN"} (${route.responseTime ?? "—"}ms)`);
    }
    console.log("");
    process.exit(0);
  }

  // Tunnel Start
  if (options.tunnelStart) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  CLOUDFLARE TUNNEL — STARTING");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const tunnel = getTunnelManager();
    const pLedger = getPerimeterLedger();

    try {
      await tunnel.start();
      pLedger.recordTunnelEvent({
        eventType: "tunnel-started",
        description: "Tunnel started via CLI",
      });
      console.log("  ✅ Tunnel started successfully.");
      console.log(tunnel.formatStatus());
    } catch (err: any) {
      pLedger.recordTunnelEvent({
        eventType: "tunnel-error",
        description: `Tunnel start failed: ${err.message}`,
      });
      console.log(`  ❌ Tunnel start failed: ${err.message}`);
    }
    console.log("");
    return; // Keep alive for tunnel process
  }

  // Tunnel Stop
  if (options.tunnelStop) {
    const tunnel = getTunnelManager();
    const pLedger = getPerimeterLedger();
    tunnel.stop();
    pLedger.recordTunnelEvent({
      eventType: "tunnel-stopped",
      description: "Tunnel stopped via CLI",
    });
    console.log("  ✅ Tunnel stopped.");
    process.exit(0);
  }

  // ── Sovereign Operations: Backup Agent ─────────────────────
  if (options.backupNow) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN OPS — BACKUP NOW");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const agent = getBackupAgent();
    const encKey = process.env.FTH_BACKUP_ENCRYPTION_KEY;
    const result = agent.createBackup(encKey);
    console.log(`  ✅ Backup created: ${result.backupId}`);
    console.log(`     Path: ${result.outputPath}`);
    console.log(`     Files: ${result.manifest.files.length}  Size: ${(result.manifest.totalSizeBytes / 1024).toFixed(1)} KB`);
    console.log(`     Hash: ${result.manifest.integrityHash.slice(0, 16)}...`);
    console.log(`     Encrypted: ${result.manifest.encrypted ? "YES" : "NO"}`);
    console.log(`     Elapsed: ${result.elapsedMs}ms`);
    console.log("");
    process.exit(0);
  }

  if (options.backupDaemon) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN OPS — BACKUP DAEMON");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const agent = getBackupAgent();
    const intervalMin = parseInt(process.env.FTH_BACKUP_INTERVAL_MINUTES || "15", 10);
    const retentionDays = parseInt(process.env.FTH_BACKUP_RETENTION_DAYS || "30", 10);
    const encKey = process.env.FTH_BACKUP_ENCRYPTION_KEY;
    agent.startDaemon(intervalMin, encKey, retentionDays);
    console.log(`  ✅ Backup daemon running every ${intervalMin} min`);
    console.log(`     Retention: ${retentionDays} days`);
    console.log(`     Encryption: ${encKey ? "ENABLED" : "DISABLED"}`);
    console.log("");
    console.log("  Press Ctrl+C to stop.");
    return; // keep alive
  }

  if (options.backupList) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN OPS — BACKUP INVENTORY");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const agent = getBackupAgent();
    const backups = agent.listBackups();
    if (backups.length === 0) {
      console.log("  No backups found.");
    } else {
      for (const b of backups) {
        console.log(`  ${b.filename}  ${(b.sizeBytes / 1024).toFixed(1)} KB  ${b.created}`);
      }
      console.log(`\n  Total: ${backups.length} backup(s)`);
    }
    console.log("");
    process.exit(0);
  }

  if (options.backupVerify) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN OPS — VERIFY BACKUP");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const agent = getBackupAgent();
    const encKey = process.env.FTH_BACKUP_ENCRYPTION_KEY;
    const result = agent.verifyBackup(options.backupVerify, encKey);
    if (result.valid) {
      console.log(`  ✅ Backup VALID: ${options.backupVerify}`);
      if (result.manifest) {
        console.log(`     Files: ${result.manifest.files.length}  Hash: ${result.manifest.integrityHash.slice(0, 16)}...`);
      }
    } else {
      console.log(`  ❌ Backup INVALID: ${options.backupVerify}`);
      console.log(`     Reason: ${result.details}`);
    }
    console.log("");
    process.exit(0);
  }

  if (options.backupRestore) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN OPS — RESTORE BACKUP (DESTRUCTIVE)");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const agent = getBackupAgent();
    const encKey = process.env.FTH_BACKUP_ENCRYPTION_KEY;
    const result = agent.restoreBackup(options.backupRestore, encKey);
    if (result.success) {
      console.log(`  ✅ Restore complete: ${result.filesRestored} files`);
    } else {
      console.log(`  ❌ Restore failed: ${result.details}`);
    }
    console.log("");
    process.exit(0);
  }

  if (options.backupStatus) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN OPS — BACKUP STATUS");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const agent = getBackupAgent();
    console.log(agent.formatStatus());
    console.log("");
    process.exit(0);
  }

  // ── Sovereign Operations: Monitoring Dashboard ────────────
  if (options.dashboardSnapshot) {
    const snap = await (await import("./sovereign/monitorDashboard")).collectSnapshot();
    console.log(JSON.stringify(snap, null, 2));
    process.exit(0);
  }

  if (options.dashboard) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SOVEREIGN OPS — MONITORING DASHBOARD");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");
    const port = options.dashboardPort;
    startDashboardServer(port);
    console.log(`  ✅ Dashboard live at http://localhost:${port}`);
    console.log(`     HTML:  http://localhost:${port}/dashboard`);
    console.log(`     API:   http://localhost:${port}/api/snapshot`);
    console.log(`     Health: http://localhost:${port}/health`);
    console.log("");
    console.log("  Press Ctrl+C to stop.");
    return; // keep alive
  }

  // SCA Webhook Server
  if (options.scaWebhook) {
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  SCA — INBOUND WEBHOOK SERVER");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const webhookPort = options.scaWebhookPort;
    const router = getInboundRouter();
    const intentEngine = getAIIntentEngine();
    const actionEng = getActionEngine();
    const composer = getResponseComposer();
    const convLedger = getConversationLedger();

    const server = http.createServer((req, res) => {
      if (req.method === "POST" && (req.url === "/webhook/telnyx" || req.url === "/webhook/sca")) {
        let body = "";
        req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
        req.on("end", async () => {
          const sourceIp = req.socket.remoteAddress || "0.0.0.0";
          const threadId = crypto.randomBytes(8).toString("hex");
          const routeResult = router.processWebhook(body, sourceIp);

          if (routeResult.handledAs === "compliance") {
            convLedger.recordCompliance({
              from: routeResult.message?.from || "",
              to: routeResult.message?.to || "",
              keyword: routeResult.message?.keyword || "",
              action: routeResult.reason,
              threadId,
            });
          } else if (routeResult.message && routeResult.handledAs === "intent") {
            const msg = routeResult.message;
            convLedger.recordInbound(msg, threadId);

            const intent = intentEngine.classify(msg);
            convLedger.recordClassification(msg, intent, threadId);

            const action = await actionEng.execute(intent, msg);
            convLedger.recordAction(msg, action, threadId);

            const response = await composer.composeAndSend(action, msg);
            convLedger.recordResponse(response, threadId);
          }

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ status: "ok", handled: routeResult.handledAs }));
        });
      } else if (req.method === "GET" && req.url === "/sca/status") {
        const stats = convLedger.getStats();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(stats));
      } else {
        res.writeHead(404);
        res.end("Not Found");
      }
    });

    server.listen(webhookPort, () => {
      console.log(`  SCA Webhook Server live on port ${webhookPort}`);
      console.log(`  Webhook endpoint: POST http://localhost:${webhookPort}/webhook/telnyx`);
      console.log(`  Status endpoint:  GET  http://localhost:${webhookPort}/sca/status`);
      console.log("");
    });
    return; // Keep alive
  }

  // Watch mode
  if (options.watch) {
    const inputDir = options.filePath || "./input";
    watchDirectory({
      inputDir,
      outputDir: options.outputDir,
      processFn: (file, outDir) => processSingleDocument(file, outDir, options),
    });
    return; // Keep process alive
  }

  // Batch mode
  if (options.batch) {
    const inputDir = options.filePath || "./input";
    console.log("");
    console.log("═══════════════════════════════════════════════════════");
    console.log("  DOCUMENT INTELLIGENCE ENGINE — BATCH MODE");
    console.log("═══════════════════════════════════════════════════════");
    console.log("");

    const result = await processBatch(
      inputDir,
      options.outputDir,
      (file, outDir) => processSingleDocument(file, outDir, options),
      { recursive: options.recursive, continueOnError: true }
    );

    printBatchSummary(result);
    process.exit(result.failed > 0 ? 1 : 0);
  }

  // ── Single file mode ────────────────────────────────────────

  console.log("");
  console.log("═══════════════════════════════════════════════════════");
  console.log("  DOCUMENT INTELLIGENCE ENGINE");
  console.log("═══════════════════════════════════════════════════════");
  console.log("");

  // Validate input
  if (!options.filePath) {
    console.error("[ERROR] No file specified. Use --help for usage.");
    process.exit(1);
  }

  const absolutePath = path.resolve(options.filePath);
  if (!fs.existsSync(absolutePath)) {
    console.error(`[ERROR] File not found: ${absolutePath}`);
    process.exit(1);
  }

  await processSingleDocument(absolutePath, options.outputDir, options);
}

/**
 * Process a single document through the full pipeline.
 * Extracted so it can be reused by batch/watch modes.
 */
async function processSingleDocument(
  filePath: string,
  outputDir: string,
  options: CLIOptions
): Promise<void> {
  const absolutePath = path.resolve(filePath);

  console.log(`[INPUT]  ${path.basename(absolutePath)}`);
  console.log(`[MODE]   ${options.mode}`);
  console.log(`[BRAND]  ${options.brand}`);
  console.log("");

  // ── Step 2: Ingest ─────────────────────────────────────────
  console.log("─── STEP 1: INGEST ─────────────────────────────────");
  const ingestResult = await ingestDocument(absolutePath);
  console.log(`[INGEST] Format: ${ingestResult.format.toUpperCase()}`);
  console.log(`[INGEST] Pages: ${ingestResult.pageCount}`);
  console.log(`[INGEST] Raw blocks: ${ingestResult.rawBlocks.length}`);
  console.log("");

  // ── Step 3: Parse & Build Document Object ──────────────────
  console.log("─── STEP 2: PARSE ──────────────────────────────────");
  let doc = buildDocumentObject(ingestResult, absolutePath);
  console.log(`[PARSE]  Title: ${doc.metadata.title}`);
  console.log(`[PARSE]  Sections: ${countSections(doc.structure)}`);
  console.log(`[PARSE]  Components: ${doc.components.length}`);
  console.log(`[PARSE]  Tags: ${doc.semanticTags.join(", ") || "none"}`);

  const suggestions = suggestTransformations(doc.semanticTags);
  console.log(`[PARSE]  Suggested modes: ${suggestions.join(", ")}`);
  console.log("");

  // ── Step 4: Transform ──────────────────────────────────────
  console.log("─── STEP 3: TRANSFORM ──────────────────────────────");
  doc = applyTransformations(doc, options);
  console.log("");

  // ── Document Diff Engine ───────────────────────────────────
  if (options.diffWith) {
    console.log("─── DOCUMENT DIFF ENGINE ───────────────────────────");
    const diffTarget = path.resolve(options.diffWith);
    if (!fs.existsSync(diffTarget)) {
      console.error(`[ERROR] Diff target not found: ${diffTarget}`);
      process.exit(1);
    }
    console.log(`[DIFF]  Comparing: ${path.basename(absolutePath)} ↔ ${path.basename(diffTarget)}`);

    // Ingest and build the comparison document
    const diffIngest = await ingestDocument(diffTarget);
    const docB = buildDocumentObject(diffIngest, diffTarget);
    console.log(`[DIFF]  Target sections: ${countSections(docB.structure)}`);

    // Run forensic diff
    const diffResult = diffDocuments(
      doc,
      docB,
      path.basename(absolutePath),
      path.basename(diffTarget)
    );

    // Print report
    console.log("");
    console.log(formatDiffReport(diffResult));

    // Save diff JSON
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    const diffJsonPath = path.join(outputDir, `diff-${diffResult.diffId}.json`);
    fs.writeFileSync(diffJsonPath, JSON.stringify(diffResult, null, 2));
    console.log(`  [SAVED] ${diffJsonPath}`);
    console.log("");

    // Log event
    const eventLog = getEventLog();
    eventLog.log({
      documentId: diffResult.diffId,
      action: "compared",
      details: `Diff: ${diffResult.stats.modified} modified, ${diffResult.stats.added} added, ${diffResult.stats.removed} removed`,
      actor: options.author,
    });
  }

  // ── Step 5: Export ─────────────────────────────────────────
  console.log("─── STEP 4: EXPORT ─────────────────────────────────");

  // Ensure output directory
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Always export HTML + JSON
  const brand = getBrand(options.brand);
  const { htmlPath } = await exportHTML(doc, outputDir, { brand });
  await exportJSON(doc, outputDir);

  // Export fingerprint
  const sourceBuffer = fs.readFileSync(absolutePath);
  const fingerprint = generateFingerprint(doc, sourceBuffer);
  await exportFingerprint(fingerprint, outputDir);

  // Generate document ID
  const documentId = crypto
    .createHash("sha256")
    .update(absolutePath + fingerprint.timestamp)
    .digest("hex");

  // ── Sovereign Hardening: Canonicalization ──────────────────
  let docCanonicalHash: string | null = null;
  let docCanonicalMerkle: string | null = null;
  if (options.canonicalize) {
    console.log("─── CANONICAL SERIALIZATION ─────────────────────────");
    const canonDoc = canonicalizeDocument(doc);
    docCanonicalHash = canonicalHash(doc);
    docCanonicalMerkle = canonicalMerkleRoot(doc);
    const canonFP = computeCanonicalFingerprint(doc);

    console.log(`[CANONICAL] Hash: ${docCanonicalHash.substring(0, 16)}...`);
    console.log(`[CANONICAL] Merkle: ${docCanonicalMerkle.substring(0, 16)}...`);
    console.log(`[CANONICAL] Fields stripped: volatile timestamps, device info`);

    // Save canonical fingerprint
    const canonPath = path.join(outputDir, "canonical-fingerprint.json");
    fs.writeFileSync(canonPath, JSON.stringify(canonFP, null, 2), "utf-8");
    console.log(`[CANONICAL] Fingerprint → ${canonPath}`);
    console.log("");
  }

  // ── Sovereign Hardening: Lifecycle Registry ────────────────
  if (options.lifecycle) {
    console.log("─── LIFECYCLE REGISTRY ─────────────────────────────");
    const lcRegistry = getLifecycleRegistry();
    lcRegistry.createLifecycle({
      documentId,
      sku: "", // Will be updated after SKU generation
      sourceFile: path.basename(absolutePath),
      title: doc.metadata.title,
      draftHash: fingerprint.sha256,
      canonicalHash: docCanonicalHash || undefined,
      merkleRoot: docCanonicalMerkle || fingerprint.merkleRoot,
      actor: options.author,
    });
    lcRegistry.advanceStage(documentId, "parsed", {
      contentHash: fingerprint.sha256,
      actor: options.author,
    });
    if (options.canonicalize) {
      lcRegistry.advanceStage(documentId, "canonicalized", {
        contentHash: docCanonicalHash || fingerprint.sha256,
        actor: options.author,
      });
    }
    console.log(`[LIFECYCLE] Created → ingested → parsed${options.canonicalize ? " → canonicalized" : ""}`);
    console.log("");
  }

  // Governance mode: compile proposal
  if (options.mode === "governance") {
    await compileProposal(doc, outputDir, {
      author: options.author,
    });
  }

  // Archive mode: create archive manifest + verification script
  if (options.mode === "archive") {
    await createArchive(doc, absolutePath, outputDir);
  }

  // Optional PDF export
  if (options.exportPDF) {
    await exportPDF(htmlPath, outputDir);
  }

  // Optional DOCX export
  if (options.exportDOCX) {
    await exportDOCX(doc, outputDir);
  }

  console.log("");

  // ── Step 6: Sovereignty Layers ─────────────────────────────

  // Initialize event log
  const eventLog = getEventLog();
  eventLog.log({
    documentId,
    action: "ingested",
    actor: options.author,
    details: `Ingested ${path.basename(absolutePath)} (${doc.metadata.type.toUpperCase()})`,
    fingerprint: fingerprint.sha256,
  });
  eventLog.log({
    documentId,
    action: "exported",
    actor: options.author,
    details: `Exported as ${options.mode} mode (HTML + JSON + fingerprint)`,
    fingerprint: fingerprint.sha256,
  });

  // SKU generation
  let skuResult: ReturnType<typeof generateSKU> | null = null;
  if (options.sku) {
    console.log("─── STEP 5: SKU IDENTITY ───────────────────────────");
    skuResult = generateSKUFromMode(options.mode, doc);
    console.log(`[SKU] ${skuResult.sku}`);
    console.log(`[SKU] Type: ${skuResult.docType} / ${skuResult.subtype}`);
    console.log(`[SKU] Jurisdiction: ${skuResult.jurisdiction}`);
    console.log(`[SKU] Hash: ${skuResult.hashSuffix}`);

    // Save SKU file
    const skuPath = path.join(outputDir, `${skuResult.sku}.sku.json`);
    fs.writeFileSync(skuPath, JSON.stringify(skuResult, null, 2), "utf-8");
    console.log(`[SKU] Saved → ${skuPath}`);
    console.log("");

    eventLog.log({
      documentId,
      sku: skuResult.sku,
      action: "sku-assigned",
      actor: options.author,
      details: `SKU assigned: ${skuResult.sku}`,
      fingerprint: fingerprint.sha256,
    });

    // Update lifecycle with SKU
    if (options.lifecycle) {
      const lcRegistry = getLifecycleRegistry();
      lcRegistry.updateSKU(documentId, skuResult.sku);
    }
  }

  // Digital signature
  let signatureState: ReturnType<typeof getSignatureEngine.prototype.createSignatureState> | null = null;
  if (options.sign) {
    console.log("─── STEP 6: DIGITAL SIGNATURE ──────────────────────");
    const sigEngine = getSignatureEngine();
    signatureState = sigEngine.createSignatureState(
      documentId,
      fingerprint.sha256,
      undefined,
      skuResult?.sku
    );

    const signer: SignerIdentity = {
      name: options.signerName,
      email: options.signerEmail || `${options.signerName.toLowerCase().replace(/\s+/g, ".")}@local`,
      role: options.signerRole,
      signatureType: options.signerRole as any || "author",
    };

    const sig = sigEngine.sign(signatureState, {
      fingerprint,
      signer,
    });

    // Save signature state
    const sigPath = path.join(outputDir, "signature-state.json");
    fs.writeFileSync(sigPath, sigEngine.exportSignatureState(signatureState), "utf-8");
    console.log(`[SIGNATURE] State → ${sigPath}`);
    console.log("");

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "signed",
      actor: options.signerName,
      details: `Signed by ${signer.name} (${signer.signatureType}) — sig: ${sig.signatureHash.substring(0, 16)}...`,
      fingerprint: signatureState.currentHash,
    });

    // Advance lifecycle to signed
    if (options.lifecycle) {
      const lcRegistry = getLifecycleRegistry();
      lcRegistry.advanceStage(documentId, "compliance-injected", {
        contentHash: signatureState.currentHash,
        actor: options.signerName,
      });
      lcRegistry.advanceStage(documentId, "signed", {
        contentHash: signatureState.currentHash,
        actor: options.signerName,
      });
    }

    // Signature certificate generation
    if (options.signCert) {
      console.log("─── SIGNATURE CERTIFICATE ──────────────────────────");
      const certs = generateCertificatesForState(
        signatureState,
        fingerprint,
        doc.metadata.title,
        true // consent given via CLI flag
      );
      for (const cert of certs) {
        const verification = verifyCertificate(cert);
        console.log(`[CERT] Certificate ID: ${cert.certificateId.substring(0, 12)}...`);
        console.log(`[CERT] Signer: ${cert.signerName} (${cert.signerRole})`);
        console.log(`[CERT] Frameworks: ${cert.frameworks.join(", ")}`);
        console.log(`[CERT] Consent: ${cert.consent.consentGiven ? "YES" : "NO"}`);
        console.log(`[CERT] Hash: ${cert.certificateHash.substring(0, 16)}...`);
        console.log(`[CERT] Integrity: ${verification.valid ? "VALID" : "ISSUES DETECTED"}`);

        // Save certificate
        const certPath = path.join(outputDir, `signature-certificate-${cert.certificateId.substring(0, 8)}.json`);
        fs.writeFileSync(certPath, JSON.stringify(cert, null, 2), "utf-8");

        // Save human-readable certificate
        const certTextPath = path.join(outputDir, `signature-certificate-${cert.certificateId.substring(0, 8)}.txt`);
        fs.writeFileSync(certTextPath, formatCertificateText(cert), "utf-8");
        console.log(`[CERT] Certificate → ${certPath}`);
      }
      console.log("");
    }
  }

  // Multi-Signature Workflow
  if (options.sign && options.requireSignatures > 0 && options.counterparties.length > 0) {
    console.log("─── MULTI-SIGNATURE WORKFLOW ────────────────────────");
    const msEngine = getMultiSigEngine();
    const signer: SignerIdentity = {
      name: options.signerName,
      email: options.signerEmail || `${options.signerName.toLowerCase().replace(/\s+/g, ".")}@local`,
      role: options.signerRole,
      signatureType: options.signerRole as any || "author",
    };

    // Build counterparty list from --counterparty flags
    const counterparties = options.counterparties.map((email: string) => ({
      email,
      name: email.split("@")[0],
      role: "counterparty",
      signatureType: "counterparty" as const,
      required: true,
    }));

    const workflow = msEngine.createWorkflow({
      documentId,
      documentHash: fingerprint.sha256,
      sku: skuResult?.sku,
      initiator: signer,
      requiredSignatures: options.requireSignatures,
      counterparties,
      ordering: options.sigOrdering,
      initiatorCounts: true,
    });

    // Add initiator's signature to the workflow
    if (signatureState && signatureState.signatures.length > 0) {
      const initSig = signatureState.signatures[signatureState.signatures.length - 1];
      const result = msEngine.addSignature(workflow.workflowId, initSig);
      console.log(`[MULTISIG] Initiator signature: ${result.message}`);
    }

    // Save workflow
    const msPath = path.join(outputDir, "multisig-workflow.json");
    const wf = msEngine.getWorkflow(workflow.workflowId);
    if (wf) {
      fs.writeFileSync(msPath, JSON.stringify(wf, null, 2), "utf-8");
      console.log(`[MULTISIG] Workflow → ${msPath}`);
    }

    // If threshold already met (single-signer threshold=1), auto-finalize
    if (wf && wf.thresholdMet) {
      const finalized = msEngine.finalize(wf.workflowId);
      if (finalized) {
        const certReport = msEngine.exportCertificateReport(wf.workflowId);
        if (certReport) {
          const certPath = path.join(outputDir, "multisig-certificate.txt");
          fs.writeFileSync(certPath, certReport, "utf-8");
          console.log(`[MULTISIG] Certificate → ${certPath}`);
        }
        const certJson = msEngine.exportCertificate(wf.workflowId);
        if (certJson) {
          const certJsonPath = path.join(outputDir, "multisig-certificate.json");
          fs.writeFileSync(certJsonPath, JSON.stringify(certJson, null, 2), "utf-8");
        }
      }
    }

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "multisig-created",
      actor: options.signerName,
      details: `Multi-sig workflow: ${workflow.workflowId.substring(0, 12)}... — threshold ${options.requireSignatures}, ${counterparties.length} counterparties`,
      fingerprint: fingerprint.sha256,
    });

    console.log("");
  }

  // Signing Session Creation (pipeline integration)
  if (options.createSession && options.sessionSigners.length > 0) {
    console.log("─── SIGNING SESSION ────────────────────────────────");
    const sessionEngine = getSigningSessionEngine();

    // Parse signer specs: "Name:email@example.com:role" or "Name:email@example.com"
    const signers = options.sessionSigners.map((spec: string) => {
      const parts = spec.split(":");
      if (parts.length < 2) {
        console.error(`[SESSION] Invalid signer spec: "${spec}" — use "Name:email:role"`);
        process.exit(1);
      }
      return {
        name: parts[0].trim(),
        email: parts[1].trim(),
        role: parts[2]?.trim() || "signer",
        signatureType: (parts[2]?.trim() || "signer") as any,
        required: true,
        channels: options.sessionChannels.length > 0
          ? options.sessionChannels
          : ["email" as ContactChannel],
      };
    });

    const session = sessionEngine.createSession({
      documentId,
      documentTitle: path.basename(absolutePath),
      documentHash: fingerprint.sha256,
      sku: skuResult?.sku,
      creator: {
        name: options.signerName || options.author,
        email: options.signerEmail || `${(options.signerName || options.author).toLowerCase().replace(/\\s+/g, ".")}@local`,
      },
      signers,
      threshold: options.sessionThreshold || signers.length,
      requireAll: options.sessionThreshold === 0,
      ordering: "any",
      expiresInHours: 168,
      autoAnchor: true,
      autoFinalize: true,
      autoNotify: true,
      requireIntent: true,
      requireOTP: options.requireOTP,
      baseUrl: `http://localhost:${options.gatewayPort}`,
    });

    console.log(`[SESSION] Created: ${session.sessionId.substring(0, 12)}...`);
    console.log(`[SESSION] Document: ${session.documentTitle}`);
    console.log(`[SESSION] Signers: ${session.signers.length}`);
    console.log(`[SESSION] Threshold: ${session.config.threshold}`);
    console.log(`[SESSION] Expires: ${session.config.expiresAt}`);
    console.log(`[SESSION] OTP Required: ${session.config.requireOTP ? "YES" : "NO"}`);
    session.signers.forEach((s: any) => {
      const url = sessionEngine.getSigningUrl(session, s);
      console.log(`[SESSION]   ${s.name} <${s.email}> → ${url}`);
    });

    // Auto-distribute if channels configured
    if (options.sessionChannels.length > 0) {
      console.log(`[SESSION] Auto-distributing via: ${options.sessionChannels.join(", ")}`);
      const distEngine = new DistributionEngine(sessionEngine);
      const distResults = await distEngine.distributeSession(session);
      console.log(`[SESSION] Distributed: ${distResults.sent} delivered, ${distResults.failed} failed`);
    }

    // Save session to output
    const sessionPath = path.join(outputDir, "signing-session.json");
    fs.writeFileSync(sessionPath, JSON.stringify(session, null, 2), "utf-8");
    console.log(`[SESSION] Session → ${sessionPath}`);

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "signed",
      actor: options.signerName || options.author,
      details: `Signing session ${session.sessionId.substring(0, 12)}... — ${session.signers.length} signers, threshold ${session.config.threshold}`,
      fingerprint: fingerprint.sha256,
    });

    console.log("");
  }

  // ── SDC Pipeline Integration ───────────────────────────────

  // SDC Intake — classify, risk-tier, assign policy
  if (options.sdcIntake) {
    console.log("─── SDC DOCUMENT INTAKE ────────────────────────────");
    const sdcIntake = getDocumentIntakeEngine();

    const intakeRecord = sdcIntake.intake({
      documentId,
      documentTitle: path.basename(absolutePath),
      documentHash: fingerprint.sha256,
      sku: skuResult?.sku,
      owner: {
        name: options.signerName || options.author,
        email: options.signerEmail || "system@local",
        entity: options.brand,
      },
      classification: options.sdcClassify as DocumentClassification | undefined,
      documentText: ingestResult.rawText,
    });

    console.log(`[SDC] Intake ID: ${intakeRecord.intakeId.substring(0, 16)}...`);
    console.log(`[SDC] Classification: ${intakeRecord.classification}`);
    console.log(`[SDC] Risk Tier: ${intakeRecord.riskTier}`);
    console.log(`[SDC] Mode Binding: ${intakeRecord.modeBinding}`);
    console.log(`[SDC] Watermark Policy: ${intakeRecord.watermarkPolicy}`);
    console.log(`[SDC] Export Policy: ${intakeRecord.exportPolicy}`);
    console.log(`[SDC] State: ${intakeRecord.state}`);
    console.log(`[SDC] Notice: ${intakeRecord.confidentialityNotice.substring(0, 80)}...`);

    const intakePath = path.join(outputDir, "sdc-intake.json");
    fs.writeFileSync(intakePath, JSON.stringify(intakeRecord, null, 2), "utf-8");
    console.log(`[SDC] Intake record → ${intakePath}`);

    // Log to access ledger
    const sdcLedger = getAccessLedger();
    sdcLedger.record({
      documentId,
      intakeId: intakeRecord.intakeId,
      action: "state-changed",
      actor: "system",
      details: `Document intake: classified as ${intakeRecord.classification}, risk=${intakeRecord.riskTier}`,
      result: "info",
      documentHash: fingerprint.sha256,
    });

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "accessed",
      actor: "sdc-intake",
      details: `SDC intake: ${intakeRecord.classification} / ${intakeRecord.riskTier} → ${intakeRecord.watermarkPolicy} watermark, ${intakeRecord.exportPolicy} export`,
      fingerprint: fingerprint.sha256,
    });

    // Issue access token for recipient if specified
    if (options.sdcTokenIssue && options.sdcTokenRecipient) {
      const recipientParts = options.sdcTokenRecipient.split(":");
      const recipientName = recipientParts[0]?.trim() || "Recipient";
      const recipientEmail = recipientParts[1]?.trim() || "recipient@local";
      const recipientOrg = recipientParts[2]?.trim();

      const tokenService = getAccessTokenService();
      const token = tokenService.issue({
        documentId,
        intakeId: intakeRecord.intakeId,
        recipient: {
          name: recipientName,
          email: recipientEmail,
          organization: recipientOrg,
        },
        maxUses: intakeRecord.accessPolicy.maxViewsPerRecipient,
        expiryHours: intakeRecord.accessPolicy.linkExpiryHours,
        requireOTP: intakeRecord.accessPolicy.requireOTP,
        boundIP: undefined,
      });

      console.log(`[SDC] Access token issued: ${token.tokenId.substring(0, 16)}...`);
      console.log(`[SDC]   Recipient: ${recipientName} <${recipientEmail}>`);
      console.log(`[SDC]   Max uses: ${token.maxUses || "unlimited"}`);
      console.log(`[SDC]   Expires: ${token.expiresAt}`);
      console.log(`[SDC]   OTP required: ${token.otpRequired ? "YES" : "NO"}`);
      console.log(`[SDC]   View URL: ${tokenService.getAccessUrl(token, `http://localhost:${options.sdcViewerPort}`)}`);

      const tokenPath = path.join(outputDir, "sdc-token.json");
      fs.writeFileSync(tokenPath, JSON.stringify(token, null, 2), "utf-8");
      console.log(`[SDC] Token → ${tokenPath}`);

      sdcLedger.record({
        documentId,
        intakeId: intakeRecord.intakeId,
        tokenId: token.tokenId,
        action: "token-issued",
        actor: "system",
        details: `Token issued to ${recipientEmail} — max ${token.maxUses || "∞"} uses, expires ${token.expiresAt}`,
        result: "info",
      });

      // Controlled export if requested
      if (options.sdcExport) {
        const exportEngine = getExportPolicyEngine();
        const exportResult = exportEngine.processExport({
          documentId,
          documentTitle: path.basename(absolutePath),
          documentContent: fs.existsSync(htmlPath) ? fs.readFileSync(htmlPath, "utf-8") : "",
          documentHash: fingerprint.sha256,
          recipient: {
            name: recipientName,
            email: recipientEmail,
            ip: "127.0.0.1",
            accessToken: token.tokenId,
            organization: recipientOrg || undefined,
          } as WatermarkRecipient,
          format: options.sdcExport,
          policy: intakeRecord.exportPolicy,
          watermarkPolicy: intakeRecord.watermarkPolicy,
          confidentialityNotice: intakeRecord.confidentialityNotice,
        });

        if (exportResult.allowed) {
          console.log(`[SDC] Export: ${options.sdcExport.toUpperCase()} — ${exportResult.reason}`);
          console.log(`[SDC]   Export ID: ${exportResult.exportId.substring(0, 16)}...`);
          console.log(`[SDC]   Output: ${exportResult.outputPath}`);
          if (exportResult.password) {
            console.log(`[SDC]   Password: ${exportResult.password}`);
          }
          if (exportResult.watermark) {
            console.log(`[SDC]   Watermark: ${exportResult.watermark.payload.watermarkId.substring(0, 16)}...`);
          }

          sdcLedger.record({
            documentId,
            intakeId: intakeRecord.intakeId,
            tokenId: token.tokenId,
            action: "exported",
            actor: recipientEmail,
            details: `Exported as ${options.sdcExport} under ${intakeRecord.exportPolicy} policy`,
            result: "granted",
            exportId: exportResult.exportId,
            watermarkId: exportResult.watermark?.payload.watermarkId,
          });
        } else {
          console.log(`[SDC] Export DENIED: ${exportResult.reason}`);
          sdcLedger.record({
            documentId,
            intakeId: intakeRecord.intakeId,
            action: "policy-enforced",
            actor: recipientEmail,
            details: `Export denied: ${exportResult.reason}`,
            result: "denied",
            denialReason: exportResult.reason,
          });
        }
      }
    }

    // Forensic fingerprint
    if (options.sdcFingerprint) {
      const fpEngine = getForensicFingerprintEngine();
      const recipientParts = (options.sdcTokenRecipient || "System:system@local").split(":");
      const recipientName = recipientParts[0]?.trim() || "System";
      const recipientEmail = recipientParts[1]?.trim() || "system@local";
      const recipientOrg = recipientParts[2]?.trim();

      const fpResult = fpEngine.fingerprint({
        documentId,
        documentTitle: path.basename(absolutePath),
        text: ingestResult.rawText || "",
        recipient: {
          email: recipientEmail,
          name: recipientName,
          organization: recipientOrg,
        },
      });

      console.log(`[SDC] Forensic fingerprint: ${fpResult.payload.fingerprintId.substring(0, 16)}...`);
      console.log(`[SDC]   Zero-width markers: ${fpResult.payload.zwMarkerCount}`);
      console.log(`[SDC]   Spacing variations: ${fpResult.payload.spacingVariations}`);
      console.log(`[SDC]   Whitespace subs: ${fpResult.payload.whitespaceSubstitutions}`);
      console.log(`[SDC]   Homoglyph subs: ${fpResult.payload.homoglyphCount}`);
      console.log(`[SDC]   Total modifications: ${fpResult.payload.totalModifications}`);

      const fpPath = path.join(outputDir, "sdc-fingerprint.json");
      fs.writeFileSync(fpPath, JSON.stringify(fpResult.payload, null, 2), "utf-8");
      console.log(`[SDC] Fingerprint → ${fpPath}`);

      sdcLedger.record({
        documentId,
        intakeId: intakeRecord.intakeId,
        action: "fingerprint-embedded",
        actor: "system",
        details: `Forensic fingerprint applied: ${fpResult.payload.totalModifications} modifications for ${recipientEmail}`,
        result: "info",
      });

      eventLog.log({
        documentId,
        sku: skuResult?.sku,
        action: "fingerprinted",
        actor: "sdc-forensic",
        details: `Forensic fingerprint: ${fpResult.payload.zwMarkerCount} ZW markers, ${fpResult.payload.homoglyphCount} homoglyphs, ${fpResult.payload.spacingVariations} spacing variations`,
        fingerprint: fingerprint.sha256,
      });
    }

    console.log("");
  }

  // Encrypted IPFS push
  let encryptedCID: string | null = null;
  if (options.encrypt && options.ipfsPush) {
    console.log("─── ENCRYPTED IPFS ─────────────────────────────────");
    const ipfs = getIPFSClient();
    const online = await ipfs.isOnline();

    if (online) {
      // Serialize the document + fingerprint as the plaintext
      const plaintext = Buffer.from(JSON.stringify({
        document: doc,
        fingerprint,
        signatureHash: signatureState?.currentHash,
        sku: skuResult?.sku,
      }, null, 2), "utf-8");

      // Encrypt using signer key if available, otherwise random key
      const encResult = signatureState
        ? encryptWithSignerKey(plaintext, signatureState.currentHash)
        : encryptBuffer(plaintext);

      // Push encrypted payload to IPFS
      const encPayloadJSON = JSON.stringify(encResult.payload, null, 2);
      const result = await ipfs.addJSON(encResult.payload, "encrypted-document.json");
      encryptedCID = result.cid;

      console.log(`[ENCRYPT] Algorithm: AES-256-GCM`);
      console.log(`[ENCRYPT] Key derivation: ${encResult.payload.keyDerivation}`);
      console.log(`[ENCRYPT] Plaintext size: ${encResult.payload.plaintextSize} bytes`);
      console.log(`[ENCRYPT] Plaintext hash: ${encResult.payload.plaintextHash.substring(0, 16)}...`);
      console.log(`[ENCRYPT] Encrypted CID: ${result.cid}`);
      console.log(`[ENCRYPT] Gateway: ${ipfs.getGatewayUrl(result.cid)}`);

      // Store key in vault (NEVER on IPFS)
      const vault = getKeyVault();
      vault.storeKey({
        documentId,
        sku: skuResult?.sku || "UNASSIGNED",
        key: encResult.key,
        derivation: encResult.payload.keyDerivation,
        encryptedCID: result.cid,
        plaintextHash: encResult.payload.plaintextHash,
        createdAt: new Date().toISOString(),
      });
      console.log(`[ENCRYPT] Key stored in vault (NEVER pushed to IPFS)`);

      // Advance lifecycle
      if (options.lifecycle) {
        const lcRegistry = getLifecycleRegistry();
        lcRegistry.advanceStage(documentId, "encrypted", {
          contentHash: encResult.payload.plaintextHash,
          cid: result.cid,
          actor: options.author,
        });
      }

      eventLog.log({
        documentId,
        sku: skuResult?.sku,
        action: "anchored",
        actor: options.author,
        details: `Encrypted and pushed to IPFS — CID: ${result.cid} (AES-256-GCM, key in vault)`,
        fingerprint: fingerprint.sha256,
        cid: result.cid,
      });
      console.log("");
    } else {
      console.log("[ENCRYPT] IPFS node offline — skipping encrypted push");
      console.log("");
    }
  }

  // IPFS push
  let ipfsCid: string | null = null;
  if (options.ipfsPush) {
    console.log("─── STEP 7: IPFS PUSH ──────────────────────────────");
    const ipfs = getIPFSClient();
    const online = await ipfs.isOnline();

    if (online) {
      // Push the fingerprint + metadata as an anchor payload
      const anchorPayload = {
        type: "document-anchor",
        engine: "Document Intelligence Engine",
        version: "2.0.0",
        sku: skuResult?.sku || "UNASSIGNED",
        fingerprint: {
          sha256: fingerprint.sha256,
          merkleRoot: fingerprint.merkleRoot,
          sourceHash: fingerprint.sourceHash,
          timestamp: fingerprint.timestamp,
        },
        signature: signatureState
          ? {
              currentHash: signatureState.currentHash,
              signerCount: signatureState.signatures.length,
              isComplete: signatureState.isComplete,
            }
          : null,
        anchoredAt: new Date().toISOString(),
      };

      const result = await ipfs.addJSON(anchorPayload, "anchor.json");
      ipfsCid = result.cid;
      console.log(`[IPFS] CID: ${result.cid}`);
      console.log(`[IPFS] Gateway: ${ipfs.getGatewayUrl(result.cid)}`);
      console.log(`[IPFS] IPFS URL: ${ipfs.getIPFSUrl(result.cid)}`);
      console.log(`[IPFS] Size: ${result.size} bytes`);

      // Save CID reference
      const cidPath = path.join(outputDir, "ipfs-cid.json");
      fs.writeFileSync(
        cidPath,
        JSON.stringify(
          {
            cid: result.cid,
            gatewayUrl: ipfs.getGatewayUrl(result.cid),
            ipfsUrl: ipfs.getIPFSUrl(result.cid),
            size: result.size,
            pushedAt: new Date().toISOString(),
          },
          null,
          2
        ),
        "utf-8"
      );
      console.log(`[IPFS] Reference → ${cidPath}`);

      eventLog.log({
        documentId,
        sku: skuResult?.sku,
        action: "anchored",
        actor: options.author,
        details: `Pushed to IPFS — CID: ${result.cid}`,
        fingerprint: fingerprint.sha256,
        cid: result.cid,
      });
    } else {
      console.log("[IPFS] Node offline — skipping push");
    }
    console.log("");
  }

  // Ledger anchor hardening
  if (options.ledgerAnchor && (ipfsCid || encryptedCID)) {
    console.log("─── LEDGER ANCHOR HARDENING ────────────────────────");
    const ledgerEngine = getLedgerAnchorEngine();
    const anchorRecord = await ledgerEngine.anchor({
      documentId,
      fingerprint,
      chain: options.ledgerAnchor as any,
      sku: skuResult?.sku,
      canonicalHash: docCanonicalHash || undefined,
      signatureHash: signatureState?.currentHash,
      encryptedCID: encryptedCID || undefined,
      metadata: { author: options.author },
    });

    // anchor() method prints its own output
    
    // Save anchor record
    const anchorPath = path.join(outputDir, "ledger-anchor.json");
    fs.writeFileSync(anchorPath, JSON.stringify(anchorRecord, null, 2), "utf-8");
    console.log(`[LEDGER] Record → ${anchorPath}`);

    // Advance lifecycle to anchored
    if (options.lifecycle) {
      const lcRegistry = getLifecycleRegistry();
      lcRegistry.advanceStage(documentId, "anchored", {
        contentHash: fingerprint.sha256,
        ledgerTx: anchorRecord.transactionHash,
        chain: anchorRecord.chain,
        blockHeight: anchorRecord.blockHeight,
        actor: options.author,
      });
    }

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "anchored",
      actor: options.author,
      details: `Ledger anchor #${anchorRecord.sequence} → ${anchorRecord.chain} — memo: ${anchorRecord.memo.memoHash.substring(0, 16)}...`,
      fingerprint: fingerprint.sha256,
      cid: anchorRecord.ipfsCid,
    });
    console.log("");
  }

  // CID Registry
  let cidRecord: ReturnType<typeof getRegistry.prototype.register> | null = null;
  if (options.registry && ipfsCid) {
    console.log("─── STEP 8: CID REGISTRY ───────────────────────────");
    const registry = getRegistry();
    cidRecord = registry.register({
      documentId,
      sku: skuResult?.sku || "UNASSIGNED",
      cid: ipfsCid,
      merkleRoot: fingerprint.merkleRoot,
      sha256: fingerprint.sha256,
      author: options.author,
      version: skuResult?.version?.toString() || "1",
      sourceFile: path.basename(absolutePath),
    });
    console.log(`[REGISTRY] Registered: ${cidRecord.sku} → ${cidRecord.cid}`);
    console.log(`[REGISTRY] Signature: ${cidRecord.signature.substring(0, 16)}...`);
    console.log("");

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "registry-added",
      actor: options.author,
      details: `Registered in CID registry — record sig: ${cidRecord.signature.substring(0, 16)}...`,
      fingerprint: fingerprint.sha256,
      cid: ipfsCid,
    });

    // Advance lifecycle to registered
    if (options.lifecycle) {
      const lcRegistry = getLifecycleRegistry();
      lcRegistry.advanceStage(documentId, "registered", {
        contentHash: fingerprint.sha256,
        evidence: `Registry signature: ${cidRecord.signature.substring(0, 32)}`,
        actor: options.author,
      });
    }
  } else if (options.registry && !ipfsCid) {
    console.log("[REGISTRY] Skipped — no IPFS CID available (use --ipfs-push)");
    console.log("");
  }

  // QR verification code
  if (options.qr) {
    console.log("─── STEP 9: QR VERIFICATION ────────────────────────");
    const qrPayload: QRPayload = {
      sku: skuResult?.sku || "UNASSIGNED",
      cid: ipfsCid || undefined,
      sha256: fingerprint.sha256,
      merkleRoot: fingerprint.merkleRoot,
      signatureHash: signatureState?.currentHash,
      timestamp: new Date().toISOString(),
    };

    const qrResult = generateVerificationQR(qrPayload, {
      outputDir,
      filename: `qr-${skuResult?.sku || "verify"}`,
    });
    console.log(`[QR] Payload hash: ${qrResult.payloadHash.substring(0, 16)}...`);
    console.log("");

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "qr-generated",
      actor: options.author,
      details: `QR verification code generated — payload hash: ${qrResult.payloadHash.substring(0, 16)}...`,
      fingerprint: fingerprint.sha256,
    });
  }

  // On-chain anchor (legacy flag)
  if (options.anchor) {
    console.log("─── ANCHOR ─────────────────────────────────────────");
    const anchorResult = await anchorDocument({
      fingerprint,
      chain: options.anchor as any,
    });
    if (anchorResult.success) {
      console.log(`[ANCHOR] Successfully anchored to ${options.anchor.toUpperCase()}`);
      console.log(`[ANCHOR] TX: ${anchorResult.reference.transactionHash || anchorResult.reference.ipfsCid}`);

      eventLog.log({
        documentId,
        sku: skuResult?.sku,
        action: "anchored",
        actor: options.author,
        details: `Anchored to ${options.anchor} — ${anchorResult.reference.transactionHash || anchorResult.reference.ipfsCid}`,
        fingerprint: fingerprint.sha256,
        cid: anchorResult.reference.ipfsCid,
      });
    } else {
      console.error(`[ANCHOR] Failed: ${anchorResult.error}`);
    }
    console.log("");
  }

  // Audit trail
  if (options.audit) {
    console.log("─── AUDIT TRAIL ────────────────────────────────────");
    const events = eventLog.getDocumentHistory(documentId);
    const auditPkg = buildAuditPackage({
      documentId,
      sku: skuResult?.sku || "UNASSIGNED",
      title: doc.metadata.title,
      sourceFile: path.basename(absolutePath),
      fingerprint,
      signatureState: signatureState || undefined,
      cidRecord: cidRecord || undefined,
      events,
      author: options.author,
    });

    exportAuditJSON(auditPkg, outputDir);
    exportAuditHTML(auditPkg, outputDir);
    console.log(`[AUDIT] Package hash: ${auditPkg.packageHash.substring(0, 16)}...`);
    console.log(`[AUDIT] Events: ${events.length}`);
    console.log(`[AUDIT] Signatures: ${auditPkg.signatures.count}`);
    console.log(`[AUDIT] Integrity: ${auditPkg.integrity.overallValid ? "ALL CHECKS PASSED" : "ISSUES DETECTED"}`);
    console.log("");
  }

  // ── Step 10: Research & Knowledge Layer ────────────────────

  // Ingest into knowledge memory
  if (options.ingestMemory) {
    console.log("─── KNOWLEDGE MEMORY INGEST ────────────────────────");
    const memory = getKnowledgeMemory();
    const node = await memory.ingestFile(absolutePath, {
      metadata: { author: options.author },
    });
    console.log(`[MEMORY] Ingested: ${node.title}`);
    console.log(`[MEMORY] Type: ${node.sourceType}`);
    console.log(`[MEMORY] Topic: ${node.topic}`);
    console.log(`[MEMORY] Keywords: ${node.keywords.slice(0, 8).join(", ")}`);
    console.log(`[MEMORY] Evidence: ${node.supportingEvidence.length} fragments`);
    console.log(`[MEMORY] Citations: ${node.citations.length} found`);
    console.log(`[MEMORY] Cross-refs: ${node.crossReferences.length}`);

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "ingested",
      actor: options.author,
      details: `Ingested into knowledge memory — topic: ${node.topic}, ${node.supportingEvidence.length} evidence fragments`,
      fingerprint: fingerprint.sha256,
    });
    console.log("");
  }

  // Compose paper from knowledge + current document
  if (options.paperType) {
    console.log("─── PAPER COMPOSITION ──────────────────────────────");
    const memory = getKnowledgeMemory();
    const allNodes = memory.getAllNodes();
    const title = options.paperTitle || doc.metadata.title || "Composed Paper";
    const paper = composePaper({
      title,
      format: options.paperType,
      sourceNodes: allNodes,
      authors: [options.author],
      citationStyle: options.formatStyle,
    });

    const paperDoc = paperToDocumentObject(paper);
    const brand = getBrand(options.brand);
    const paperOutDir = path.join(outputDir, "paper");
    if (!fs.existsSync(paperOutDir)) fs.mkdirSync(paperOutDir, { recursive: true });
    await exportHTML(paperDoc, paperOutDir, { brand });
    await exportJSON(paperDoc, paperOutDir);

    // Bibliography
    const paperStruct = paper.structure as any;
    const paperCitations: import("./schema/researchSchema").Citation[] = paperStruct.references || [];
    const bibText = formatBibliography(paperCitations, options.formatStyle);
    fs.writeFileSync(path.join(paperOutDir, "bibliography.txt"), bibText, "utf-8");
    const bibHTML = formatReferencesHTML(paperCitations, options.formatStyle);
    fs.writeFileSync(path.join(paperOutDir, "bibliography.html"), bibHTML, "utf-8");

    console.log(`[PAPER] Title: ${paper.title}`);
    console.log(`[PAPER] Format: ${paper.format}`);
    console.log(`[PAPER] Words: ${paper.wordCount.total}`);
    console.log(`[PAPER] Citations: ${paperCitations.length}`);
    console.log(`[PAPER] Output: ${path.resolve(paperOutDir)}`);

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "exported",
      actor: options.author,
      details: `Paper composed: "${paper.title}" (${paper.format}, ${paper.wordCount.total} words)`,
      fingerprint: fingerprint.sha256,
    });
    console.log("");
  }

  // Peer review simulation
  if (options.peerReview) {
    console.log("─── PEER REVIEW SIMULATION ─────────────────────────");
    // Build a ComposedPaper from the document for review
    const paperId = crypto.createHash("sha256")
      .update(doc.metadata.title + options.author + Date.now().toString())
      .digest("hex").substring(0, 16);

    const contentText = doc.structure.map((s: any) =>
      typeof s.content === "string" ? s.content : ""
    ).join("\n");

    const totalWords = contentText.split(/\s+/).filter(Boolean).length;

    const reviewPaper: import("./schema/researchSchema").ComposedPaper = {
      paperId,
      format: options.paperType || "whitepaper",
      title: doc.metadata.title,
      authors: [options.author],
      date: new Date().toISOString(),
      citationStyle: options.formatStyle,
      structure: {
        executiveSummary: contentText.substring(0, 500),
        problemStatement: "",
        architecture: "",
        protocolDesign: "",
        securityModel: "",
        economicModel: "",
        governanceModel: "",
        riskFactors: "",
        roadmap: "",
        legalConsiderations: "",
        references: [],
        appendices: [],
      },
      sourceNodes: [],
      contentHash: crypto.createHash("sha256").update(contentText).digest("hex"),
      wordCount: { total: totalWords, bySections: { content: totalWords } },
    };

    const reviewPkg = simulatePeerReview(reviewPaper, {
      reviewers: options.reviewers,
    });

    const summary = formatReviewSummary(reviewPkg);
    console.log(summary);

    const reviewHTML = formatReviewHTML(reviewPkg);
    const reviewPath = path.join(outputDir, "peer-review.html");
    fs.writeFileSync(reviewPath, reviewHTML, "utf-8");
    console.log(`[REVIEW] Report → ${reviewPath}`);

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "exported",
      actor: options.author,
      details: `Peer review simulated — consensus: ${reviewPkg.consensusRecommendation} (${reviewPkg.consensusScore})`,
      fingerprint: fingerprint.sha256,
    });
    console.log("");
  }

  // Agreement state creation
  if (options.agreementCreate) {
    console.log("─── AGREEMENT STATE ────────────────────────────────");
    const agEngine = getAgreementEngine();
    const agreement = agEngine.createAgreement({
      title: options.agreementCreate,
      sourceDocumentId: documentId,
      sku: skuResult?.sku,
      parties: options.author !== "System" ? [{
        name: options.author,
        role: "party-a" as const,
        email: options.signerEmail || undefined,
      }] : [],
    });
    console.log(`[AGREEMENT] Created: ${agreement.title}`);
    console.log(`[AGREEMENT] ID: ${agreement.agreementId}`);
    console.log(`[AGREEMENT] Status: ${agreement.status}`);
    if (agreement.sku) console.log(`[AGREEMENT] SKU: ${agreement.sku}`);

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "registry-added",
      actor: options.author,
      details: `Agreement created: "${agreement.title}" — status: ${agreement.status}`,
      fingerprint: fingerprint.sha256,
    });
    console.log("");
  }

  // Folder organization
  if (options.organizeFolder) {
    console.log("─── FOLDER ORGANIZATION ────────────────────────────");
    const folder = createDocumentFolder(outputDir, {
      category: options.mode === "governance" ? "governance" : options.mode === "compliance" ? "compliance" : "general",
      clientName: options.clientName || undefined,
      sku: skuResult?.sku,
      year: new Date().getFullYear(),
    });
    const organized = organizeOutputFiles(outputDir, folder);
    console.log(`[FOLDER] Path: ${folder.fullPath}`);
    console.log(`[FOLDER] Client: ${folder.clientName} | Year: ${folder.year} | SKU: ${folder.sku}`);
    console.log(`[FOLDER] Files organized: ${organized.length}`);

    const manifest = generateFolderManifest(folder, {
      documentId,
      title: doc.metadata.title,
      author: options.author,
      sku: skuResult?.sku || "",
    });
    console.log(`[FOLDER] Manifest → ${manifest}`);

    eventLog.log({
      documentId,
      sku: skuResult?.sku,
      action: "exported",
      actor: options.author,
      details: `Output organized into folder structure — ${organized.length} files moved`,
      fingerprint: fingerprint.sha256,
    });
    console.log("");
  }

  // ── Summary ────────────────────────────────────────────────
  console.log("═══════════════════════════════════════════════════════");
  console.log("  COMPLETE — SOVEREIGN DOCUMENT PIPELINE v4.0.0");
  console.log("═══════════════════════════════════════════════════════");
  console.log(`  Output directory: ${path.resolve(outputDir)}`);
  console.log(`  Document ID: ${documentId}`);
  if (skuResult) {
    console.log(`  SKU: ${skuResult.sku}`);
  }
  console.log(`  Fingerprint SHA256: ${fingerprint.sha256.substring(0, 16)}...`);
  console.log(`  Merkle Root: ${fingerprint.merkleRoot.substring(0, 16)}...`);
  if (docCanonicalHash) {
    console.log(`  Canonical Hash: ${docCanonicalHash.substring(0, 16)}...`);
  }
  if (ipfsCid) {
    console.log(`  IPFS CID: ${ipfsCid}`);
  }
  if (encryptedCID) {
    console.log(`  Encrypted CID: ${encryptedCID}`);
  }
  if (signatureState) {
    console.log(`  Signature Hash: ${signatureState.currentHash.substring(0, 16)}...`);
  }
  if (options.lifecycle) {
    const lcRegistry = getLifecycleRegistry();
    const lc = lcRegistry.getLifecycle(documentId);
    if (lc) {
      console.log(`  Lifecycle Stage: ${lc.currentStage}`);
      console.log(`  Lifecycle Transitions: ${lc.transitions.length}`);
    }
  }
  console.log("═══════════════════════════════════════════════════════");
  console.log("");
}

// ── Transform Pipeline ───────────────────────────────────────

function applyTransformations(doc: DocumentObject, options: CLIOptions): DocumentObject {
  let transformed = doc;

  switch (options.mode) {
    case "template":
      console.log("[TRANSFORM] Mode: Template — empty structure replication");
      // Template mode is default — structure already has empty content
      break;

    case "governance":
      console.log("[TRANSFORM] Mode: Governance — DAO proposal format");
      break;

    case "compliance":
      console.log("[TRANSFORM] Mode: Compliance — injecting legal clauses");
      transformed = injectComplianceClauses(transformed);
      transformed = injectSignatureBlocks(transformed, 2);
      break;

    case "brand":
      console.log(`[TRANSFORM] Mode: Brand — applying ${options.brand} brand`);
      const brand = getBrand(options.brand);
      transformed = applyBranding(transformed, brand);
      break;

    case "web":
      console.log("[TRANSFORM] Mode: Web — editable HTML output");
      break;

    case "archive":
      console.log("[TRANSFORM] Mode: Archive — hash + Merkle record");
      break;

    default:
      console.log(`[TRANSFORM] Unknown mode: ${options.mode}, defaulting to template`);
  }

  return transformed;
}

// ── Helpers ──────────────────────────────────────────────────

function countSections(sections: any[]): number {
  let count = 0;
  const walk = (list: any[]) => {
    for (const s of list) {
      count++;
      if (s.children?.length > 0) walk(s.children);
    }
  };
  walk(sections);
  return count;
}

// ── Run ──────────────────────────────────────────────────────

main().catch((err) => {
  console.error("\n[FATAL ERROR]", err.message || err);
  process.exit(1);
});
