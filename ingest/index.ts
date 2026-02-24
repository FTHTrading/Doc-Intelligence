// ─────────────────────────────────────────────────────────────
// Ingest Index — Unified document ingestion dispatcher
// ─────────────────────────────────────────────────────────────

import path from "path";
import { IngestResult, InputFormat } from "../schema/documentSchema";
import { ingestPDF } from "./pdfIngest";
import { ingestDOCX } from "./docxIngest";
import { ingestImage } from "./imageIngest";
import { ingestTextBased } from "./htmlIngest";

/** Map file extensions to input formats */
const EXT_MAP: Record<string, InputFormat> = {
  ".pdf": "pdf",
  ".docx": "docx",
  ".doc": "docx",
  ".png": "png",
  ".jpg": "jpg",
  ".jpeg": "jpg",
  ".html": "html",
  ".htm": "html",
  ".txt": "txt",
  ".md": "md",
  ".markdown": "md",
};

/**
 * Ingest any supported document format.
 * Automatically detects format from file extension and routes to the appropriate parser.
 */
export async function ingestDocument(filePath: string): Promise<IngestResult> {
  const ext = path.extname(filePath).toLowerCase();
  const format = EXT_MAP[ext];

  if (!format) {
    throw new Error(
      `Unsupported file format: ${ext}\nSupported: ${Object.keys(EXT_MAP).join(", ")}`
    );
  }

  console.log(`[INGEST] Processing ${path.basename(filePath)} as ${format.toUpperCase()}...`);

  switch (format) {
    case "pdf":
      return ingestPDF(filePath);
    case "docx":
      return ingestDOCX(filePath);
    case "png":
    case "jpg":
      return ingestImage(filePath);
    case "html":
    case "txt":
    case "md":
      return ingestTextBased(filePath);
    default:
      throw new Error(`No ingest handler for format: ${format}`);
  }
}

export { ingestPDF, ingestDOCX, ingestImage, ingestTextBased };
