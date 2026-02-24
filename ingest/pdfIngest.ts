// ─────────────────────────────────────────────────────────────
// PDF Ingest — Extract text & structure from PDF files
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import { IngestResult, RawBlock } from "../schema/documentSchema";

// pdf-parse v2 exports a class-based API
const { PDFParse } = require("pdf-parse") as {
  PDFParse: new (opts: { data: Buffer | Uint8Array; verbosity?: number }) => {
    getText(opts?: Record<string, unknown>): Promise<{ text: string; total: number; pages: { text: string; num: number }[] }>;
    getInfo(opts?: Record<string, unknown>): Promise<{ total: number; info?: { Title?: string; Author?: string }; metadata?: unknown }>;
    destroy(): Promise<void>;
  };
};

/**
 * Ingest a PDF file and extract raw text + structural blocks.
 */
export async function ingestPDF(filePath: string): Promise<IngestResult> {
  if (!fs.existsSync(filePath)) {
    throw new Error(`PDF file not found: ${filePath}`);
  }

  const buffer = fs.readFileSync(filePath);
  const parser = new PDFParse({ data: buffer });

  let text = "";
  let pageCount = 1;
  let title = "";

  try {
    const textResult = await parser.getText();
    text = textResult.text;
    pageCount = textResult.total;

    try {
      const infoResult = await parser.getInfo();
      title = infoResult.info?.Title || "";
    } catch {
      // info extraction is optional
    }
  } finally {
    await parser.destroy().catch(() => {});
  }

  const rawBlocks = textToRawBlocks(text);

  return {
    rawText: text,
    format: "pdf",
    pageCount,
    rawBlocks,
    metadata: {
      title: title || extractTitleFromText(text),
      pageCount,
      language: detectLanguage(text),
      ingestedAt: new Date().toISOString(),
    },
  };
}

/** Convert raw text into structural blocks */
function textToRawBlocks(text: string): RawBlock[] {
  const lines = text.split("\n");
  return lines.map((line, index) => ({
    text: line,
    lineNumber: index + 1,
    indentLevel: getIndentLevel(line),
    isUpperCase: line.trim().length > 0 && line.trim() === line.trim().toUpperCase() && /[A-Z]/.test(line),
    hasNumbering: /^\s*\d+[\.\)\-]/.test(line),
    hasBullet: /^\s*[•\-\*▪▸►]/.test(line),
    isEmpty: line.trim().length === 0,
  }));
}

/** Detect indent level by counting leading whitespace */
function getIndentLevel(line: string): number {
  const match = line.match(/^(\s+)/);
  if (!match) return 0;
  return Math.floor(match[1].length / 2);
}

/** Extract a likely title from the first non-empty lines */
function extractTitleFromText(text: string): string {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  return lines[0]?.trim().substring(0, 100) || "Untitled Document";
}

/** Simple language detection heuristic */
function detectLanguage(text: string): string {
  const sample = text.substring(0, 500).toLowerCase();
  const spanishWords = ["el", "la", "de", "en", "es", "los", "las", "del", "por", "con", "una", "uno"];
  const englishWords = ["the", "and", "is", "in", "to", "of", "for", "with", "that", "this"];

  let spanishCount = 0;
  let englishCount = 0;

  spanishWords.forEach((w) => {
    const regex = new RegExp(`\\b${w}\\b`, "gi");
    spanishCount += (sample.match(regex) || []).length;
  });

  englishWords.forEach((w) => {
    const regex = new RegExp(`\\b${w}\\b`, "gi");
    englishCount += (sample.match(regex) || []).length;
  });

  if (spanishCount > englishCount * 1.5) return "es";
  return "en";
}
