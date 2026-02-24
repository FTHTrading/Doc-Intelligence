// ─────────────────────────────────────────────────────────────
// Image Ingest — OCR extraction from PNG / JPG files
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import Tesseract from "tesseract.js";
import sharp from "sharp";
import { IngestResult, RawBlock } from "../schema/documentSchema";

/**
 * Ingest an image file (PNG/JPG) using OCR to extract text.
 */
export async function ingestImage(filePath: string): Promise<IngestResult> {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Image file not found: ${filePath}`);
  }

  // Pre-process image for better OCR accuracy
  const processedBuffer = await preprocessImage(filePath);

  // Run OCR with English + Spanish support
  const result = await Tesseract.recognize(processedBuffer, "eng+spa", {
    logger: (info) => {
      if (info.status === "recognizing text") {
        process.stdout.write(`\rOCR Progress: ${Math.round((info.progress || 0) * 100)}%`);
      }
    },
  });

  console.log(""); // newline after progress

  const rawText = result.data.text;
  const rawBlocks = textToRawBlocks(rawText);

  // Get image dimensions
  const imageMetadata = await sharp(filePath).metadata();

  return {
    rawText,
    format: filePath.toLowerCase().endsWith(".png") ? "png" : "jpg",
    pageCount: 1,
    rawBlocks,
    metadata: {
      title: extractTitleFromText(rawText),
      pageCount: 1,
      language: detectLanguageFromOCR(result.data),
      ingestedAt: new Date().toISOString(),
      dimensions: {
        width: imageMetadata.width || 0,
        height: imageMetadata.height || 0,
        unit: "px",
      },
    },
  };
}

/** Pre-process image for better OCR: grayscale, sharpen, normalize */
async function preprocessImage(filePath: string): Promise<Buffer> {
  return sharp(filePath)
    .grayscale()
    .normalize()
    .sharpen()
    .toBuffer();
}

/** Convert OCR text into raw blocks */
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

/** Detect indent level */
function getIndentLevel(line: string): number {
  const match = line.match(/^(\s+)/);
  if (!match) return 0;
  return Math.floor(match[1].length / 2);
}

/** Extract title from first non-empty line */
function extractTitleFromText(text: string): string {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  return lines[0]?.trim().substring(0, 100) || "Untitled Document";
}

/** Detect language from Tesseract OCR data */
function detectLanguageFromOCR(data: Tesseract.RecognizeResult["data"]): string {
  // Use confidence and script detection from Tesseract
  const text = data.text.substring(0, 500).toLowerCase();
  const spanishIndicators = ["ñ", "á", "é", "í", "ó", "ú", "¿", "¡"];
  const spanishCount = spanishIndicators.reduce(
    (count, char) => count + (text.split(char).length - 1),
    0
  );
  return spanishCount > 3 ? "es" : "en";
}
