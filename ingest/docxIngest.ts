// ─────────────────────────────────────────────────────────────
// DOCX Ingest — Extract text & structure from Word documents
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import mammoth from "mammoth";
import * as cheerio from "cheerio";
import { IngestResult, RawBlock } from "../schema/documentSchema";

/**
 * Ingest a DOCX file and extract raw text + structural blocks.
 */
export async function ingestDOCX(filePath: string): Promise<IngestResult> {
  if (!fs.existsSync(filePath)) {
    throw new Error(`DOCX file not found: ${filePath}`);
  }

  const buffer = fs.readFileSync(filePath);

  // Extract as HTML to preserve structure
  const htmlResult = await mammoth.convertToHtml({ buffer });
  const textResult = await mammoth.extractRawText({ buffer });

  const rawBlocks = htmlToRawBlocks(htmlResult.value);

  return {
    rawText: textResult.value,
    format: "docx",
    pageCount: estimatePageCount(textResult.value),
    rawBlocks,
    metadata: {
      title: extractTitleFromHTML(htmlResult.value) || extractTitleFromText(textResult.value),
      pageCount: estimatePageCount(textResult.value),
      language: "en",
      ingestedAt: new Date().toISOString(),
    },
  };
}

/** Parse HTML output from mammoth into raw blocks */
function htmlToRawBlocks(html: string): RawBlock[] {
  const $ = cheerio.load(html);
  const blocks: RawBlock[] = [];
  let lineNum = 0;

  $("body")
    .children()
    .each((_, el) => {
      lineNum++;
      const $el = $(el);
      const text = $el.text().trim();
      const tagName = (el as any).tagName?.toLowerCase() || "";

      blocks.push({
        text,
        lineNumber: lineNum,
        indentLevel: getIndentFromTag(tagName),
        isUpperCase: text.length > 0 && text === text.toUpperCase() && /[A-Z]/.test(text),
        hasNumbering: /^\d+[\.\)\-]/.test(text) || tagName === "ol",
        hasBullet: tagName === "ul" || /^[•\-\*]/.test(text),
        isEmpty: text.length === 0,
      });

      // Extract child list items
      if (tagName === "ol" || tagName === "ul") {
        $el.find("li").each((_, li) => {
          lineNum++;
          const liText = $(li).text().trim();
          blocks.push({
            text: liText,
            lineNumber: lineNum,
            indentLevel: 1,
            isUpperCase: false,
            hasNumbering: tagName === "ol",
            hasBullet: tagName === "ul",
            isEmpty: liText.length === 0,
          });
        });
      }

      // Extract table rows
      if (tagName === "table") {
        $el.find("tr").each((_, tr) => {
          lineNum++;
          const cells = $(tr)
            .find("td, th")
            .map((__, cell) => $(cell).text().trim())
            .get();
          blocks.push({
            text: cells.join(" | "),
            lineNumber: lineNum,
            indentLevel: 0,
            isUpperCase: false,
            hasNumbering: false,
            hasBullet: false,
            isEmpty: cells.every((c) => c.length === 0),
          });
        });
      }
    });

  return blocks;
}

/** Map HTML tags to logical indent depth */
function getIndentFromTag(tag: string): number {
  const map: Record<string, number> = {
    h1: 0,
    h2: 0,
    h3: 1,
    h4: 1,
    h5: 2,
    h6: 2,
    p: 0,
    li: 1,
    blockquote: 1,
  };
  return map[tag] ?? 0;
}

/** Extract title from the first heading in HTML */
function extractTitleFromHTML(html: string): string | null {
  const $ = cheerio.load(html);
  const h1 = $("h1").first().text().trim();
  if (h1) return h1;
  const h2 = $("h2").first().text().trim();
  if (h2) return h2;
  return null;
}

/** Extract title from raw text */
function extractTitleFromText(text: string): string {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  return lines[0]?.trim().substring(0, 100) || "Untitled Document";
}

/** Estimate pages from word count (~250 words/page) */
function estimatePageCount(text: string): number {
  const wordCount = text.split(/\s+/).filter((w) => w.length > 0).length;
  return Math.max(1, Math.ceil(wordCount / 250));
}
