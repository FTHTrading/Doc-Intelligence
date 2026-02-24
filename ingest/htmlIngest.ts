// ─────────────────────────────────────────────────────────────
// HTML / TXT / Markdown Ingest — Plain text & markup ingestion
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import * as cheerio from "cheerio";
import { IngestResult, RawBlock, InputFormat } from "../schema/documentSchema";

/**
 * Ingest an HTML file and extract structural blocks.
 */
export async function ingestHTML(filePath: string): Promise<IngestResult> {
  if (!fs.existsSync(filePath)) {
    throw new Error(`HTML file not found: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const $ = cheerio.load(content);
  const rawText = $("body").text();
  const rawBlocks = htmlToRawBlocks($);

  return {
    rawText,
    format: "html",
    pageCount: 1,
    rawBlocks,
    metadata: {
      title: $("title").text().trim() || $("h1").first().text().trim() || "Untitled",
      pageCount: 1,
      language: $("html").attr("lang") || "en",
      ingestedAt: new Date().toISOString(),
    },
  };
}

/**
 * Ingest a plain TXT file.
 */
export async function ingestTXT(filePath: string): Promise<IngestResult> {
  if (!fs.existsSync(filePath)) {
    throw new Error(`TXT file not found: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const rawBlocks = textToRawBlocks(content);

  return {
    rawText: content,
    format: "txt",
    pageCount: Math.max(1, Math.ceil(content.split(/\s+/).length / 250)),
    rawBlocks,
    metadata: {
      title: extractTitleFromText(content),
      pageCount: 1,
      language: "en",
      ingestedAt: new Date().toISOString(),
    },
  };
}

/**
 * Ingest a Markdown file.
 */
export async function ingestMarkdown(filePath: string): Promise<IngestResult> {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Markdown file not found: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const rawBlocks = markdownToRawBlocks(content);

  return {
    rawText: content,
    format: "md",
    pageCount: Math.max(1, Math.ceil(content.split(/\s+/).length / 250)),
    rawBlocks,
    metadata: {
      title: extractMarkdownTitle(content),
      pageCount: 1,
      language: "en",
      ingestedAt: new Date().toISOString(),
    },
  };
}

/**
 * Unified ingest dispatcher for text-based formats.
 */
export async function ingestTextBased(filePath: string): Promise<IngestResult> {
  const ext = filePath.toLowerCase().split(".").pop();
  switch (ext) {
    case "html":
    case "htm":
      return ingestHTML(filePath);
    case "txt":
      return ingestTXT(filePath);
    case "md":
    case "markdown":
      return ingestMarkdown(filePath);
    default:
      throw new Error(`Unsupported text format: .${ext}`);
  }
}

// ── Helpers ──────────────────────────────────────────────────

function htmlToRawBlocks($: cheerio.CheerioAPI): RawBlock[] {
  const blocks: RawBlock[] = [];
  let lineNum = 0;

  $("body")
    .children()
    .each((_, el) => {
      lineNum++;
      const $el = $(el);
      const text = $el.text().trim();
      const tag = (el as any).tagName?.toLowerCase() || "";

      blocks.push({
        text,
        lineNumber: lineNum,
        indentLevel: tagToIndent(tag),
        isUpperCase: text.length > 0 && text === text.toUpperCase() && /[A-Z]/.test(text),
        hasNumbering: tag === "ol" || /^\d+[\.\)]/.test(text),
        hasBullet: tag === "ul" || /^[•\-\*]/.test(text),
        isEmpty: text.length === 0,
      });
    });

  return blocks;
}

function textToRawBlocks(text: string): RawBlock[] {
  return text.split("\n").map((line, i) => ({
    text: line,
    lineNumber: i + 1,
    indentLevel: Math.floor((line.match(/^(\s*)/)?.[1].length || 0) / 2),
    isUpperCase: line.trim().length > 0 && line.trim() === line.trim().toUpperCase() && /[A-Z]/.test(line),
    hasNumbering: /^\s*\d+[\.\)\-]/.test(line),
    hasBullet: /^\s*[•\-\*]/.test(line),
    isEmpty: line.trim().length === 0,
  }));
}

function markdownToRawBlocks(md: string): RawBlock[] {
  return md.split("\n").map((line, i) => {
    const headingMatch = line.match(/^(#{1,6})\s/);
    return {
      text: line.replace(/^#{1,6}\s/, "").replace(/\*\*/g, "").replace(/\*/g, ""),
      lineNumber: i + 1,
      indentLevel: headingMatch ? headingMatch[1].length - 1 : Math.floor((line.match(/^(\s*)/)?.[1].length || 0) / 2),
      isUpperCase: false,
      hasNumbering: /^\s*\d+[\.\)]/.test(line),
      hasBullet: /^\s*[\-\*\+]\s/.test(line),
      isEmpty: line.trim().length === 0,
    };
  });
}

function tagToIndent(tag: string): number {
  const map: Record<string, number> = { h1: 0, h2: 0, h3: 1, h4: 1, h5: 2, h6: 2, p: 0, li: 1 };
  return map[tag] ?? 0;
}

function extractTitleFromText(text: string): string {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  return lines[0]?.trim().substring(0, 100) || "Untitled Document";
}

function extractMarkdownTitle(md: string): string {
  const match = md.match(/^#\s+(.+)/m);
  return match ? match[1].trim() : extractTitleFromText(md);
}
