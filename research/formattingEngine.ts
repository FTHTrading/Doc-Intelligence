// ─────────────────────────────────────────────────────────────
// Citation Formatting Engine — Multi-Style Reference Formatter
//
// Supported styles:
//   APA 7th    │ MLA 9th     │ Chicago 17th │ IEEE
//   Bluebook   │ SEC Filing  │ ArXiv        │ Grant
//   Board Memo
//
// Each formatter produces properly formatted reference strings
// from the structured Citation schema.
// ─────────────────────────────────────────────────────────────

import { Citation, CitationStyle } from "../schema/researchSchema";

// ── Main Formatter ───────────────────────────────────────────

/**
 * Format a single citation in the specified style.
 */
export function formatCitation(citation: Citation, style: CitationStyle): string {
  switch (style) {
    case "apa":        return formatAPA(citation);
    case "mla":        return formatMLA(citation);
    case "chicago":    return formatChicago(citation);
    case "ieee":       return formatIEEE(citation);
    case "bluebook":   return formatBluebook(citation);
    case "sec-filing": return formatSEC(citation);
    case "arxiv":      return formatArXiv(citation);
    case "grant":      return formatGrant(citation);
    case "board-memo": return formatBoardMemo(citation);
    default:           return formatAPA(citation);
  }
}

/**
 * Format a list of citations as a numbered bibliography.
 */
export function formatBibliography(
  citations: Citation[],
  style: CitationStyle,
  options: { numbered?: boolean; sorted?: boolean } = {}
): string {
  const { numbered = true, sorted = true } = options;

  let formatted = [...citations];
  if (sorted) {
    formatted.sort((a, b) => {
      // Sort by first author last name, then year
      const authorA = a.authors[0]?.split(",")[0] || a.authors[0] || "";
      const authorB = b.authors[0]?.split(",")[0] || b.authors[0] || "";
      const cmp = authorA.localeCompare(authorB);
      return cmp !== 0 ? cmp : a.year - b.year;
    });
  }

  return formatted
    .map((c, i) => {
      const formatted = formatCitation(c, style);
      return numbered ? `[${i + 1}] ${formatted}` : formatted;
    })
    .join("\n\n");
}

/**
 * Format inline citation reference (for in-text use).
 */
export function formatInlineCitation(citation: Citation, style: CitationStyle): string {
  switch (style) {
    case "apa":
      return `(${formatAuthorShort(citation.authors)}, ${citation.year})`;
    case "mla":
      return `(${lastNameOnly(citation.authors[0])} ${citation.pages || ""})`.trim() + ")";
    case "chicago":
      return `${lastNameOnly(citation.authors[0])}, ${citation.year}`;
    case "ieee":
      return `[${citation.citationId.substring(0, 3).toUpperCase()}]`;
    case "bluebook":
      return `${citation.title}, ${citation.year}`;
    default:
      return `(${formatAuthorShort(citation.authors)}, ${citation.year})`;
  }
}

/**
 * Generate a complete references section as HTML.
 */
export function formatReferencesHTML(citations: Citation[], style: CitationStyle): string {
  const bib = formatBibliography(citations, style, { numbered: true, sorted: true });
  const lines = bib.split("\n\n");

  let html = `<div class="references-section">\n`;
  html += `  <h2>References</h2>\n`;
  html += `  <p class="citation-style">Citation Style: ${style.toUpperCase()}</p>\n`;
  html += `  <ol class="reference-list">\n`;

  for (const line of lines) {
    // Strip leading [N]
    const text = line.replace(/^\[\d+\]\s*/, "");
    html += `    <li>${escapeHtml(text)}</li>\n`;
  }

  html += `  </ol>\n`;
  html += `</div>`;

  return html;
}

// ── APA 7th Edition ──────────────────────────────────────────

function formatAPA(c: Citation): string {
  const authors = formatAuthorsAPA(c.authors);
  let ref = `${authors} (${c.year}). ${c.title}.`;

  switch (c.type) {
    case "journal-article":
      ref += ` ${italicize(c.source)}`;
      if (c.volume) ref += `, ${italicize(c.volume)}`;
      if (c.issue) ref += `(${c.issue})`;
      if (c.pages) ref += `, ${c.pages}`;
      ref += ".";
      break;
    case "book":
      ref = `${authors} (${c.year}). ${italicize(c.title)}.`;
      if (c.edition) ref += ` (${c.edition} ed.).`;
      if (c.publisher) ref += ` ${c.publisher}.`;
      break;
    case "book-chapter":
      ref += ` In ${c.source}`;
      if (c.pages) ref += ` (pp. ${c.pages})`;
      ref += `.`;
      if (c.publisher) ref += ` ${c.publisher}.`;
      break;
    case "website":
      ref += ` ${c.source}.`;
      if (c.url) ref += ` ${c.url}`;
      break;
    case "conference-paper":
      ref += ` ${c.source}.`;
      if (c.location) ref += ` ${c.location}.`;
      break;
    default:
      if (c.source) ref += ` ${c.source}.`;
  }

  if (c.doi) ref += ` https://doi.org/${c.doi}`;

  return ref;
}

function formatAuthorsAPA(authors: string[]): string {
  if (authors.length === 0) return "Unknown";
  if (authors.length === 1) return formatAuthorLastFirst(authors[0]);
  if (authors.length === 2) return `${formatAuthorLastFirst(authors[0])} & ${formatAuthorLastFirst(authors[1])}`;
  if (authors.length <= 20) {
    const init = authors.slice(0, -1).map(formatAuthorLastFirst).join(", ");
    return `${init}, & ${formatAuthorLastFirst(authors[authors.length - 1])}`;
  }
  // 21+ authors: first 19, ..., last
  const first19 = authors.slice(0, 19).map(formatAuthorLastFirst).join(", ");
  return `${first19}, ... ${formatAuthorLastFirst(authors[authors.length - 1])}`;
}

// ── MLA 9th Edition ──────────────────────────────────────────

function formatMLA(c: Citation): string {
  const author = c.authors.length > 0 ? formatAuthorLastFirst(c.authors[0]) : "Unknown";
  const otherAuthors = c.authors.length > 2 ? " et al." : c.authors.length === 2 ? `, and ${c.authors[1]}` : "";

  let ref = `${author}${otherAuthors}. "${c.title}."`;

  if (c.source) ref += ` ${italicize(c.source)},`;
  if (c.volume) ref += ` vol. ${c.volume},`;
  if (c.issue) ref += ` no. ${c.issue},`;
  ref += ` ${c.year},`;
  if (c.pages) ref += ` pp. ${c.pages}`;
  ref += ".";

  if (c.doi) ref += ` doi:${c.doi}.`;
  if (c.url) ref += ` ${c.url}.`;

  return ref;
}

// ── Chicago 17th Edition (Notes-Bibliography) ────────────────

function formatChicago(c: Citation): string {
  const authors = c.authors.length > 0
    ? c.authors.join(", ")
    : "Unknown";

  let ref = `${authors}. ${italicize(c.title)}.`;

  if (c.location && c.publisher) {
    ref += ` ${c.location}: ${c.publisher}, ${c.year}.`;
  } else if (c.publisher) {
    ref += ` ${c.publisher}, ${c.year}.`;
  } else {
    ref += ` ${c.year}.`;
  }

  if (c.source && c.type === "journal-article") {
    ref = `${authors}. "${c.title}." ${italicize(c.source)}`;
    if (c.volume) ref += ` ${c.volume}`;
    if (c.issue) ref += `, no. ${c.issue}`;
    ref += ` (${c.year})`;
    if (c.pages) ref += `: ${c.pages}`;
    ref += ".";
  }

  if (c.doi) ref += ` https://doi.org/${c.doi}.`;

  return ref;
}

// ── IEEE ─────────────────────────────────────────────────────

function formatIEEE(c: Citation): string {
  const authors = c.authors.map((a) => {
    const parts = a.split(" ");
    if (parts.length >= 2) {
      const initials = parts.slice(0, -1).map((p) => p[0] + ".").join(" ");
      return `${initials} ${parts[parts.length - 1]}`;
    }
    return a;
  }).join(", ");

  let ref = `${authors}, "${c.title},"`;

  if (c.type === "journal-article") {
    ref += ` ${italicize(c.source)},`;
    if (c.volume) ref += ` vol. ${c.volume},`;
    if (c.issue) ref += ` no. ${c.issue},`;
    if (c.pages) ref += ` pp. ${c.pages},`;
    ref += ` ${c.year}.`;
  } else if (c.type === "conference-paper") {
    ref += ` in ${italicize(c.source)}, ${c.year}`;
    if (c.pages) ref += `, pp. ${c.pages}`;
    ref += ".";
  } else {
    if (c.source) ref += ` ${c.source},`;
    ref += ` ${c.year}.`;
  }

  if (c.doi) ref += ` doi: ${c.doi}.`;

  return ref;
}

// ── Bluebook (Legal Citations) ───────────────────────────────

function formatBluebook(c: Citation): string {
  switch (c.type) {
    case "legal-case":
      return `${italicize(c.title)}, ${c.volume || ""} ${c.source} ${c.pages || ""} (${c.year}).`;
    case "statute":
      return `${c.title}, ${c.volume || ""} ${c.source} § ${c.pages || ""} (${c.year}).`;
    case "journal-article":
      return `${c.authors.join(" & ")}, ${italicize(c.title)}, ${c.volume || ""} ${c.source} ${c.pages || ""} (${c.year}).`;
    case "book":
      return `${c.authors.join(" & ")}, ${smallCaps(c.title)}${c.edition ? ` (${c.edition} ed.)` : ""} (${c.publisher ? c.publisher + " " : ""}${c.year}).`;
    default:
      return `${c.authors.join(" & ")}, ${italicize(c.title)}${c.source ? `, ${c.source}` : ""} (${c.year}).`;
  }
}

// ── SEC Filing Style ─────────────────────────────────────────

function formatSEC(c: Citation): string {
  const authors = c.authors.length > 0 ? c.authors.join(", ") : "Filing Entity";
  let ref = `${authors}. "${c.title}."`;

  if (c.source) ref += ` ${c.source}.`;
  ref += ` Filed ${c.year}.`;

  if (c.url) ref += ` Available at: ${c.url}.`;
  if (c.notes) ref += ` ${c.notes}`;

  return ref;
}

// ── ArXiv Preprint ───────────────────────────────────────────

function formatArXiv(c: Citation): string {
  const authors = c.authors.join(", ");
  let ref = `${authors}. "${c.title}."`;
  ref += ` arXiv preprint`;
  if (c.doi) ref += ` arXiv:${c.doi}`;
  ref += ` (${c.year}).`;
  if (c.url) ref += ` ${c.url}`;
  return ref;
}

// ── Grant Submission ─────────────────────────────────────────

function formatGrant(c: Citation): string {
  const authors = c.authors.join(", ");
  let ref = `${authors} (${c.year}). ${c.title}.`;
  if (c.source) ref += ` ${c.source}.`;
  if (c.publisher) ref += ` Funded by: ${c.publisher}.`;
  if (c.doi) ref += ` DOI: ${c.doi}.`;
  if (c.url) ref += ` Available: ${c.url}.`;
  return ref;
}

// ── Corporate Board Memo ─────────────────────────────────────

function formatBoardMemo(c: Citation): string {
  const authors = c.authors.length > 0 ? c.authors.join(", ") : "Board of Directors";
  let ref = `${authors}. "${c.title}."`;
  if (c.source) ref += ` ${c.source}.`;
  ref += ` ${c.year}.`;
  if (c.notes) ref += ` Note: ${c.notes}.`;
  return ref;
}

// ── Formatting Helpers ───────────────────────────────────────

function formatAuthorLastFirst(author: string): string {
  const parts = author.trim().split(/\s+/);
  if (parts.length === 1) return parts[0];
  const last = parts[parts.length - 1];
  const first = parts.slice(0, -1).map((p) => p[0] + ".").join(" ");
  return `${last}, ${first}`;
}

function formatAuthorShort(authors: string[]): string {
  if (authors.length === 0) return "Unknown";
  const first = lastNameOnly(authors[0]);
  if (authors.length === 1) return first;
  if (authors.length === 2) return `${first} & ${lastNameOnly(authors[1])}`;
  return `${first} et al.`;
}

function lastNameOnly(author: string): string {
  const parts = author.trim().split(/\s+/);
  return parts[parts.length - 1];
}

/** Markdown-style italic (for text output; HTML can post-process) */
function italicize(text: string): string {
  return `_${text}_`;
}

/** Small caps wrapper (Bluebook convention) */
function smallCaps(text: string): string {
  return text.toUpperCase();
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
