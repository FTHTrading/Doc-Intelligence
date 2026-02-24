// ─────────────────────────────────────────────────────────────
// Layout Analyzer — Detect document visual layout patterns
// ─────────────────────────────────────────────────────────────

import { RawBlock, Section, SectionStyle, BlockType } from "../schema/documentSchema";

/** Patterns for layout detection */
const LAYOUT_PATTERNS = {
  tableRow: /^(.+?\s*\|\s*)+.+$/,
  dividerLine: /^[\-=_\*]{3,}$/,
  labelField: /^(.+?):\s*(.*)$/,
  checkbox: /^\s*[\[\(]\s*[\]\)]\s*/,
  signatureLine: /^_{3,}\s*$|^\.{3,}\s*$|^X_{2,}/,
  pageBreak: /^\f|^-{5,}\s*page\s*\d*/i,
  decorativeBox: /^[╔╗╚╝║═┌┐└┘│─┬┴├┤┼\+\|]{2,}/,
};

/**
 * Analyze raw blocks and detect layout structure.
 * Returns classified sections with empty content for template mode.
 */
export function analyzeLayout(rawBlocks: RawBlock[]): Section[] {
  const sections: Section[] = [];
  let sectionIdCounter = 0;

  const generateId = () => `section-${++sectionIdCounter}`;

  for (let i = 0; i < rawBlocks.length; i++) {
    const block = rawBlocks[i];

    // Skip empty lines (preserve as dividers if between content)
    if (block.isEmpty) {
      if (i > 0 && i < rawBlocks.length - 1 && !rawBlocks[i - 1].isEmpty) {
        sections.push(createSection(generateId(), "divider", 0, "", block));
      }
      continue;
    }

    const type = classifyBlock(block);
    const label = extractLabel(block, type);

    const section = createSection(generateId(), type, block.indentLevel, label, block);
    sections.push(section);
  }

  return nestSections(sections);
}

/** Classify a raw block into a semantic block type */
function classifyBlock(block: RawBlock): BlockType {
  const text = block.text.trim();

  if (LAYOUT_PATTERNS.dividerLine.test(text)) return "divider";
  if (LAYOUT_PATTERNS.signatureLine.test(text)) return "signature-block";
  if (LAYOUT_PATTERNS.checkbox.test(text)) return "checkbox";
  if (LAYOUT_PATTERNS.decorativeBox.test(text)) return "decorative-box";
  if (LAYOUT_PATTERNS.tableRow.test(text)) return "table";

  if (LAYOUT_PATTERNS.labelField.test(text)) return "field";

  if (block.isUpperCase && text.length > 2 && text.length < 80) return "header";
  if (block.hasNumbering) return "numbered-item";
  if (block.hasBullet) return "bulleted-item";

  // Detect subheaders: short lines that aren't all-caps but appear before content
  if (text.length < 60 && !text.endsWith(".") && !text.endsWith(",")) {
    const words = text.split(/\s+/);
    if (words.length <= 6 && /^[A-Z]/.test(text)) return "subheader";
  }

  if (text.length < 20) return "label";

  return "paragraph";
}

/** Extract label text from a block */
function extractLabel(block: RawBlock, type: BlockType): string {
  const text = block.text.trim();

  if (type === "field") {
    const match = text.match(LAYOUT_PATTERNS.labelField);
    return match ? match[1].trim() : "";
  }

  if (type === "header" || type === "subheader" || type === "label") {
    return text;
  }

  if (type === "numbered-item") {
    const match = text.match(/^\s*(\d+[\.\)\-])\s*/);
    return match ? match[1] : "";
  }

  return "";
}

/** Create a Section with empty content (template mode) */
function createSection(
  id: string,
  type: BlockType,
  depth: number,
  label: string,
  _block: RawBlock
): Section {
  return {
    id,
    type,
    depth,
    label,
    content: "",  // Always empty — template mode
    children: [],
    style: inferStyle(type, depth),
  };
}

/** Infer visual style from block type */
function inferStyle(type: BlockType, depth: number): SectionStyle {
  const styles: Record<string, SectionStyle> = {
    header: { fontSize: "24px", fontWeight: "bold", textAlign: "center" },
    subheader: { fontSize: "18px", fontWeight: "600", textAlign: "left" },
    paragraph: { fontSize: "14px", fontWeight: "normal" },
    "numbered-item": { fontSize: "14px", padding: `0 0 0 ${20 + depth * 15}px` },
    "bulleted-item": { fontSize: "14px", padding: `0 0 0 ${20 + depth * 15}px` },
    field: { fontSize: "14px", borderStyle: "1px solid #ccc", padding: "4px 8px" },
    label: { fontSize: "12px", fontWeight: "600", color: "#555" },
    table: { fontSize: "13px", borderStyle: "1px solid #999" },
    "signature-block": { fontSize: "14px", borderStyle: "none none solid none", margin: "30px 0" },
    checkbox: { fontSize: "14px", padding: "4px" },
    divider: { margin: "10px 0", borderStyle: "0 0 1px 0" },
    "decorative-box": { borderStyle: "2px solid #333", padding: "12px" },
    footer: { fontSize: "10px", color: "#888", textAlign: "center" },
  };

  return styles[type] || { fontSize: "14px" };
}

/** Nest sections based on depth to create hierarchy */
function nestSections(flatSections: Section[]): Section[] {
  const root: Section[] = [];
  const stack: Section[] = [];

  for (const section of flatSections) {
    // Find parent at lower depth
    while (stack.length > 0 && stack[stack.length - 1].depth >= section.depth) {
      stack.pop();
    }

    if (stack.length === 0) {
      root.push(section);
    } else {
      stack[stack.length - 1].children.push(section);
    }

    stack.push(section);
  }

  return root;
}
