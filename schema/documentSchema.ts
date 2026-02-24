// ─────────────────────────────────────────────────────────────
// Document Intelligence Engine — Core Schema Definitions
// ─────────────────────────────────────────────────────────────

/** Supported input file types */
export type InputFormat = "pdf" | "docx" | "png" | "jpg" | "html" | "txt" | "md";

/** Semantic block types detected during parsing */
export type BlockType =
  | "header"
  | "subheader"
  | "paragraph"
  | "numbered-item"
  | "bulleted-item"
  | "table"
  | "image-placeholder"
  | "signature-block"
  | "divider"
  | "footer"
  | "label"
  | "field"
  | "checkbox"
  | "decorative-box"
  | "unknown";

/** A single structural section within a document */
export interface Section {
  id: string;
  type: BlockType;
  depth: number;           // nesting depth (0 = root)
  label: string;           // detected label text (e.g. "Name:", "Date:")
  content: string;         // always empty in template mode
  children: Section[];
  style: SectionStyle;
}

/** Visual style attributes for a section */
export interface SectionStyle {
  fontFamily?: string;
  fontSize?: string;
  fontWeight?: string;
  textAlign?: string;
  color?: string;
  backgroundColor?: string;
  borderStyle?: string;
  padding?: string;
  margin?: string;
  width?: string;
  height?: string;
}

/** Extracted style map across the entire document */
export interface StyleMap {
  primaryFont: string;
  secondaryFont: string;
  headingSize: string;
  bodySize: string;
  primaryColor: string;
  secondaryColor: string;
  accentColor: string;
  backgroundColor: string;
  lineHeight: string;
}

/** A reusable component detected in the document */
export interface Component {
  id: string;
  name: string;
  type: "table" | "list" | "form-field" | "image-block" | "text-block" | "signature" | "checkbox-group";
  columns?: number;
  rows?: number;
  fields?: string[];
  style: SectionStyle;
}

/** Metadata about the ingested document */
export interface DocumentMetadata {
  title: string;
  type: InputFormat;
  pageCount: number;
  sourceFile: string;
  ingestedAt: string;       // ISO timestamp
  language: string;
  dimensions?: {
    width: number;
    height: number;
    unit: string;
  };
}

/** The master document object — all transformations operate on this */
export interface DocumentObject {
  metadata: DocumentMetadata;
  structure: Section[];
  styles: StyleMap;
  components: Component[];
  semanticTags: string[];
}

/** Document fingerprint for integrity & compliance */
export interface DocumentFingerprint {
  sha256: string;
  merkleRoot: string;
  version: string;
  timestamp: number;
  sourceHash: string;
}

/** Export mode selection */
export type ExportMode =
  | "template"     // Empty replica
  | "governance"   // DAO proposal JSON
  | "compliance"   // Legal structured PDF
  | "brand"        // Styled enterprise doc
  | "web"          // Editable HTML
  | "archive";     // Hash + Merkle record

/** Transformation rule for rule-based document conversion */
export interface TransformationRule {
  id: string;
  match: string;            // regex or literal match
  replaceWith: string;
  injectAfter?: string;
  injectBefore?: string;
  styleOverride?: Partial<SectionStyle>;
  condition?: string;       // optional condition expression
}

/** Result of an ingest operation */
export interface IngestResult {
  rawText: string;
  format: InputFormat;
  pageCount: number;
  rawBlocks: RawBlock[];
  metadata: Partial<DocumentMetadata>;
}

/** A raw block extracted before semantic classification */
export interface RawBlock {
  text: string;
  lineNumber: number;
  indentLevel: number;
  isUpperCase: boolean;
  hasNumbering: boolean;
  hasBullet: boolean;
  isEmpty: boolean;
}
