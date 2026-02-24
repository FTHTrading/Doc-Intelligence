// ─────────────────────────────────────────────────────────────
// Folder Manager — Sovereign Document Organization
//
// Structured folder hierarchy:
//   /Agreements/ClientName/Year/SKU/
//     ├── draft.docx
//     ├── signed.pdf
//     ├── audit.json
//     ├── cid.txt
//     ├── signature-state.json
//     └── qr-verify.svg
//
// Folder state mirrors registry state.
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";

export interface FolderStructure {
  /** Root output directory */
  rootDir: string;
  /** Client/counterparty name */
  clientName: string;
  /** Year */
  year: number;
  /** Document SKU */
  sku: string;
  /** Full resolved path */
  fullPath: string;
}

export interface FolderContents {
  structure: FolderStructure;
  files: string[];
  totalSize: number;
}

/**
 * Create the organized folder structure for a document.
 * Returns the full path to the document folder.
 */
export function createDocumentFolder(
  rootDir: string,
  options: {
    clientName?: string;
    year?: number;
    sku?: string;
    category?: string;
  } = {}
): FolderStructure {
  const clientName = sanitizeFolderName(options.clientName || "General");
  const year = options.year || new Date().getFullYear();
  const sku = options.sku || "UNASSIGNED";
  const category = options.category || "Agreements";

  const fullPath = path.join(rootDir, category, clientName, year.toString(), sku);

  if (!fs.existsSync(fullPath)) {
    fs.mkdirSync(fullPath, { recursive: true });
  }

  return {
    rootDir,
    clientName,
    year,
    sku,
    fullPath,
  };
}

/**
 * Move a file into the organized folder structure.
 */
export function moveToFolder(
  sourcePath: string,
  folder: FolderStructure,
  targetFilename?: string
): string {
  const filename = targetFilename || path.basename(sourcePath);
  const destPath = path.join(folder.fullPath, filename);

  // Ensure destination directory exists
  if (!fs.existsSync(folder.fullPath)) {
    fs.mkdirSync(folder.fullPath, { recursive: true });
  }

  // Copy file (rather than move, to avoid cross-device issues)
  fs.copyFileSync(sourcePath, destPath);
  return destPath;
}

/**
 * Copy generated output files into the organized folder.
 */
export function organizeOutputFiles(
  outputDir: string,
  folder: FolderStructure
): string[] {
  const movedFiles: string[] = [];

  if (!fs.existsSync(outputDir)) return movedFiles;

  const files = fs.readdirSync(outputDir);

  for (const file of files) {
    const sourcePath = path.join(outputDir, file);
    const stat = fs.statSync(sourcePath);
    if (!stat.isFile()) continue;

    const destPath = path.join(folder.fullPath, file);
    fs.copyFileSync(sourcePath, destPath);
    movedFiles.push(destPath);
  }

  return movedFiles;
}

/**
 * List contents of a document folder.
 */
export function listFolderContents(folder: FolderStructure): FolderContents {
  const files: string[] = [];
  let totalSize = 0;

  if (fs.existsSync(folder.fullPath)) {
    const entries = fs.readdirSync(folder.fullPath);
    for (const entry of entries) {
      const fullPath = path.join(folder.fullPath, entry);
      const stat = fs.statSync(fullPath);
      if (stat.isFile()) {
        files.push(entry);
        totalSize += stat.size;
      }
    }
  }

  return { structure: folder, files, totalSize };
}

/**
 * Get a directory tree summary for the root output.
 */
export function getFolderTree(rootDir: string, depth: number = 4): string {
  const lines: string[] = [];

  const walk = (dir: string, prefix: string, currentDepth: number) => {
    if (currentDepth > depth) return;
    if (!fs.existsSync(dir)) return;

    const entries = fs.readdirSync(dir).sort();
    const dirs = entries.filter((e) => {
      try { return fs.statSync(path.join(dir, e)).isDirectory(); } catch { return false; }
    });
    const files = entries.filter((e) => {
      try { return fs.statSync(path.join(dir, e)).isFile(); } catch { return false; }
    });

    for (let i = 0; i < dirs.length; i++) {
      const isLast = i === dirs.length - 1 && files.length === 0;
      lines.push(`${prefix}${isLast ? "└── " : "├── "}${dirs[i]}/`);
      walk(path.join(dir, dirs[i]), prefix + (isLast ? "    " : "│   "), currentDepth + 1);
    }

    for (let i = 0; i < files.length; i++) {
      const isLast = i === files.length - 1;
      lines.push(`${prefix}${isLast ? "└── " : "├── "}${files[i]}`);
    }
  };

  lines.push(rootDir);
  walk(rootDir, "", 0);
  return lines.join("\n");
}

/**
 * Generate a manifest.json for a document folder.
 */
export function generateFolderManifest(
  folder: FolderStructure,
  metadata?: Record<string, string>
): string {
  const contents = listFolderContents(folder);

  const manifest = {
    manifestVersion: "1.0",
    generatedAt: new Date().toISOString(),
    folder: {
      clientName: folder.clientName,
      year: folder.year,
      sku: folder.sku,
      path: folder.fullPath,
    },
    files: contents.files.map((f) => {
      const stat = fs.statSync(path.join(folder.fullPath, f));
      return {
        name: f,
        size: stat.size,
        modified: stat.mtime.toISOString(),
      };
    }),
    totalFiles: contents.files.length,
    totalSize: contents.totalSize,
    metadata: metadata || {},
  };

  const manifestPath = path.join(folder.fullPath, "manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf-8");
  return manifestPath;
}

// ── Helpers ──────────────────────────────────────────────────

/**
 * Sanitize a string for use as a folder name.
 */
function sanitizeFolderName(name: string): string {
  return name
    .replace(/[<>:"/\\|?*]/g, "-")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .substring(0, 100)
    || "Unknown";
}
