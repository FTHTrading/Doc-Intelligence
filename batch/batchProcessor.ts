// ─────────────────────────────────────────────────────────────
// Batch Processor — Process multiple documents in a directory
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";

const SUPPORTED_EXTENSIONS = new Set([
  ".pdf", ".docx", ".doc",
  ".png", ".jpg", ".jpeg",
  ".html", ".htm",
  ".txt", ".md", ".markdown",
]);

export interface BatchResult {
  total: number;
  succeeded: number;
  failed: number;
  skipped: number;
  results: {
    file: string;
    status: "success" | "failed" | "skipped";
    error?: string;
    outputDir?: string;
    duration?: number;
  }[];
}

/**
 * Discover all supported documents in a directory (non-recursive by default).
 */
export function discoverDocuments(dir: string, recursive = false): string[] {
  if (!fs.existsSync(dir)) {
    throw new Error(`Directory not found: ${dir}`);
  }

  const files: string[] = [];

  const walk = (currentDir: string) => {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory() && recursive) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SUPPORTED_EXTENSIONS.has(ext)) {
          files.push(fullPath);
        }
      }
    }
  };

  walk(dir);
  return files.sort();
}

/**
 * Run a processing function across all discovered documents.
 * Creates per-document output subdirectories to avoid collisions.
 */
export async function processBatch(
  inputDir: string,
  outputBaseDir: string,
  processFn: (filePath: string, outputDir: string) => Promise<void>,
  options?: {
    recursive?: boolean;
    continueOnError?: boolean;
    concurrency?: number;
  }
): Promise<BatchResult> {
  const files = discoverDocuments(inputDir, options?.recursive);
  const result: BatchResult = {
    total: files.length,
    succeeded: 0,
    failed: 0,
    skipped: 0,
    results: [],
  };

  if (files.length === 0) {
    console.log(`[BATCH] No supported documents found in ${inputDir}`);
    return result;
  }

  console.log(`[BATCH] Found ${files.length} document(s) to process`);
  console.log("");

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const baseName = path.basename(file, path.extname(file));
    const docOutputDir = path.join(outputBaseDir, baseName);

    console.log(`[BATCH] (${i + 1}/${files.length}) ${path.basename(file)}`);
    const start = Date.now();

    try {
      if (!fs.existsSync(docOutputDir)) {
        fs.mkdirSync(docOutputDir, { recursive: true });
      }

      await processFn(file, docOutputDir);

      const duration = Date.now() - start;
      result.succeeded++;
      result.results.push({
        file: path.basename(file),
        status: "success",
        outputDir: docOutputDir,
        duration,
      });
      console.log(`[BATCH] ✓ Completed in ${duration}ms`);
    } catch (err: any) {
      const duration = Date.now() - start;
      result.failed++;
      result.results.push({
        file: path.basename(file),
        status: "failed",
        error: err.message || String(err),
        duration,
      });
      console.error(`[BATCH] ✗ Failed: ${err.message}`);

      if (!options?.continueOnError) {
        throw new Error(`Batch aborted at ${path.basename(file)}: ${err.message}`);
      }
    }

    console.log("");
  }

  return result;
}

/**
 * Print a summary table of batch results.
 */
export function printBatchSummary(result: BatchResult): void {
  console.log("═══════════════════════════════════════════════════════");
  console.log("  BATCH SUMMARY");
  console.log("═══════════════════════════════════════════════════════");
  console.log(`  Total:     ${result.total}`);
  console.log(`  Succeeded: ${result.succeeded}`);
  console.log(`  Failed:    ${result.failed}`);
  console.log(`  Skipped:   ${result.skipped}`);
  console.log("");

  if (result.failed > 0) {
    console.log("  FAILURES:");
    for (const r of result.results.filter((r) => r.status === "failed")) {
      console.log(`    - ${r.file}: ${r.error}`);
    }
    console.log("");
  }

  const totalTime = result.results.reduce((sum, r) => sum + (r.duration || 0), 0);
  console.log(`  Total time: ${(totalTime / 1000).toFixed(1)}s`);
  console.log("");
}
