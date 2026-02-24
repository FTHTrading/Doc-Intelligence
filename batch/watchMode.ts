// ─────────────────────────────────────────────────────────────
// Watch Mode — Auto-reprocess documents when files change
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";

const SUPPORTED_EXTENSIONS = new Set([
  ".pdf", ".docx", ".doc",
  ".png", ".jpg", ".jpeg",
  ".html", ".htm",
  ".txt", ".md", ".markdown",
]);

interface WatchOptions {
  inputDir: string;
  outputDir: string;
  processFn: (filePath: string, outputDir: string) => Promise<void>;
  debounceMs?: number;
}

/**
 * Watch a directory for new/modified documents and auto-process them.
 */
export function watchDirectory(options: WatchOptions): void {
  const { inputDir, outputDir, processFn, debounceMs = 1000 } = options;

  if (!fs.existsSync(inputDir)) {
    fs.mkdirSync(inputDir, { recursive: true });
  }

  console.log("═══════════════════════════════════════════════════════");
  console.log("  WATCH MODE — Monitoring for changes");
  console.log("═══════════════════════════════════════════════════════");
  console.log(`  Input:  ${path.resolve(inputDir)}`);
  console.log(`  Output: ${path.resolve(outputDir)}`);
  console.log("  Press Ctrl+C to stop");
  console.log("");

  const pending = new Map<string, NodeJS.Timeout>();

  const watcher = fs.watch(inputDir, { recursive: false }, (eventType, filename) => {
    if (!filename) return;

    const ext = path.extname(filename).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.has(ext)) return;

    const fullPath = path.join(inputDir, filename);

    // Debounce — wait for file write to complete
    if (pending.has(filename)) {
      clearTimeout(pending.get(filename)!);
    }

    pending.set(
      filename,
      setTimeout(async () => {
        pending.delete(filename);

        if (!fs.existsSync(fullPath)) {
          console.log(`[WATCH] Deleted: ${filename}`);
          return;
        }

        console.log(`[WATCH] Detected ${eventType}: ${filename}`);
        const baseName = path.basename(filename, ext);
        const docOutputDir = path.join(outputDir, baseName);

        if (!fs.existsSync(docOutputDir)) {
          fs.mkdirSync(docOutputDir, { recursive: true });
        }

        try {
          const start = Date.now();
          await processFn(fullPath, docOutputDir);
          console.log(`[WATCH] ✓ Processed ${filename} in ${Date.now() - start}ms`);
        } catch (err: any) {
          console.error(`[WATCH] ✗ Error processing ${filename}: ${err.message}`);
        }

        console.log("[WATCH] Waiting for changes...");
        console.log("");
      }, debounceMs)
    );
  });

  console.log("[WATCH] Waiting for changes...");
  console.log("");

  // Handle graceful shutdown
  process.on("SIGINT", () => {
    console.log("\n[WATCH] Shutting down...");
    watcher.close();
    for (const timeout of pending.values()) clearTimeout(timeout);
    process.exit(0);
  });
}
