// ─────────────────────────────────────────────────────────────
// PDF Export — Render HTML template to printable PDF
// ─────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import puppeteer from "puppeteer";

// ── Browser Detection ────────────────────────────────────────
// Puppeteer's bundled Chromium can fail on some systems.
// Auto-detect a system Chrome/Edge as fallback.

function findSystemBrowser(): string | undefined {
  const candidates = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return undefined;
}

async function launchBrowser() {
  const launchArgs = ["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"];

  // Try Puppeteer's bundled browser first
  try {
    return await puppeteer.launch({ headless: true, args: launchArgs });
  } catch (_) {
    // Fallback to system browser
    const execPath = findSystemBrowser();
    if (!execPath) {
      throw new Error(
        "No Chromium-based browser found. Install Chrome or Edge for PDF export."
      );
    }
    console.log(`[EXPORT] Using system browser: ${path.basename(execPath)}`);
    return await puppeteer.launch({
      headless: true,
      executablePath: execPath,
      args: launchArgs,
    });
  }
}

/**
 * Export an HTML file to PDF using Puppeteer.
 */
export async function exportPDF(
  htmlPath: string,
  outputDir: string,
  options?: {
    filename?: string;
    format?: "A4" | "Letter" | "Legal";
    landscape?: boolean;
    margin?: { top?: string; right?: string; bottom?: string; left?: string };
    headerTemplate?: string;
    footerTemplate?: string;
    displayHeaderFooter?: boolean;
  }
): Promise<string> {
  if (!fs.existsSync(htmlPath)) {
    throw new Error(`HTML file not found: ${htmlPath}`);
  }

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const baseName = options?.filename || path.basename(htmlPath, ".html");
  const pdfPath = path.join(outputDir, `${baseName}.pdf`);

  console.log(`[EXPORT] Launching browser for PDF render...`);

  const browser = await launchBrowser();

  try {
    const page = await browser.newPage();

    // Load the HTML file
    const resolvedPath = path.resolve(htmlPath).replace(/\\/g, "/");
    const fileUrl = `file:///${resolvedPath.replace(/^\//, "")}`;
    await page.goto(fileUrl, { waitUntil: "networkidle0" });

    // Generate PDF
    await page.pdf({
      path: pdfPath,
      format: options?.format || "A4",
      landscape: options?.landscape || false,
      printBackground: true,
      margin: options?.margin || {
        top: "20mm",
        right: "15mm",
        bottom: "20mm",
        left: "15mm",
      },
      displayHeaderFooter: options?.displayHeaderFooter || false,
      headerTemplate: options?.headerTemplate || "",
      footerTemplate: options?.footerTemplate || `
        <div style="font-size: 9px; color: #999; width: 100%; text-align: center; padding: 5px;">
          Page <span class="pageNumber"></span> of <span class="totalPages"></span>
        </div>
      `,
    });

    console.log(`[EXPORT] PDF → ${pdfPath}`);
    return pdfPath;
  } finally {
    await browser.close();
  }
}

/**
 * Export an HTML string directly to PDF (without needing a file on disk).
 */
export async function exportHTMLStringToPDF(
  htmlContent: string,
  outputPath: string,
  options?: {
    format?: "A4" | "Letter" | "Legal";
    landscape?: boolean;
  }
): Promise<string> {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const browser = await launchBrowser();

  try {
    const page = await browser.newPage();
    await page.setContent(htmlContent, { waitUntil: "networkidle0" });

    await page.pdf({
      path: outputPath,
      format: options?.format || "A4",
      landscape: options?.landscape || false,
      printBackground: true,
      margin: { top: "20mm", right: "15mm", bottom: "20mm", left: "15mm" },
    });

    console.log(`[EXPORT] PDF → ${outputPath}`);
    return outputPath;
  } finally {
    await browser.close();
  }
}
