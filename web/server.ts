// ─────────────────────────────────────────────────────────────
// Web Server — Live template preview and editing server
// ─────────────────────────────────────────────────────────────

import http from "http";
import fs from "fs";
import path from "path";
import { DocumentObject } from "../schema/documentSchema";
import { generateHTMLTemplate } from "../transform/templateGenerator";
import { getBrand } from "../styles/brandConfig";

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

interface WebServerOptions {
  port?: number;
  outputDir: string;
  brand?: string;
}

/**
 * Launch a local web server to preview and interact with generated templates.
 */
export function startWebServer(options: WebServerOptions): http.Server {
  const { port = 3000, outputDir, brand = "clean" } = options;
  const brandConfig = getBrand(brand);

  const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", `http://localhost:${port}`);
    const pathname = url.pathname;

    // ── API Routes ────────────────────────────────────────────
    if (pathname === "/api/files") {
      return serveFileList(outputDir, res);
    }

    if (pathname === "/api/document" && url.searchParams.has("file")) {
      return serveDocument(outputDir, url.searchParams.get("file")!, res);
    }

    // ── Dashboard ─────────────────────────────────────────────
    if (pathname === "/" || pathname === "/index.html") {
      return serveDashboard(outputDir, brand, res);
    }

    // ── Static Files from output ──────────────────────────────
    const filePath = path.join(outputDir, pathname.slice(1));
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath);
      res.writeHead(200, { "Content-Type": MIME_TYPES[ext] || "application/octet-stream" });
      fs.createReadStream(filePath).pipe(res);
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
  });

  server.listen(port, () => {
    console.log("═══════════════════════════════════════════════════════");
    console.log("  WEB SERVER — Live Template Preview");
    console.log("═══════════════════════════════════════════════════════");
    console.log(`  Dashboard: http://localhost:${port}`);
    console.log(`  Output:    ${path.resolve(outputDir)}`);
    console.log("  Press Ctrl+C to stop");
    console.log("");
  });

  return server;
}

function serveFileList(outputDir: string, res: http.ServerResponse): void {
  if (!fs.existsSync(outputDir)) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify([]));
    return;
  }

  const files = fs.readdirSync(outputDir)
    .filter((f) => !fs.statSync(path.join(outputDir, f)).isDirectory())
    .map((f) => {
      const stat = fs.statSync(path.join(outputDir, f));
      return {
        name: f,
        ext: path.extname(f),
        size: stat.size,
        modified: stat.mtime.toISOString(),
      };
    });

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(files, null, 2));
}

function serveDocument(outputDir: string, filename: string, res: http.ServerResponse): void {
  const filePath = path.join(outputDir, filename);
  if (!fs.existsSync(filePath)) {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "File not found" }));
    return;
  }

  const ext = path.extname(filePath);
  res.writeHead(200, { "Content-Type": MIME_TYPES[ext] || "application/octet-stream" });
  fs.createReadStream(filePath).pipe(res);
}

function serveDashboard(outputDir: string, brand: string, res: http.ServerResponse): void {
  const brandConfig = getBrand(brand);
  const files = fs.existsSync(outputDir)
    ? fs.readdirSync(outputDir).filter((f) => !fs.statSync(path.join(outputDir, f)).isDirectory())
    : [];

  const htmlFiles = files.filter((f) => f.endsWith(".html"));
  const jsonFiles = files.filter((f) => f.endsWith(".json"));
  const pdfFiles = files.filter((f) => f.endsWith(".pdf"));
  const otherFiles = files.filter((f) => !f.endsWith(".html") && !f.endsWith(".json") && !f.endsWith(".pdf"));

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Document Intelligence Engine — Dashboard</title>
  <style>
    :root {
      --primary: ${brandConfig.colors.primary};
      --accent: ${brandConfig.colors.accent};
      --bg: #f8f9fa;
      --card-bg: #ffffff;
      --text: #2c3e50;
      --text-muted: #7f8c8d;
      --border: #e0e0e0;
      --radius: 8px;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: ${brandConfig.fonts.body}, system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
    }

    header {
      background: var(--primary);
      color: white;
      padding: 24px 40px;
      display: flex;
      align-items: center;
      gap: 16px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    }

    header h1 {
      font-family: ${brandConfig.fonts.heading}, sans-serif;
      font-size: 1.5rem;
      font-weight: 700;
    }

    header .subtitle {
      opacity: 0.8;
      font-size: 0.9rem;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 24px;
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }

    .stat-card {
      background: var(--card-bg);
      border-radius: var(--radius);
      padding: 20px;
      border: 1px solid var(--border);
      text-align: center;
    }

    .stat-card .number {
      font-size: 2rem;
      font-weight: 700;
      color: var(--primary);
    }

    .stat-card .label {
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-top: 4px;
    }

    h2 {
      font-family: ${brandConfig.fonts.heading}, sans-serif;
      font-size: 1.2rem;
      margin-bottom: 16px;
      color: var(--primary);
      border-bottom: 2px solid var(--accent);
      padding-bottom: 8px;
    }

    .file-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 12px;
      margin-bottom: 32px;
    }

    .file-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 16px;
      display: flex;
      align-items: center;
      gap: 12px;
      transition: border-color 0.2s, box-shadow 0.2s;
      cursor: pointer;
      text-decoration: none;
      color: inherit;
    }

    .file-card:hover {
      border-color: var(--accent);
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }

    .file-icon {
      width: 40px;
      height: 40px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 0.75rem;
      color: white;
      flex-shrink: 0;
    }

    .file-icon.html { background: #e74c3c; }
    .file-icon.json { background: #f39c12; }
    .file-icon.pdf { background: #c0392b; }
    .file-icon.css { background: #3498db; }
    .file-icon.xml { background: #27ae60; }
    .file-icon.other { background: #95a5a6; }

    .file-info h3 {
      font-size: 0.95rem;
      font-weight: 600;
      word-break: break-all;
    }

    .file-info .meta {
      color: var(--text-muted);
      font-size: 0.8rem;
      margin-top: 2px;
    }

    .preview-frame {
      width: 100%;
      height: 600px;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: white;
      margin-top: 16px;
    }

    .empty-state {
      text-align: center;
      padding: 48px 24px;
      color: var(--text-muted);
    }

    .empty-state .icon { font-size: 3rem; margin-bottom: 16px; }

    footer {
      text-align: center;
      padding: 24px;
      color: var(--text-muted);
      font-size: 0.85rem;
      border-top: 1px solid var(--border);
      margin-top: 48px;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Document Intelligence Engine</h1>
      <div class="subtitle">Template Dashboard — ${brand.toUpperCase()} Brand</div>
    </div>
  </header>

  <div class="container">
    <div class="stats">
      <div class="stat-card">
        <div class="number">${files.length}</div>
        <div class="label">Total Files</div>
      </div>
      <div class="stat-card">
        <div class="number">${htmlFiles.length}</div>
        <div class="label">HTML Templates</div>
      </div>
      <div class="stat-card">
        <div class="number">${jsonFiles.length}</div>
        <div class="label">JSON Documents</div>
      </div>
      <div class="stat-card">
        <div class="number">${pdfFiles.length}</div>
        <div class="label">PDF Exports</div>
      </div>
    </div>

    ${htmlFiles.length > 0 ? `
    <h2>HTML Templates</h2>
    <div class="file-grid">
      ${htmlFiles.map((f) => `
        <a class="file-card" href="/${f}" target="_blank">
          <div class="file-icon html">HTML</div>
          <div class="file-info">
            <h3>${f}</h3>
            <div class="meta">${formatFileSize(fs.statSync(path.join(outputDir, f)).size)}</div>
          </div>
        </a>
      `).join("")}
    </div>
    ` : ""}

    ${jsonFiles.length > 0 ? `
    <h2>JSON Documents</h2>
    <div class="file-grid">
      ${jsonFiles.map((f) => `
        <a class="file-card" href="/${f}" target="_blank">
          <div class="file-icon json">JSON</div>
          <div class="file-info">
            <h3>${f}</h3>
            <div class="meta">${formatFileSize(fs.statSync(path.join(outputDir, f)).size)}</div>
          </div>
        </a>
      `).join("")}
    </div>
    ` : ""}

    ${pdfFiles.length > 0 ? `
    <h2>PDF Exports</h2>
    <div class="file-grid">
      ${pdfFiles.map((f) => `
        <a class="file-card" href="/${f}" target="_blank">
          <div class="file-icon pdf">PDF</div>
          <div class="file-info">
            <h3>${f}</h3>
            <div class="meta">${formatFileSize(fs.statSync(path.join(outputDir, f)).size)}</div>
          </div>
        </a>
      `).join("")}
    </div>
    ` : ""}

    ${otherFiles.length > 0 ? `
    <h2>Other Files</h2>
    <div class="file-grid">
      ${otherFiles.map((f) => {
        const ext = path.extname(f).replace(".", "").toUpperCase();
        const iconClass = ext === "CSS" ? "css" : ext === "XML" ? "xml" : "other";
        return `
        <a class="file-card" href="/${f}" target="_blank">
          <div class="file-icon ${iconClass}">${ext}</div>
          <div class="file-info">
            <h3>${f}</h3>
            <div class="meta">${formatFileSize(fs.statSync(path.join(outputDir, f)).size)}</div>
          </div>
        </a>
        `;
      }).join("")}
    </div>
    ` : ""}

    ${files.length === 0 ? `
    <div class="empty-state">
      <div class="icon">📄</div>
      <p>No output files yet. Process a document to see results here.</p>
    </div>
    ` : ""}

    ${htmlFiles.length > 0 ? `
    <h2>Preview</h2>
    <iframe class="preview-frame" src="/${htmlFiles[0]}"></iframe>
    ` : ""}
  </div>

  <footer>
    Document Intelligence Engine v1.0.0 — From The Hart
  </footer>
</body>
</html>`;

  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(html);
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
