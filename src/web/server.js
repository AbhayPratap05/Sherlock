#!/usr/bin/env node
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = parseInt(process.env.PORT || "3000", 10);
const OUT_DIR = path.resolve(__dirname, "../../out");
const PUBLIC_DIR = path.resolve(__dirname, "public");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js":   "application/javascript; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".ico":  "image/x-icon",
};

function listStems() {
  try {
    return fs.readdirSync(OUT_DIR)
      .filter(f => f.endsWith(".json"))
      .map(f => f.replace(".json", ""));
  } catch { return []; }
}

function send(res, status, body, type) {
  const buf = typeof body === "string" ? Buffer.from(body) : body;
  res.writeHead(status, { "Content-Type": type || "application/json", "Content-Length": buf.length, "Access-Control-Allow-Origin": "*" });
  res.end(buf);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost`);
  const p = url.pathname;

  if (p === "/api/health") {
    return send(res, 200, JSON.stringify({ ok: true }), "application/json");
  }

  if (p === "/api/analysis") {
    return send(res, 200, JSON.stringify(listStems()), "application/json");
  }

  if (p.startsWith("/api/analysis/")) {
    const stem = path.basename(p);
    const file = path.join(OUT_DIR, stem + ".json");
    if (!fs.existsSync(file)) return send(res, 404, JSON.stringify({ error: "not found" }));
    const data = fs.readFileSync(file);
    return send(res, 200, data, "application/json");
  }

  // Serve static files from public/
  let filePath = p === "/" ? "/index.html" : p;
  const full = path.join(PUBLIC_DIR, filePath);
  if (fs.existsSync(full) && fs.statSync(full).isFile()) {
    const ext = path.extname(full);
    return send(res, 200, fs.readFileSync(full), MIME[ext] || "application/octet-stream");
  }

  // SPA fallback
  const index = path.join(PUBLIC_DIR, "index.html");
  if (fs.existsSync(index)) return send(res, 200, fs.readFileSync(index), "text/html; charset=utf-8");
  return send(res, 404, JSON.stringify({ error: "not found" }));
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`http://127.0.0.1:${PORT}`);
});
