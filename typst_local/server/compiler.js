// Main-thread client for the Typst compiler. Requests are processed strictly in
// order, which is what keeps per-project file deltas consistent.
//
// Uses the native incremental engine (engine/, built to bin/typst-engine) when
// it exists, and falls back to the typst-ts worker otherwise. Both produce the
// same result shape: {status, diagnostics, pages, ms, preview?, pdf?}.
import { Worker } from 'node:worker_threads';
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FONTS_DIR } from './storage.js';
import { fontFamilies } from './font-names.js';

const ENGINE_BIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'typst-engine');

const sha1 = (s) => crypto.createHash('sha1').update(s).digest('hex');

// ---- helpers shared by both backends ----------------------------------------

/** Replaces inline base64 images with URLs; returns images not handed over before. */
export function extractImages(svg, imageBase, sentImages) {
  const images = [];
  const byData = new Map();
  const out = svg.replace(/data:(image\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=]+)/g, (_, mime, b64) => {
    let hash = byData.get(b64);
    if (!hash) {
      hash = sha1(b64);
      byData.set(b64, hash);
      if (!sentImages.has(hash)) {
        sentImages.add(hash);
        images.push({ hash, mime, data: Buffer.from(b64, 'base64') });
      }
    }
    return imageBase + hash;
  });
  return { svg: out, images };
}

const familyCache = new Map();
function familiesOf(file) {
  if (!familyCache.has(file)) {
    try {
      familyCache.set(file, fontFamilies(fs.readFileSync(file)));
    } catch {
      familyCache.set(file, []);
    }
  }
  return familyCache.get(file);
}

/** Adds the names the available fonts provide to "unknown font family" messages. */
function addFontHints(diagnostics, projectFonts) {
  if (!diagnostics.some((d) => /^unknown font family/.test(d.message))) return;
  const files = [...projectFonts];
  try {
    for (const f of fs.readdirSync(FONTS_DIR)) if (/\.(ttf|otf|ttc|otc)$/i.test(f)) files.push(path.join(FONTS_DIR, f));
  } catch {}
  const names = [...new Set(files.flatMap(familiesOf))].sort();
  const builtIn = '(built-in: "Libertinus Serif", "New Computer Modern", "DejaVu Sans Mono")';
  const hint = names.length
    ? `font files in this project provide: ${names.map((n) => `"${n}"`).join(', ')} ${builtIn}`
    : `add .ttf or .otf files anywhere in the project to use them ${builtIn}`;
  for (const d of diagnostics) if (/^unknown font family/.test(d.message)) d.hints = [...(d.hints || []), hint];
}

// ---- native engine ----------------------------------------------------------

class EngineBackend extends EventEmitter {
  constructor() {
    super();
    this.nextId = 1;
    this.pending = new Map();
    this.projects = new Map(); // project -> {sentImages, fonts}
    this.spawn();
  }

  spawn() {
    const proc = (this.proc = spawn(ENGINE_BIN, [], {
      stdio: ['pipe', 'pipe', 'inherit'],
      env: { ...process.env, TYPST_FONT_LIBRARY: FONTS_DIR },
    }));
    // Responses are newline-delimited JSON; only scan new data for line breaks.
    let chunks = [];
    proc.stdout.on('data', (data) => {
      let start = 0;
      for (let i = data.indexOf(10); i !== -1; i = data.indexOf(10, start)) {
        chunks.push(data.subarray(start, i));
        const line = Buffer.concat(chunks).toString('utf8');
        chunks = [];
        start = i + 1;
        this.onResponse(line);
      }
      if (start < data.length) chunks.push(data.subarray(start));
    });
    proc.on('exit', (code, signal) => {
      if (this.proc !== proc) return;
      console.error(`[compile] engine exited (${signal || code}), restarting`);
      for (const p of this.pending.values()) p.reject(new Error('compiler crashed'));
      this.pending.clear();
      this.projects.clear();
      this.spawn();
      this.emit('reset');
    });
  }

  onResponse(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    const p = this.pending.get(msg.id);
    if (!p) return;
    this.pending.delete(msg.id);
    if (p.raw) return p.resolve(msg);
    try {
      p.resolve(this.finish(p.request, msg));
    } catch (e) {
      p.reject(e);
    }
  }

  state(project) {
    if (!this.projects.has(project)) this.projects.set(project, { sentImages: new Set(), fonts: [] });
    return this.projects.get(project);
  }

  /** Turns an engine response into the shared result shape. */
  finish(request, msg) {
    const st = this.state(request.project);
    addFontHints(msg.diagnostics, st.fonts);
    const out = { status: msg.status, diagnostics: msg.diagnostics, pages: msg.numPages, ms: msg.ms, outline: msg.outline, html: msg.html, style: msg.style, deps: msg.deps };
    if (request.pdfPath) {
      if (msg.pdf) out.pdf = fs.readFileSync(request.pdfPath);
      fs.rmSync(request.pdfPath, { force: true });
    }
    if (msg.pages) {
      const images = [];
      const glyphs = {};
      const pages = msg.pages.map((p) => {
        if (p.svg === undefined) return p;
        const extracted = extractImages(p.svg, request.imageBase, st.sentImages);
        images.push(...extracted.images);
        // Drop pretty-printing, and pool glyph shapes: every page embeds the
        // glyphs it uses, but ids are content hashes, so one copy serves all.
        const svg = extracted.svg
          .replace(/>\s+</g, '><')
          .replace(/<symbol id="([^"]+)"[^>]*>[\s\S]*?<\/symbol>/g, (m, id) => ((glyphs[id] = m), ''));
        return { ...p, svg };
      });
      out.preview = { defs: '', defsHash: 'engine', pages, images, glyphs };
    }
    return out;
  }

  request(msg) {
    const id = this.nextId++;
    const st = this.state(msg.project);
    if (msg.fonts) st.fonts = msg.fonts;
    const request = { project: msg.project, imageBase: msg.imageBase };
    const payload = {
      type: 'compile',
      id,
      project: msg.project,
      main: msg.main,
      set: msg.set,
      remove: msg.remove,
      fonts: msg.fonts,
      full: !!msg.full,
      html: !!msg.html,
      deps: !!msg.deps,
    };
    if (msg.pdf) {
      request.pdfPath = path.join(os.tmpdir(), `typst-local-${process.pid}-${id}.pdf`);
      payload.pdf = request.pdfPath;
    }
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, request });
      this.proc.stdin.write(JSON.stringify(payload) + '\n');
    });
  }

  raw(payload) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, raw: true });
      this.proc.stdin.write(JSON.stringify({ ...payload, id }) + '\n');
    });
  }

  /** Maps a click on page `page` (0-based) at (x, y) in pt to a source location. */
  jump(project, page, x, y) {
    return this.raw({ type: 'jump', project, page, x, y });
  }

  /** Maps a cursor (UTF-16 offset into `path`) to a point in the preview. */
  cursor(project, path, offset) {
    return this.raw({ type: 'cursor', project, path, offset });
  }

  drop(project) {
    this.projects.delete(project);
    this.proc.stdin.write(JSON.stringify({ type: 'drop', project }) + '\n');
  }
}

// ---- typst-ts fallback ------------------------------------------------------

class WorkerBackend extends EventEmitter {
  constructor() {
    super();
    this.nextId = 1;
    this.pending = new Map();
    this.spawn();
  }

  spawn() {
    this.worker = new Worker(new URL('./compile-worker.js', import.meta.url), {
      env: { ...process.env, TYPST_FONTS_DIR: FONTS_DIR },
    });
    this.worker.on('message', (msg) => {
      const p = this.pending.get(msg.reqId);
      if (!p) return;
      this.pending.delete(msg.reqId);
      p.resolve(msg);
    });
    this.worker.on('error', (err) => console.error('[compile] worker error:', err));
    this.worker.on('exit', (code) => {
      console.error(`[compile] worker exited (${code}), restarting`);
      for (const p of this.pending.values()) p.reject(new Error('compiler crashed'));
      this.pending.clear();
      this.spawn();
      // The new worker knows nothing about any project; rooms must resend everything.
      this.emit('reset');
    });
  }

  request(msg) {
    const reqId = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(reqId, { resolve, reject });
      this.worker.postMessage({ ...msg, reqId });
    });
  }

  drop(project) {
    this.worker.postMessage({ type: 'drop', project });
  }
}

const useEngine = fs.existsSync(ENGINE_BIN);
console.log(useEngine ? '[compile] using the incremental engine (bin/typst-engine)' : '[compile] engine not built; using the typst-ts compiler (run `npm run build:engine`)');

export const compiler = useEngine ? new EngineBackend() : new WorkerBackend();
