// Runs Typst compilation off the main thread so long compiles (or package
// downloads) never stall real-time collaboration traffic.
//
// The main thread sends per-project file deltas; this worker keeps the full file
// set per project so it can rebuild a compiler when the project's fonts change.
import { parentPort } from 'node:worker_threads';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { NodeCompiler } from '@myriaddreamin/typst-ts-node-compiler';
import { fontFamilies } from './font-names.js';

const FONTS_DIR = process.env.TYPST_FONTS_DIR;

/** @type {Map<string, {compiler: NodeCompiler, workspace: string, files: Map<string, string | {disk: string}>, fonts: string[]}>} */
const projects = new Map();
let compileCount = 0;

/** Family names provided by the given font files plus the server's font library. */
function availableFamilies(fonts) {
  const files = [...fonts];
  if (FONTS_DIR) {
    try {
      for (const f of fs.readdirSync(FONTS_DIR)) if (/\.(ttf|otf|ttc|otc)$/i.test(f)) files.push(path.join(FONTS_DIR, f));
    } catch {}
  }
  const names = new Set();
  for (const f of files) {
    try {
      fontFamilies(fs.readFileSync(f)).forEach((n) => names.add(n));
    } catch {}
  }
  return [...names].sort();
}

function createCompiler(workspace, fonts) {
  const fontArgs = [];
  if (FONTS_DIR) fontArgs.push({ fontPaths: [FONTS_DIR] });
  const blobs = [];
  for (const f of fonts) {
    try {
      blobs.push(fs.readFileSync(f));
    } catch {}
  }
  if (blobs.length) fontArgs.push({ fontBlobs: blobs });
  return NodeCompiler.create({ workspace, fontArgs });
}

function applyFile(p, rel, content) {
  const abs = path.join(p.workspace, rel);
  if (typeof content === 'string') p.compiler.addSource(abs, content);
  else p.compiler.mapShadow(abs, fs.readFileSync(content.disk));
}

function getProject(msg) {
  let p = projects.get(msg.project);
  const fontsChanged = msg.fonts && (!p || msg.fonts.join('\n') !== p.fonts.join('\n'));
  if (!p || fontsChanged) {
    const fonts = msg.fonts || p?.fonts || [];
    const next = {
      compiler: createCompiler(msg.workspace, fonts),
      workspace: msg.workspace,
      files: p?.files || new Map(),
      fonts,
      sentImages: p?.sentImages || new Set(), // image hashes the main thread already has
      families: availableFamilies(fonts),
    };
    for (const [rel, content] of next.files) applyFile(next, rel, content);
    projects.set(msg.project, next);
    p = next;
  }
  return p;
}

function toDiagnostic(p, d) {
  const rel = d.path && d.path.startsWith(p.workspace) ? path.relative(p.workspace, d.path) : d.path || null;
  const hints = [...(d.hints || [])];
  if (/^unknown font family/.test(d.message)) {
    hints.push(
      p.families.length
        ? `font files in this project provide: ${p.families.map((f) => `"${f}"`).join(', ')} (built-in: "Libertinus Serif", "New Computer Modern", "DejaVu Sans Mono")`
        : 'add .ttf or .otf files anywhere in the project to use them (built-in: "Libertinus Serif", "New Computer Modern", "DejaVu Sans Mono")',
    );
  }
  return {
    message: d.message,
    severity: d.severity === 1 ? 'error' : d.severity === 2 ? 'warning' : 'info',
    path: d.package ? null : rel,
    package: d.package || null,
    range: d.range || null,
    hints,
  };
}

const sha1 = (s) => crypto.createHash('sha1').update(s).digest('hex');

/**
 * Turns the compiler's single SVG into something cheap to ship and diff:
 * - inline base64 images become URLs (each image is handed over once),
 * - the document is split into shared defs (glyphs, styles) plus one chunk per
 *   page, keyed by the page's content hash (data-tid).
 */
function toPreview(p, svg, imageBase) {
  const images = [];
  const byData = new Map();
  svg = svg.replace(/data:(image\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=]+)/g, (_, mime, b64) => {
    let hash = byData.get(b64);
    if (!hash) {
      hash = sha1(b64);
      byData.set(b64, hash);
      if (!p.sentImages.has(hash)) {
        p.sentImages.add(hash);
        images.push({ hash, mime, data: Buffer.from(b64, 'base64') });
      }
    }
    return imageBase + hash;
  });

  const MARK = '<g class="typst-page"';
  const starts = [];
  for (let i = svg.indexOf(MARK); i !== -1; i = svg.indexOf(MARK, i + MARK.length)) starts.push(i);
  const end = svg.lastIndexOf('</svg>');
  const header = svg.slice(0, starts.length ? starts[0] : end);
  const defs = header.slice(header.indexOf('>') + 1);
  const pages = starts.map((start, k) => {
    let body = svg.slice(start, k + 1 < starts.length ? starts[k + 1] : end);
    const open = body.slice(0, body.indexOf('>'));
    const attr = (name) => new RegExp(`${name}="([^"]*)"`).exec(open)?.[1];
    // Each page is shown in its own <svg>, so drop the offset into the long strip.
    body = body.replace(/^<g class="typst-page" transform="[^"]*"/, MARK);
    return { tid: attr('data-tid') || sha1(body), w: parseFloat(attr('data-page-width')) || 595, h: parseFloat(attr('data-page-height')) || 842, svg: body };
  });
  return { defs, defsHash: sha1(defs), pages, images };
}

function compile(msg) {
  const p = getProject(msg);
  for (const rel of msg.remove || []) {
    p.files.delete(rel);
    try {
      p.compiler.unmapShadow(path.join(p.workspace, rel));
    } catch {}
  }
  for (const [rel, content] of msg.set || []) {
    p.files.set(rel, content);
    applyFile(p, rel, content);
  }

  const start = performance.now();
  if (!p.files.has(msg.main)) {
    return {
      status: 'error',
      diagnostics: [{ message: `main file "${msg.main}" does not exist`, severity: 'error', path: null, range: null, hints: [] }],
      ms: 0,
    };
  }

  const res = p.compiler.compile({ mainFilePath: path.join(p.workspace, msg.main) });
  const doc = res.result;
  // Errors and warnings are reported separately; a successful compile only has warnings.
  let diagnostics = [];
  let status = doc ? 'ok' : 'error';
  for (const err of [res.takeDiagnostics() || res.takeError(), res.takeWarnings()]) {
    if (!err) continue;
    if (err.compilationStatus !== 'ok' && status !== 'error') status = err.compilationStatus;
    let list;
    try {
      list = p.compiler.fetchDiagnostics(err);
    } catch {
      list = err.shortDiagnostics;
    }
    diagnostics.push(...list.map((d) => toDiagnostic(p, d)));
  }
  // The same diagnostic can come back from both calls.
  const seen = new Set();
  diagnostics = diagnostics.filter((d) => {
    const key = JSON.stringify([d.message, d.path, d.range]);
    return seen.has(key) ? false : (seen.add(key), true);
  });
  const out = { status, diagnostics, ms: 0 };
  if (doc) {
    out.pages = doc.numOfPages;
    out.title = doc.title;
    if (msg.pdf) out.pdf = p.compiler.pdf(doc);
    else out.preview = toPreview(p, p.compiler.svg(doc), msg.imageBase);
  }
  out.ms = Math.round(performance.now() - start);

  if (++compileCount % 25 === 0) p.compiler.evictCache(30);
  return out;
}

parentPort.on('message', (msg) => {
  if (msg.type === 'drop') {
    projects.delete(msg.project);
    return;
  }
  let reply;
  try {
    reply = compile(msg);
  } catch (e) {
    reply = {
      status: 'error',
      diagnostics: [{ message: String(e?.message || e), severity: 'error', path: null, range: null, hints: [] }],
      ms: 0,
    };
  }
  reply.reqId = msg.reqId;
  parentPort.postMessage(reply);
});
