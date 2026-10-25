import './env.js';
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { WebSocketServer } from 'ws';
import * as Y from 'yjs';
import * as storage from './storage.js';
import { getRoom, unloadRoom, saveAll, createProject, replaceText } from './rooms.js';
import * as history from './history.js';
import * as gitlog from './gitlog.js';
import { templates } from './templates.js';
import { createZip } from './zip.js';

const PORT = Number(process.env.TYPST_LOCAL_PORT || process.env.PORT || 3000);
const HOST = process.env.LISTEN_HOST || '0.0.0.0';
const PASSWORD = process.env.ACCESS_PASSWORD || '';
const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

if (!fs.existsSync(path.join(PUBLIC_DIR, 'editor.js'))) {
  console.error('Client bundle missing. Run `npm run build` first (or just `npm start`).');
  process.exit(1);
}

// IPv4 addresses others on the network can use. VPN tunnels (utun/tun/ppp/ipsec)
// are skipped: they usually don't accept incoming connections from the LAN.
function lanAddresses() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    if (/^(utun|tun|tap|ppp|ipsec|gpd|awdl|llw|bridge)/.test(name)) continue;
    for (const a of addrs || []) if (a.family === 'IPv4' && !a.internal) out.push(a.address);
  }
  return out;
}

// ---- auth (optional shared password) ---------------------------------------

const AUTH_COOKIE = 'typst_local_auth';
const authToken = PASSWORD ? crypto.createHash('sha256').update('typst-local:' + PASSWORD).digest('hex') : '';

function isAuthed(req) {
  if (!PASSWORD) return true;
  const cookies = Object.fromEntries(
    (req.headers.cookie || '').split(';').map((c) => {
      const i = c.indexOf('=');
      return [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1).trim())];
    }),
  );
  const got = Buffer.from(cookies[AUTH_COOKIE] || '');
  const want = Buffer.from(authToken);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

// ---- http ------------------------------------------------------------------

const app = express();
app.disable('x-powered-by');

app.get('/login', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'login.html')));
app.post('/api/login', express.json(), (req, res) => {
  if (!PASSWORD || req.body?.password === PASSWORD) {
    res.cookie(AUTH_COOKIE, authToken, { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 365 });
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Wrong password' });
});

app.use(express.static(PUBLIC_DIR, { index: false }));

// Read-only git access to each project's history ("dumb" HTTP protocol):
//   git clone http://host:port/git/<project-id>.git
// With a password set, git prompts for credentials: any username, the access password.
function basicAuthOk(req) {
  const m = /^Basic\s+(.+)$/i.exec(req.headers.authorization || '');
  if (!m) return false;
  const decoded = Buffer.from(m[1], 'base64').toString('utf8');
  const got = Buffer.from(decoded.slice(decoded.indexOf(':') + 1));
  const want = Buffer.from(PASSWORD);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

app.use('/git', (req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return res.status(405).end();
  const m = /^\/([a-z0-9]{10})\.git(\/.*)?$/.exec(req.path);
  if (!m || !storage.readMeta(m[1])) return res.status(404).end();
  if (PASSWORD && !isAuthed(req) && !basicAuthOk(req)) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Typst Local", charset="UTF-8"');
    return res.status(401).end();
  }
  const dir = gitlog.repoDir(m[1]);
  const file = path.resolve(dir, '.' + decodeURIComponent(m[2] || '/'));
  if (!file.startsWith(dir + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) return res.status(404).end();
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(file);
});

app.use((req, res, next) => {
  if (isAuthed(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'unauthorized' });
  res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
});

app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));
app.get('/project/:id', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'editor.html')));

const api = express.Router();
app.use('/api', api);

function loadRoom(req, res, next) {
  if (!storage.isValidId(req.params.id)) return res.status(404).json({ error: 'not found' });
  const room = getRoom(req.params.id);
  if (!room) return res.status(404).json({ error: 'not found' });
  req.room = room;
  next();
}

const cleanName = (name) => String(name || '').trim().slice(0, 120);

api.get('/templates', (req, res) => {
  res.json(Object.entries(templates).map(([id, t]) => ({ id, label: t.label })));
});

api.get('/info', (req, res) => res.json({ addresses: lanAddresses() }));

api.get('/projects', (req, res) => res.json(storage.listProjects()));

api.post('/projects', express.json(), (req, res) => {
  const template = templates[req.body?.template] || templates.article;
  const meta = createProject(cleanName(req.body?.name) || 'Untitled', template.files);
  res.json(meta);
});

api.get('/projects/:id', loadRoom, (req, res) => res.json(req.room.meta));

api.patch('/projects/:id', express.json(), loadRoom, (req, res) => {
  const name = cleanName(req.body?.name);
  if (name) req.room.setName(name);
  res.json(req.room.meta);
});

api.delete('/projects/:id', loadRoom, (req, res) => {
  unloadRoom(req.params.id);
  storage.deleteProject(req.params.id);
  res.json({ ok: true });
});

api.post('/projects/:id/duplicate', loadRoom, (req, res) => {
  const src = req.room;
  src.save();
  const meta = createProject(`${src.meta.name} (copy)`, {});
  fs.writeFileSync(path.join(storage.projectDir(meta.id), 'doc.ystate'), Y.encodeStateAsUpdate(src.doc));
  const blobs = path.join(storage.projectDir(src.id), 'blobs');
  if (fs.existsSync(blobs)) fs.cpSync(blobs, path.join(storage.projectDir(meta.id), 'blobs'), { recursive: true });
  res.json(meta);
});

// Upload a file into the project (raw body). Text files become editable documents.
api.post('/projects/:id/upload', loadRoom, express.raw({ type: () => true, limit: '100mb' }), (req, res) => {
  const rel = storage.normalizePath(req.query.path);
  if (!rel) return res.status(400).json({ error: 'invalid path' });
  const buf = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  const files = req.room.files;
  let text = null;
  if (storage.isTextPath(rel)) {
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
    } catch {}
  }
  if (text !== null) {
    req.room.doc.transact(() => {
      const existing = files.get(rel);
      if (existing instanceof Y.Text) {
        replaceText(existing, text);
      } else {
        files.set(rel, new Y.Text(text));
      }
    });
  } else {
    const hash = storage.writeBlob(req.room.id, buf);
    files.set(rel, { blob: hash, size: buf.length });
  }
  res.json({ ok: true, path: rel });
});

// Raw file contents (used for image previews and downloads).
api.get('/projects/:id/raw/*path', loadRoom, (req, res) => {
  const rel = storage.normalizePath(req.params.path.join('/'));
  const entry = rel && req.room.files.get(rel);
  if (!entry) return res.status(404).end();
  res.type(path.extname(rel) || 'application/octet-stream');
  if (req.query.download) res.attachment(path.basename(rel));
  if (entry instanceof Y.Text) return res.send(entry.toString());
  res.sendFile(storage.blobPath(req.room.id, entry.blob));
});

// Content-addressed binary file, e.g. an image as it was in an old version.
api.get('/projects/:id/blob/:hash', loadRoom, (req, res) => {
  if (!/^[a-f0-9]{64}$/.test(req.params.hash)) return res.status(404).end();
  const file = storage.blobPath(req.room.id, req.params.hash);
  if (!fs.existsSync(file)) return res.status(404).end();
  res.type(path.extname(String(req.query.name || '')) || 'application/octet-stream');
  res.sendFile(file);
});

// Which preview the client means: a file it previews on its own, or the main file.
const previewTarget = (req) => (req.body?.target ? storage.normalizePath(req.body.target) : null);

// Click-to-source: which part of which file produced this point in the preview?
api.post('/projects/:id/jump', express.json(), loadRoom, async (req, res) => {
  const { page, x, y } = req.body || {};
  if (![page, x, y].every(Number.isFinite)) return res.status(400).json({ error: 'page, x and y are required' });
  const result = await req.room.jump(Math.trunc(page), x, y, previewTarget(req));
  if (!result) return res.status(501).json({ error: 'Click-to-source needs the incremental engine (npm run build:engine)' });
  res.json(result);
});

// Cursor-to-preview: where in the preview is the text at this cursor?
api.post('/projects/:id/cursor', express.json(), loadRoom, async (req, res) => {
  const p = storage.normalizePath(req.body?.path);
  const offset = req.body?.offset;
  if (!p || !Number.isFinite(offset)) return res.status(400).json({ error: 'path and offset are required' });
  const result = await req.room.cursor(p, Math.max(0, Math.trunc(offset)), previewTarget(req));
  if (!result) return res.status(501).json({ error: 'Needs the incremental engine (npm run build:engine)' });
  res.json(result);
});

// Images in the project that the document doesn't use.
api.get('/projects/:id/unused-images', loadRoom, async (req, res) => {
  try {
    res.json(await req.room.unusedImages());
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

api.post('/projects/:id/unused-images/delete', express.json(), loadRoom, async (req, res) => {
  const paths = Array.isArray(req.body?.paths) ? req.body.paths.map(storage.normalizePath).filter(Boolean) : [];
  if (!paths.length) return res.status(400).json({ error: 'paths are required' });
  try {
    res.json(await req.room.deleteUnusedImages(paths, cleanAuthor(req.body?.author)));
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// Images in the live preview, handed out by content hash so browsers cache them.
api.get('/projects/:id/img/:hash', loadRoom, (req, res) => {
  const img = req.room.images.get(req.params.hash);
  if (!img) return res.status(404).end();
  res.type(img.mime);
  res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
  res.send(img.data);
});

api.get('/projects/:id/pdf', loadRoom, async (req, res) => {
  try {
    const pdf = await req.room.pdf();
    res.type('application/pdf');
    const filename = (req.room.meta.name || 'document').replace(/[^\w\- .]+/g, '_') + '.pdf';
    res.setHeader('Content-Disposition', `${req.query.inline ? 'inline' : 'attachment'}; filename="${filename}"`);
    res.send(pdf);
  } catch (e) {
    res.status(422).type('text/plain').send('Could not compile PDF:\n' + e.message);
  }
});

api.get('/projects/:id/docx', loadRoom, async (req, res) => {
  try {
    const docx = await req.room.docx();
    const filename = (req.room.meta.name || 'document').replace(/[^\w\- .]+/g, '_') + '.docx';
    res.type('application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(docx);
  } catch (e) {
    res.status(422).type('text/plain').send('Could not create the Word document:\n' + e.message);
  }
});

api.get('/projects/:id/zip', loadRoom, (req, res) => {
  const entries = [];
  req.room.files.forEach((v, rel) => {
    entries.push([rel, v instanceof Y.Text ? v.toString() : fs.readFileSync(storage.blobPath(req.room.id, v.blob))]);
  });
  // Empty folders get their own directory entries.
  for (const folder of req.room.folders.keys()) {
    if (!entries.some(([rel]) => rel.startsWith(folder + '/'))) entries.push([folder + '/', null]);
  }
  const filename = (req.room.meta.name || 'project').replace(/[^\w\- .]+/g, '_') + '.zip';
  res.type('application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(createZip(entries));
});

// ---- version history ----

const cleanAuthor = (name) => String(name || '').trim().slice(0, 40) || null;

api.get('/projects/:id/history', loadRoom, (req, res) => {
  res.json({
    versions: history.listVersions(req.room.id).reverse(),
    git: gitlog.gitAvailable() ? { url: `/git/${req.room.id}.git`, branch: 'main' } : null,
  });
});

api.post('/projects/:id/history', express.json(), loadRoom, (req, res) => {
  const name = cleanName(req.body?.name) || 'Untitled version';
  res.json(req.room.saveVersion(name, cleanAuthor(req.body?.author)));
});

function loadVersion(req, res, next) {
  const v = history.listVersions(req.room.id).find((x) => x.id === req.params.vid);
  if (!v) return res.status(404).json({ error: 'version not found' });
  req.version = v;
  next();
}

api.get('/projects/:id/history/:vid', loadRoom, loadVersion, (req, res) => {
  res.json({ ...req.version, ...history.readVersion(req.room.id, req.version.id) });
});

api.patch('/projects/:id/history/:vid', express.json(), loadRoom, loadVersion, (req, res) => {
  res.json(req.room.renameVersion(req.version.id, cleanName(req.body?.name)));
});

// Puts a git tag on a version (empty removes it).
api.put('/projects/:id/history/:vid/tag', express.json(), loadRoom, loadVersion, (req, res) => {
  const tag = String(req.body?.tag || '').trim();
  if (tag && !history.isValidTag(tag)) return res.status(400).json({ error: 'Tags may use letters, digits, ".", "-", "_" and "/"' });
  const v = history.setTag(req.room.id, req.version.id, tag || null);
  req.room.broadcastJSON({ type: 'history' });
  res.json(v);
});

api.post('/projects/:id/history/:vid/restore', express.json(), loadRoom, loadVersion, (req, res) => {
  req.room.restore(req.version.id, cleanAuthor(req.body?.author));
  res.json({ ok: true });
});

api.get('/projects/:id/history/:vid/preview', loadRoom, loadVersion, async (req, res) => {
  const out = await req.room.compileVersion(req.version.id);
  res.json({ preview: out.preview || null, diagnostics: out.diagnostics || [] });
});

api.get('/projects/:id/history/:vid/pdf', loadRoom, loadVersion, async (req, res) => {
  const out = await req.room.compileVersion(req.version.id, { pdf: true });
  if (!out.pdf) return res.status(422).type('text/plain').send('This version does not compile.');
  const stamp = new Date(req.version.ts).toISOString().slice(0, 16).replace(/[T:]/g, '-');
  const filename = (req.room.meta.name || 'document').replace(/[^\w\- .]+/g, '_') + `-${stamp}.pdf`;
  res.type('application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(Buffer.from(out.pdf));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || 'server error' });
});

// ---- websocket -------------------------------------------------------------

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true, perMessageDeflate: { threshold: 1024 }, maxPayload: 64 * 1024 * 1024 });

server.on('upgrade', (req, socket, head) => {
  const match = /^\/ws\/([a-z0-9]+)$/.exec(new URL(req.url, 'http://x').pathname);
  const room = match && isAuthed(req) && storage.isValidId(match[1]) ? getRoom(match[1]) : null;
  if (!room) {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => (ws.isAlive = true));
    room.addConnection(ws);
  });
});

// Drop dead connections so stale cursors disappear.
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30_000).unref();

// Mirror existing version histories into git (in the background).
gitlog.syncAll();

server.listen(PORT, HOST, () => {
  console.log(`\nTypst Local is running${PASSWORD ? ' (password protected)' : ''}:\n`);
  console.log(`  Local:    http://localhost:${PORT}`);
  for (const address of lanAddresses()) console.log(`  Network:  http://${address}:${PORT}`);
  console.log(`\n  Data directory: ${storage.DATA_DIR}\n`);
});

function shutdown() {
  saveAll();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
