// On-disk layout:
//   data/projects/<id>/meta.json     project metadata (name, timestamps)
//   data/projects/<id>/doc.ystate    Yjs document state (source of truth for files)
//   data/projects/<id>/blobs/<sha>   binary assets (images, fonts, ...), content addressed
//   data/projects/<id>/files/...     plain-file mirror of the project, for backups
//   data/projects/<id>/ws/           empty compiler workspace (all files are shadowed in)
//   data/fonts/                      extra fonts available to every project
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { ROOT } from './env.js';

export const DATA_DIR = path.resolve(ROOT, process.env.DATA_DIR || 'data');
export const PROJECTS_DIR = path.join(DATA_DIR, 'projects');
export const FONTS_DIR = path.join(DATA_DIR, 'fonts');

fs.mkdirSync(PROJECTS_DIR, { recursive: true });
fs.mkdirSync(FONTS_DIR, { recursive: true });

const ID_RE = /^[a-z0-9]{10}$/;

export const isValidId = (id) => typeof id === 'string' && ID_RE.test(id);

export function projectDir(id) {
  if (!isValidId(id)) throw new Error('invalid project id');
  return path.join(PROJECTS_DIR, id);
}

export function newId() {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.randomBytes(10);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
}

export function readMeta(id) {
  try {
    return JSON.parse(fs.readFileSync(path.join(projectDir(id), 'meta.json'), 'utf8'));
  } catch {
    return null;
  }
}

export function writeMeta(id, meta) {
  const dir = projectDir(id);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(dir, 'meta.json.tmp');
  fs.writeFileSync(tmp, JSON.stringify(meta, null, 2));
  fs.renameSync(tmp, path.join(dir, 'meta.json'));
}

export function listProjects() {
  return fs
    .readdirSync(PROJECTS_DIR)
    .filter(isValidId)
    .map(readMeta)
    .filter(Boolean)
    .sort((a, b) => b.updatedAt - a.updatedAt);
}

export function deleteProject(id) {
  fs.rmSync(projectDir(id), { recursive: true, force: true });
}

export function readDocState(id) {
  try {
    return fs.readFileSync(path.join(projectDir(id), 'doc.ystate'));
  } catch {
    return null;
  }
}

export function writeDocState(id, state) {
  const dir = projectDir(id);
  const tmp = path.join(dir, 'doc.ystate.tmp');
  fs.writeFileSync(tmp, state);
  fs.renameSync(tmp, path.join(dir, 'doc.ystate'));
}

export function workspaceDir(id) {
  const dir = path.join(projectDir(id), 'ws');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function blobPath(id, hash) {
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error('invalid blob hash');
  return path.join(projectDir(id), 'blobs', hash);
}

export function writeBlob(id, buf) {
  const hash = crypto.createHash('sha256').update(buf).digest('hex');
  const file = blobPath(id, hash);
  if (!fs.existsSync(file)) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, buf);
  }
  return hash;
}

/** Rewrites the plain-file mirror so the project is browsable outside the app. */
export function writeMirror(id, entries, folders = []) {
  const dir = path.join(projectDir(id), 'files');
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  for (const rel of folders) {
    const target = path.join(dir, rel);
    if (target.startsWith(dir + path.sep)) fs.mkdirSync(target, { recursive: true });
  }
  for (const [rel, content] of entries) {
    const target = path.join(dir, rel);
    if (!target.startsWith(dir + path.sep)) continue;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    if (typeof content === 'string') fs.writeFileSync(target, content);
    else fs.copyFileSync(blobPath(id, content.blob), target);
  }
}

/** Normalizes a user supplied project path ("a/b.typ"); returns null if invalid. */
export function normalizePath(p) {
  if (typeof p !== 'string') return null;
  const parts = p.replace(/\\/g, '/').split('/').filter((s) => s && s !== '.');
  if (!parts.length || parts.some((s) => s === '..' || s.length > 200)) return null;
  return parts.join('/');
}

const TEXT_EXT = new Set([
  'typ', 'bib', 'yml', 'yaml', 'toml', 'txt', 'csv', 'json', 'xml', 'md', 'tex', 'svg', 'html', 'css', 'js', 'py', 'rs', 'tsv',
]);

export const isTextPath = (p) => TEXT_EXT.has(p.split('.').pop().toLowerCase());

export const isFontPath = (p) => /\.(ttf|otf|ttc|otc)$/i.test(p);

// PDFs are left out on purpose: Typst can place them as images, but a PDF in a
// project is just as often a reference document someone wants to keep.
export const isImagePath = (p) => /\.(png|jpe?g|gif|webp|svg|bmp|tiff?|avif|heic)$/i.test(p);
