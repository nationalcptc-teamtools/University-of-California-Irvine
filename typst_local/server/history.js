// Version history for a project.
//
//   data/projects/<id>/history/index.json    version list, oldest first
//   data/projects/<id>/history/<vid>.json.gz  {main, files: {path: text | {blob, size}}}
//
// Snapshots store plain file contents (binary files by blob hash; blobs are
// never deleted, so old versions keep working). Versions are kept forever.
// `name` is a user-given commit message; `note` is a system description;
// `tag` is an optional git tag. gitlog.js mirrors every version into a git
// repository and records `commit` (sha) and `stats`/`changes` here.
import fs from 'node:fs';
import { EventEmitter } from 'node:events';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { projectDir } from './storage.js';

/** Emits 'change' (projectId) whenever versions are added or tagged. */
export const events = new EventEmitter();

const historyDir = (id) => path.join(projectDir(id), 'history');
const indexPath = (id) => path.join(historyDir(id), 'index.json');
const versionPath = (id, vid) => {
  if (!/^[a-z0-9-]{1,40}$/.test(vid)) throw new Error('invalid version id');
  return path.join(historyDir(id), vid + '.json.gz');
};

export function listVersions(id) {
  try {
    return JSON.parse(fs.readFileSync(indexPath(id), 'utf8'));
  } catch {
    return [];
  }
}

function writeIndex(id, versions) {
  fs.mkdirSync(historyDir(id), { recursive: true });
  const tmp = indexPath(id) + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(versions, null, 1));
  fs.renameSync(tmp, indexPath(id));
}

export function readVersion(id, vid) {
  return JSON.parse(zlib.gunzipSync(fs.readFileSync(versionPath(id, vid))).toString('utf8'));
}

export const contentHash = (snapshot) => crypto.createHash('sha1').update(JSON.stringify(snapshot)).digest('hex');

/**
 * Stores a snapshot. Unnamed snapshots identical to the latest version are
 * skipped (returns null).
 */
export function addVersion(id, snapshot, { name = null, note = null, authors = [] } = {}) {
  const versions = listVersions(id);
  const hash = contentHash(snapshot);
  const latest = versions.at(-1);
  if (!name && latest?.hash === hash) return null;

  const ts = Date.now();
  const vid = ts.toString(36) + '-' + crypto.randomBytes(3).toString('hex');
  fs.mkdirSync(historyDir(id), { recursive: true });
  fs.writeFileSync(versionPath(id, vid), zlib.gzipSync(JSON.stringify(snapshot)));

  const files = Object.keys(snapshot.files).length;
  const version = { id: vid, ts, name, note, authors: [...new Set(authors)].slice(0, 20), hash, files };
  versions.push(version);
  writeIndex(id, versions);
  events.emit('change', id);
  return version;
}

/** Merges fields into a version's metadata (used to record git results). */
export function updateVersion(id, vid, fields) {
  const versions = listVersions(id);
  const v = versions.find((x) => x.id === vid);
  if (!v) return null;
  Object.assign(v, fields);
  writeIndex(id, versions);
  return v;
}

/** Valid git tag names (a conservative subset of git-check-ref-format). */
export const isValidTag = (tag) =>
  typeof tag === 'string' && /^[A-Za-z0-9][A-Za-z0-9._\-/]{0,79}$/.test(tag) && !tag.includes('..') && !/\.lock$|\/$|\.$/.test(tag);

/** Puts `tag` on a version (moving it off any other version); null removes it. */
export function setTag(id, vid, tag) {
  const versions = listVersions(id);
  const v = versions.find((x) => x.id === vid);
  if (!v) return null;
  if (tag) for (const other of versions) if (other.tag === tag) other.tag = null;
  v.tag = tag || null;
  writeIndex(id, versions);
  events.emit('change', id);
  return v;
}

export function renameVersion(id, vid, name) {
  const versions = listVersions(id);
  const v = versions.find((x) => x.id === vid);
  if (!v) return null;
  v.name = name || null;
  writeIndex(id, versions);
  events.emit('change', id);
  return v;
}
