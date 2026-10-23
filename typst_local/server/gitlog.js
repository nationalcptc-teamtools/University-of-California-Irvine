// Mirrors each project's version history into a bare git repository
// (data/projects/<id>/history.git): every version becomes a commit on `main`
// with its original time and authors, and tagged versions become git tags.
// The repo is served read-only over HTTP (dumb protocol) so it can be cloned.
//
// The JSON snapshots in history/ stay the source of truth; this is an export
// that's kept in sync, and can be deleted and rebuilt at any time.
import { spawn, execFileSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import * as storage from './storage.js';
import * as history from './history.js';

const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';
const COMMITTER = 'Typst Local <typst-local@localhost>';

/** Emits 'synced' (projectId) after the repo caught up with the history. */
export const events = new EventEmitter();

let available = null;
export function gitAvailable() {
  if (available === null) {
    try {
      execFileSync('git', ['--version'], { stdio: 'ignore' });
      available = true;
    } catch {
      available = false;
      console.warn('[git] git is not installed; version history will not be mirrored to git');
    }
  }
  return available;
}

export const repoDir = (id) => path.join(storage.projectDir(id), 'history.git');

/** Runs git against a repo; resolves with stdout (Buffer), rejects on failure. */
function git(dir, args, input) {
  return new Promise((resolve, reject) => {
    const proc = spawn('git', ['--git-dir', dir, '-c', 'core.quotePath=false', ...args], {
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', LC_ALL: 'C' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const out = [];
    const err = [];
    proc.stdout.on('data', (d) => out.push(d));
    proc.stderr.on('data', (d) => err.push(d));
    proc.on('error', reject);
    proc.on('close', (code) =>
      code === 0 ? resolve(Buffer.concat(out)) : reject(new Error(`git ${args[0]}: ${Buffer.concat(err).toString().trim()}`)),
    );
    proc.stdin.on('error', () => {});
    if (input) for (const chunk of input) proc.stdin.write(chunk);
    proc.stdin.end();
  });
}

async function revParse(dir, ref) {
  try {
    return (await git(dir, ['rev-parse', '--verify', '-q', ref + '^{commit}'])).toString().trim() || null;
  } catch {
    return null;
  }
}

// ---- writing commits ----------------------------------------------------------

/** fast-import path: quoted C-style when it has characters that need it. */
const quotePath = (p) => (/^"|[\n\\"]/.test(p) ? '"' + p.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n') + '"' : p);

const identity = (name) => {
  const clean = String(name || 'Typst Local').replace(/[<>\n]/g, '').trim() || 'Typst Local';
  const user = clean.toLowerCase().replace(/[^a-z0-9]+/g, '.').replace(/^\.|\.$/g, '') || 'user';
  return `${clean} <${user}@typst-local>`;
};

export const messageOf = (v) => v.name || v.note || 'Auto-save';

/** Writes one version as a commit on top of `parent`; returns the new sha. */
async function writeCommit(id, dir, version, snapshot, previous, parent) {
  const secs = Math.floor(version.ts / 1000);
  const [author, ...coauthors] = version.authors?.length ? version.authors : [null];
  let message = messageOf(version);
  if (coauthors.length) message += '\n\n' + coauthors.map((a) => `Co-authored-by: ${identity(a)}`).join('\n');
  message += '\n';

  const chunks = [];
  const line = (s) => chunks.push(Buffer.from(s + '\n', 'utf8'));
  const data = (buf) => {
    chunks.push(Buffer.from(`data ${buf.length}\n`, 'utf8'), buf, Buffer.from('\n'));
  };
  line('commit refs/heads/main');
  line(`author ${identity(author)} ${secs} +0000`);
  line(`committer ${COMMITTER} ${secs} +0000`);
  data(Buffer.from(message, 'utf8'));
  if (parent) line(`from ${parent}`);
  if (!previous) line('deleteall');

  const same = (a, b) => (typeof a === 'string' || typeof b === 'string' ? a === b : a?.blob === b?.blob);
  for (const [rel, content] of Object.entries(snapshot.files)) {
    if (previous && same(previous.files[rel], content)) continue;
    const buf = typeof content === 'string' ? Buffer.from(content, 'utf8') : fs.readFileSync(storage.blobPath(id, content.blob));
    line(`M 100644 inline ${quotePath(rel)}`);
    data(buf);
  }
  if (previous) for (const rel of Object.keys(previous.files)) if (!(rel in snapshot.files)) line(`D ${quotePath(rel)}`);
  line('');

  await git(dir, ['fast-import', '--quiet', '--date-format=raw'], chunks);
  return revParse(dir, 'refs/heads/main');
}

/** Per-file changes of a commit against its parent, from git itself. */
async function changesOf(dir, parent, sha) {
  const base = parent || EMPTY_TREE;
  const [numstat, status] = await Promise.all([
    git(dir, ['diff', '--no-renames', '--numstat', base, sha]),
    git(dir, ['diff', '--no-renames', '--name-status', base, sha]),
  ]);
  const statusOf = new Map(
    status
      .toString()
      .split('\n')
      .filter(Boolean)
      .map((l) => {
        const [s, ...p] = l.split('\t');
        return [p.join('\t'), { A: 'added', D: 'deleted' }[s[0]] || 'modified'];
      }),
  );
  const changes = numstat
    .toString()
    .split('\n')
    .filter(Boolean)
    .map((l) => {
      const [add, del, ...p] = l.split('\t');
      const file = p.join('\t');
      return { path: file, status: statusOf.get(file) || 'modified', add: add === '-' ? null : +add, del: del === '-' ? null : +del };
    });
  const stats = {
    files: changes.length,
    insertions: changes.reduce((n, c) => n + (c.add || 0), 0),
    deletions: changes.reduce((n, c) => n + (c.del || 0), 0),
  };
  return { stats, changes };
}

// ---- tags -----------------------------------------------------------------------

async function syncTags(dir, versions) {
  const want = new Map(versions.filter((v) => v.tag && v.commit).map((v) => [v.tag, v]));
  const have = new Map(
    (await git(dir, ['for-each-ref', 'refs/tags', '--format=%(refname:strip=2) %(*objectname)']))
      .toString()
      .split('\n')
      .filter(Boolean)
      .map((l) => l.split(' ')),
  );
  for (const [tag, sha] of have) if (want.get(tag)?.commit !== sha) await git(dir, ['tag', '-d', tag]);
  for (const [tag, v] of want) {
    if (have.get(tag) === v.commit) continue;
    const secs = Math.floor(v.ts / 1000);
    await new Promise((resolve, reject) => {
      const proc = spawn('git', ['--git-dir', dir, 'tag', '-a', '-f', '-m', messageOf(v), tag, v.commit], {
        env: {
          ...process.env,
          GIT_COMMITTER_NAME: 'Typst Local',
          GIT_COMMITTER_EMAIL: 'typst-local@localhost',
          GIT_COMMITTER_DATE: `${secs} +0000`,
          GIT_CONFIG_NOSYSTEM: '1',
        },
        stdio: 'ignore',
      });
      proc.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`git tag ${tag} failed`))));
    });
  }
}

// ---- syncing --------------------------------------------------------------------

async function doSync(id) {
  if (!gitAvailable() || !storage.readMeta(id)) return;
  const dir = repoDir(id);
  if (!fs.existsSync(path.join(dir, 'HEAD'))) {
    fs.mkdirSync(dir, { recursive: true });
    await git(dir, ['init', '--bare', '-q']);
    await git(dir, ['symbolic-ref', 'HEAD', 'refs/heads/main']);
  }

  let versions = history.listVersions(id);
  let parent = await revParse(dir, 'refs/heads/main');
  // Resume after the last version already in the repo; rebuild if the repo is new.
  let start = 0;
  if (parent) {
    const last = versions.findLastIndex((v) => v.commit === parent);
    start = last + 1;
    if (last < 0) parent = null; // repo doesn't match the history: start over
  }
  if (!parent && start === 0 && versions.some((v) => v.commit)) {
    await git(dir, ['update-ref', '-d', 'refs/heads/main']).catch(() => {});
  }

  let previous = start > 0 ? history.readVersion(id, versions[start - 1].id) : null;
  for (const v of versions.slice(start)) {
    const snapshot = history.readVersion(id, v.id);
    const sha = await writeCommit(id, dir, v, snapshot, previous, parent);
    const { stats, changes } = await changesOf(dir, parent, sha);
    history.updateVersion(id, v.id, { commit: sha, parent, stats, changes });
    parent = sha;
    previous = snapshot;
  }

  await syncTags(dir, history.listVersions(id));
  await git(dir, ['update-server-info']);
  events.emit('synced', id);
}

const queues = new Map();

/** Brings the project's git repo up to date (serialized per project). */
export function sync(id) {
  const next = (queues.get(id) || Promise.resolve())
    .then(() => doSync(id))
    .catch((e) => console.error(`[git ${id}]`, e.message));
  queues.set(id, next);
  return next;
}

history.events.on('change', (id) => sync(id));

/** Brings every project's repo up to date (on startup). */
export async function syncAll() {
  for (const meta of storage.listProjects()) await sync(meta.id);
}
