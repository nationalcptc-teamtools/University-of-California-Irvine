// A Room is one loaded project: its Yjs document, the websocket clients editing
// it, autosave, and the compile loop that pushes previews to every client.
import fs from 'node:fs';
import path from 'node:path';
import * as Y from 'yjs';
import * as syncProtocol from 'y-protocols/sync';
import * as awarenessProtocol from 'y-protocols/awareness';
import * as encoding from 'lib0/encoding';
import * as decoding from 'lib0/decoding';
import * as storage from './storage.js';
import { compiler } from './compiler.js';
import * as history from './history.js';
import * as gitlog from './gitlog.js';
import { htmlToDocx } from './docx.js';

const MSG_SYNC = 0;
const MSG_AWARENESS = 1;

const COMPILE_DELAY_MS = 80;
const SAVE_DELAY_MS = 1000;
const MIRROR_DELAY_MS = 5000;
const UNLOAD_DELAY_MS = 30_000;
const HISTORY_INTERVAL_MS = 5 * 60_000;

/** @type {Map<string, Room>} */
const rooms = new Map();

// Commit hashes and stats arrive once the git mirror catches up.
gitlog.events.on('synced', (id) => rooms.get(id)?.broadcastJSON({ type: 'history' }));

compiler.on('reset', () => {
  for (const room of rooms.values()) {
    room.sent.clear();
    room.sentFonts = null;
    room.scheduleCompile();
  }
});

export function getRoom(id) {
  let room = rooms.get(id);
  if (!room) {
    const meta = storage.readMeta(id);
    if (!meta) return null;
    room = new Room(id, meta);
    rooms.set(id, room);
  }
  room.keepAlive();
  return room;
}

export const getLoadedRoom = (id) => rooms.get(id) || null;

export function unloadRoom(id) {
  const room = rooms.get(id);
  if (!room) return;
  for (const ws of room.conns.keys()) ws.close(4000, 'project removed');
  room.destroy();
}

export function saveAll() {
  for (const room of rooms.values()) {
    room.save();
    room.snapshot();
  }
}

/** Replaces a Y.Text's content with a minimal edit, so cursors outside the change stay put. */
export function replaceText(ytext, next) {
  const cur = ytext.toString();
  if (cur === next) return;
  let start = 0;
  while (start < cur.length && start < next.length && cur[start] === next[start]) start++;
  let endCur = cur.length;
  let endNext = next.length;
  while (endCur > start && endNext > start && cur[endCur - 1] === next[endNext - 1]) {
    endCur--;
    endNext--;
  }
  if (endCur > start) ytext.delete(start, endCur - start);
  if (endNext > start) ytext.insert(start, next.slice(start, endNext));
}

const versionLabel = (v) => (v.name ? `"${v.name}"` : `version from ${new Date(v.ts).toLocaleString()}`);

/** Creates a brand-new project on disk with the given initial files. */
export function createProject(name, files) {
  const id = storage.newId();
  const doc = new Y.Doc();
  doc.transact(() => {
    const map = doc.getMap('files');
    for (const [p, content] of Object.entries(files)) map.set(p, new Y.Text(content));
    doc.getMap('settings').set('main', 'main.typ');
  });
  const now = Date.now();
  const meta = { id, name, createdAt: now, updatedAt: now };
  storage.writeMeta(id, meta);
  storage.writeDocState(id, Y.encodeStateAsUpdate(doc));
  return meta;
}

const send = (ws, data) => {
  if (ws.readyState === 1) ws.send(data, (err) => err && ws.close());
};

export class Room {
  constructor(id, meta) {
    this.id = id;
    this.meta = meta;
    this.doc = new Y.Doc();
    const state = storage.readDocState(id);
    if (state) Y.applyUpdate(this.doc, state);

    this.awareness = new awarenessProtocol.Awareness(this.doc);
    this.awareness.setLocalState(null);
    /** websocket -> awareness client ids it controls */
    this.conns = new Map();

    this.sent = new Map(); // what the compile worker currently holds: rel -> text | "blob:<hash>"
    this.sentFonts = null;
    this.compiling = false;
    this.compileAgain = false;
    this.last = null; // last compile message (without the preview)
    this.preview = null; // {defs, defsHash, order: [tid], pages: Map<tid, {tid, w, h, svg}>}
    this.images = new Map(); // hash -> {mime, data}: images referenced by previews
    this.glyphs = new Map(); // id -> <symbol> markup shared by all pages (engine only)
    this.outline = null; // headings of the last successful compile (engine only)
    this.outlineJson = null;
    this.pendingAuthors = new Set();
    this.changedSinceSnapshot = false;
    this.versionCache = new Map(); // vid -> full preview
    if (!history.listVersions(id).length) history.addVersion(id, this.takeSnapshot(), { note: 'Initial version' });

    this.doc.on('update', (update, origin) => {
      const author = this.authorOf(origin);
      if (author) this.pendingAuthors.add(author);
      this.scheduleSnapshot();
      const enc = encoding.createEncoder();
      encoding.writeVarUint(enc, MSG_SYNC);
      syncProtocol.writeUpdate(enc, update);
      const msg = encoding.toUint8Array(enc);
      for (const ws of this.conns.keys()) send(ws, msg);
      this.dirty = true;
      this.docVersion = (this.docVersion || 0) + 1;
      this.scheduleSave();
      this.scheduleCompile();
    });

    this.awareness.on('update', ({ added, updated, removed }, origin) => {
      const changed = added.concat(updated, removed);
      const ids = this.conns.get(origin);
      if (ids) {
        added.forEach((c) => ids.add(c));
        removed.forEach((c) => ids.delete(c));
      }
      const enc = encoding.createEncoder();
      encoding.writeVarUint(enc, MSG_AWARENESS);
      encoding.writeVarUint8Array(enc, awarenessProtocol.encodeAwarenessUpdate(this.awareness, changed));
      const msg = encoding.toUint8Array(enc);
      for (const ws of this.conns.keys()) send(ws, msg);
    });

    this.scheduleCompile();
  }

  get files() {
    return this.doc.getMap('files');
  }

  get folders() {
    return this.doc.getMap('folders');
  }

  get mainFile() {
    return this.doc.getMap('settings').get('main') || 'main.typ';
  }

  // ---- connections -------------------------------------------------------

  addConnection(ws) {
    this.conns.set(ws, new Set());
    clearTimeout(this.unloadTimer);

    ws.on('message', (data, isBinary) => {
      if (!isBinary) {
        // A client that lost track of the preview asks for all of it again.
        if (data.toString() === 'resync' && this.last) send(ws, JSON.stringify(this.fullMessage()));
        return;
      }
      try {
        this.onMessage(ws, new Uint8Array(data));
      } catch (e) {
        console.error(`[room ${this.id}] bad message:`, e);
      }
    });
    ws.on('close', () => this.removeConnection(ws));

    const enc = encoding.createEncoder();
    encoding.writeVarUint(enc, MSG_SYNC);
    syncProtocol.writeSyncStep1(enc, this.doc);
    send(ws, encoding.toUint8Array(enc));

    const states = this.awareness.getStates();
    if (states.size) {
      const aw = encoding.createEncoder();
      encoding.writeVarUint(aw, MSG_AWARENESS);
      encoding.writeVarUint8Array(aw, awarenessProtocol.encodeAwarenessUpdate(this.awareness, [...states.keys()]));
      send(ws, encoding.toUint8Array(aw));
    }

    send(ws, JSON.stringify({ type: 'meta', meta: this.meta }));
    if (this.last) send(ws, JSON.stringify(this.fullMessage()));
  }

  onMessage(ws, data) {
    const dec = decoding.createDecoder(data);
    const type = decoding.readVarUint(dec);
    if (type === MSG_SYNC) {
      const enc = encoding.createEncoder();
      encoding.writeVarUint(enc, MSG_SYNC);
      syncProtocol.readSyncMessage(dec, enc, this.doc, ws);
      if (encoding.length(enc) > 1) send(ws, encoding.toUint8Array(enc));
    } else if (type === MSG_AWARENESS) {
      awarenessProtocol.applyAwarenessUpdate(this.awareness, decoding.readVarUint8Array(dec), ws);
    }
  }

  removeConnection(ws) {
    const ids = this.conns.get(ws);
    if (!ids) return;
    this.conns.delete(ws);
    awarenessProtocol.removeAwarenessStates(this.awareness, [...ids], null);
    this.keepAlive();
  }

  broadcastJSON(obj) {
    const msg = JSON.stringify(obj);
    for (const ws of this.conns.keys()) send(ws, msg);
  }

  /** Unloads the room a while after the last client leaves. */
  keepAlive() {
    clearTimeout(this.unloadTimer);
    if (this.conns.size) return;
    this.unloadTimer = setTimeout(() => {
      if (!this.conns.size) this.destroy({ save: true });
    }, UNLOAD_DELAY_MS);
  }

  destroy({ save = false } = {}) {
    if (save) {
      this.save();
      this.snapshot();
    }
    clearTimeout(this.snapshotTimer);
    clearTimeout(this.saveTimer);
    clearTimeout(this.mirrorTimer);
    clearTimeout(this.compileTimer);
    clearTimeout(this.unloadTimer);
    this.destroyed = true;
    rooms.delete(this.id);
    compiler.drop(this.id);
    this.awareness.destroy();
    this.doc.destroy();
  }

  // ---- persistence -------------------------------------------------------

  scheduleSave() {
    if (this.saveTimer) return;
    this.saveTimer = setTimeout(() => this.save(), SAVE_DELAY_MS);
    clearTimeout(this.mirrorTimer);
    this.mirrorTimer = setTimeout(() => this.writeMirror(), MIRROR_DELAY_MS);
  }

  save() {
    clearTimeout(this.saveTimer);
    this.saveTimer = null;
    if (!this.dirty || this.destroyed) return;
    this.dirty = false;
    try {
      storage.writeDocState(this.id, Y.encodeStateAsUpdate(this.doc));
      this.meta.updatedAt = Date.now();
      storage.writeMeta(this.id, this.meta);
    } catch (e) {
      console.error(`[room ${this.id}] save failed:`, e);
    }
  }

  writeMirror() {
    if (this.destroyed) return;
    try {
      const entries = [];
      this.files.forEach((v, rel) => entries.push([rel, v instanceof Y.Text ? v.toString() : v]));
      storage.writeMirror(this.id, entries, [...this.folders.keys()]);
    } catch (e) {
      console.error(`[room ${this.id}] mirror failed:`, e);
    }
  }

  // ---- version history ---------------------------------------------------

  authorOf(origin) {
    const ids = this.conns.get(origin);
    if (!ids) return null;
    for (const clientId of ids) {
      const name = this.awareness.getStates().get(clientId)?.user?.name;
      if (name) return name;
    }
    return null;
  }

  takeSnapshot() {
    const files = {};
    this.files.forEach((v, rel) => {
      files[rel] = v instanceof Y.Text ? v.toString() : { blob: v.blob, size: v.size };
    });
    return { main: this.mainFile, files, folders: [...this.folders.keys()].sort() };
  }

  /** Takes an automatic snapshot a while after the first change since the last one. */
  scheduleSnapshot() {
    this.changedSinceSnapshot = true;
    if (this.snapshotTimer) return;
    this.snapshotTimer = setTimeout(() => this.snapshot(), HISTORY_INTERVAL_MS);
  }

  /** Records an automatic version if anything changed since the last one. */
  snapshot(note = null) {
    clearTimeout(this.snapshotTimer);
    this.snapshotTimer = null;
    if (this.destroyed || !this.changedSinceSnapshot) return null;
    this.changedSinceSnapshot = false;
    const authors = [...this.pendingAuthors];
    this.pendingAuthors.clear();
    try {
      const v = history.addVersion(this.id, this.takeSnapshot(), { note, authors });
      if (v) this.broadcastJSON({ type: 'history' });
      return v;
    } catch (e) {
      console.error(`[room ${this.id}] snapshot failed:`, e);
      return null;
    }
  }

  saveVersion(name, author) {
    if (author) this.pendingAuthors.add(author);
    const authors = [...this.pendingAuthors];
    this.pendingAuthors.clear();
    this.changedSinceSnapshot = false;
    clearTimeout(this.snapshotTimer);
    this.snapshotTimer = null;
    const v = history.addVersion(this.id, this.takeSnapshot(), { name, authors });
    this.broadcastJSON({ type: 'history' });
    return v;
  }

  renameVersion(vid, name) {
    const v = history.renameVersion(this.id, vid, name);
    if (v) this.broadcastJSON({ type: 'history' });
    return v;
  }

  /**
   * Makes the project match a stored version. This is applied as a normal
   * edit that syncs to everyone; the state before it is kept as a version.
   */
  restore(vid, author) {
    const target = history.listVersions(this.id).find((v) => v.id === vid);
    if (!target) return null;
    const snap = history.readVersion(this.id, vid);
    this.changedSinceSnapshot = true; // always record the pre-restore state
    this.snapshot(`Before restoring ${versionLabel(target)}`);

    this.doc.transact(() => {
      for (const rel of [...this.files.keys()]) if (!(rel in snap.files)) this.files.delete(rel);
      for (const [rel, content] of Object.entries(snap.files)) {
        const cur = this.files.get(rel);
        if (typeof content === 'string') {
          if (cur instanceof Y.Text) replaceText(cur, content);
          else this.files.set(rel, new Y.Text(content));
        } else if (cur instanceof Y.Text || cur?.blob !== content.blob) {
          this.files.set(rel, { ...content });
        }
      }
      if (this.mainFile !== snap.main) this.doc.getMap('settings').set('main', snap.main);
      // Older snapshots predate explicit folders; leave folders alone for those.
      if (Array.isArray(snap.folders)) {
        for (const f of [...this.folders.keys()]) if (!snap.folders.includes(f)) this.folders.delete(f);
        for (const f of snap.folders) if (!this.folders.has(f)) this.folders.set(f, true);
      }
    }, 'restore');

    this.pendingAuthors.clear();
    if (author) this.pendingAuthors.add(author);
    this.changedSinceSnapshot = true;
    const restored = this.snapshot(`Restored ${versionLabel(target)}`);
    this.broadcastJSON({ type: 'restored', by: author, label: versionLabel(target) });
    return restored;
  }

  /** Compiles a stored version without touching the live document. */
  async compileVersion(vid, { pdf = false } = {}) {
    if (!pdf && this.versionCache.has(vid)) return { preview: this.versionCache.get(vid) };
    const snap = history.readVersion(this.id, vid);
    const key = `${this.id}@${vid}`;
    const set = Object.entries(snap.files).map(([rel, c]) =>
      typeof c === 'string' ? [rel, c] : [rel, { disk: storage.blobPath(this.id, c.blob) }],
    );
    const fonts = Object.entries(snap.files)
      .filter(([rel, c]) => typeof c !== 'string' && storage.isFontPath(rel))
      .map(([, c]) => storage.blobPath(this.id, c.blob))
      .sort();
    try {
      const res = await compiler.request({
        type: 'compile',
        project: key,
        workspace: storage.workspaceDir(this.id),
        main: snap.main,
        set,
        remove: [],
        fonts,
        pdf,
        imageBase: this.imageBase,
      });
      if (res.preview) {
        this.storeImages(res.preview.images);
        const { defs, pages, glyphs } = res.preview;
        res.preview = { defs, pages, glyphs };
        this.versionCache.set(vid, res.preview);
        if (this.versionCache.size > 4) this.versionCache.delete(this.versionCache.keys().next().value);
      }
      return res;
    } finally {
      compiler.drop(key);
    }
  }

  setName(name) {
    this.meta.name = name;
    storage.writeMeta(this.id, this.meta);
    this.broadcastJSON({ type: 'meta', meta: this.meta });
  }

  // ---- compilation -------------------------------------------------------

  /** Builds the minimal set of changes the compile worker needs. */
  takeDelta() {
    const set = [];
    const remove = [];
    const fonts = [];
    const seen = new Set();
    this.files.forEach((v, rel) => {
      seen.add(rel);
      if (v instanceof Y.Text) {
        const text = v.toString();
        if (this.sent.get(rel) !== text) {
          set.push([rel, text]);
          this.sent.set(rel, text);
        }
      } else if (v?.blob) {
        const disk = storage.blobPath(this.id, v.blob);
        if (this.sent.get(rel) !== 'blob:' + v.blob) {
          set.push([rel, { disk }]);
          this.sent.set(rel, 'blob:' + v.blob);
        }
        if (storage.isFontPath(rel)) fonts.push(disk);
      }
    });
    for (const rel of [...this.sent.keys()]) {
      if (!seen.has(rel)) {
        remove.push(rel);
        this.sent.delete(rel);
      }
    }
    fonts.sort();
    const fontsKey = fonts.join('\n');
    const fontsChanged = fontsKey !== this.sentFonts;
    this.sentFonts = fontsKey;
    return { set, remove, fonts: fontsChanged ? fonts : undefined };
  }

  get imageBase() {
    return `/api/projects/${this.id}/img/`;
  }

  storeImages(images) {
    for (const { hash, mime, data } of images) {
      this.images.set(hash, { mime, data: Buffer.from(data.buffer, data.byteOffset, data.byteLength) });
    }
  }

  /** Everything a newly connected client needs: last compile, outline, full preview. */
  fullMessage() {
    return { ...this.last, outline: this.outline ?? undefined, preview: this.fullPreview() };
  }

  /** The whole current preview, for clients that have nothing yet. */
  fullPreview() {
    if (!this.preview) return null;
    return {
      defs: this.preview.defs,
      glyphs: Object.fromEntries(this.glyphs),
      pages: this.preview.order.map((tid) => this.preview.pages.get(tid)),
    };
  }

  /**
   * Stores a new preview and returns what clients holding the previous one
   * need: changed defs and only the pages they don't have (null if nothing changed).
   */
  applyPreview(next) {
    this.storeImages(next.images);
    const newGlyphs = {};
    for (const [id, markup] of Object.entries(next.glyphs || {})) {
      if (!this.glyphs.has(id)) this.glyphs.set(id, (newGlyphs[id] = markup));
    }
    const hasNewGlyphs = Object.keys(newGlyphs).length > 0;
    const prev = this.preview;
    // The engine only renders pages it hasn't rendered before; reuse the rest.
    const pages = next.pages.map((p) => (p.svg !== undefined ? p : { ...p, svg: prev?.pages.get(p.tid)?.svg }));
    this.preview = {
      defs: next.defs,
      defsHash: next.defsHash,
      order: pages.map((p) => p.tid),
      pages: new Map(pages.map((p) => [p.tid, p])),
    };
    const defsChanged = !prev || prev.defsHash !== next.defsHash;
    const sameOrder = prev && prev.order.length === next.pages.length && prev.order.every((tid, i) => tid === next.pages[i].tid);
    if (!defsChanged && sameOrder && !hasNewGlyphs) return null;
    return {
      defs: defsChanged ? next.defs : undefined,
      glyphs: hasNewGlyphs ? newGlyphs : undefined,
      pages: pages.map((p) => (prev?.pages.has(p.tid) ? { tid: p.tid, w: p.w, h: p.h } : p)),
    };
  }

  request(extra = {}) {
    return compiler.request({
      type: 'compile',
      project: this.id,
      workspace: storage.workspaceDir(this.id),
      main: this.mainFile,
      imageBase: this.imageBase,
      ...this.takeDelta(),
      ...extra,
    });
  }

  scheduleCompile(delay = COMPILE_DELAY_MS) {
    clearTimeout(this.compileTimer);
    this.compileTimer = setTimeout(() => this.compile(), delay);
  }

  async compile() {
    if (this.destroyed) return;
    if (this.compiling) {
      this.compileAgain = true;
      return;
    }
    this.compiling = true;
    try {
      let res = await this.request();
      if (this.destroyed) return;
      // If the compiler assumed we have pages we don't (e.g. after a restart), get them all.
      if (res.preview?.pages.some((p) => p.svg === undefined && !this.preview?.pages.get(p.tid)?.svg)) {
        res = await this.request({ full: true });
        if (this.destroyed) return;
      }
      const msg = {
        type: 'compile',
        status: res.status,
        diagnostics: res.diagnostics,
        pages: res.pages ?? this.last?.pages ?? 0,
        ms: res.ms,
        at: Date.now(),
      };
      this.last = msg;
      const out = { ...msg };
      if (res.preview) {
        const preview = this.applyPreview(res.preview);
        if (preview) out.preview = preview;
      }
      // The heading list only goes out when it changed.
      if (res.outline) {
        const json = JSON.stringify(res.outline);
        if (json !== this.outlineJson) {
          this.outline = res.outline;
          this.outlineJson = json;
          out.outline = res.outline;
        }
      }
      this.broadcastJSON(out);
    } catch (e) {
      console.error(`[room ${this.id}] compile failed:`, e);
    } finally {
      this.compiling = false;
      if (this.compileAgain) {
        this.compileAgain = false;
        this.scheduleCompile(0);
      }
    }
  }

  /**
   * Images in the project that compiling the main file doesn't read. Compiles
   * the current text first, so the answer reflects every edit made so far.
   * Throws if the document doesn't compile, since the list would be incomplete.
   */
  async unusedImages() {
    // Only the engine can report which files a compile read (it's the backend with jump()).
    if (!compiler.jump) throw Object.assign(new Error('Finding unused images needs the incremental engine (npm run build:engine)'), { status: 501 });
    const res = await this.request({ deps: true });
    if (!res.deps) {
      const first = res.diagnostics?.find((d) => d.severity === 'error');
      throw Object.assign(
        new Error(`${this.mainFile} has errors, so it can't tell which images are used yet. Fix them first${first ? ` (${first.path ? first.path + ': ' : ''}${first.message})` : ''}.`),
        { status: 422 },
      );
    }
    const used = new Set(res.deps);
    const unused = [];
    this.files.forEach((v, rel) => {
      if (storage.isImagePath(rel) && !used.has(rel)) unused.push({ path: rel, size: v instanceof Y.Text ? Buffer.byteLength(v.toString()) : v?.size ?? 0 });
    });
    return { main: this.mainFile, images: unused.sort((a, b) => a.path.localeCompare(b.path)) };
  }

  /**
   * Deletes the given images, but only those that are still unused right now
   * (someone may have started using one since the list was shown). The state
   * before is kept as a version, so this can be undone from History.
   */
  async deleteUnusedImages(paths, author) {
    const { images } = await this.unusedImages();
    const unused = new Set(images.map((i) => i.path));
    const doomed = [...new Set(paths)].filter((p) => unused.has(p));
    if (!doomed.length) return { deleted: [] };
    this.changedSinceSnapshot = true; // always record the state before
    this.snapshot('Before deleting unused images');
    this.doc.transact(() => {
      for (const rel of doomed) {
        this.files.delete(rel);
        // Keep the folder it was in, like deleting a single file does.
        const parent = rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '';
        if (parent) this.folders.set(parent, true);
      }
    }, 'unused-images');
    this.pendingAuthors.clear();
    if (author) this.pendingAuthors.add(author);
    this.changedSinceSnapshot = true;
    this.snapshot(`Deleted ${doomed.length} unused image${doomed.length > 1 ? 's' : ''}`);
    return { deleted: doomed };
  }

  /** Source location for a click in the preview, or null if unsupported. */
  async jump(page, x, y) {
    if (!compiler.jump) return null;
    return compiler.jump(this.id, page, x, y);
  }

  /** Preview position of the text at a cursor, or null if unsupported. */
  async cursor(path, offset) {
    if (!compiler.cursor) return null;
    return compiler.cursor(this.id, path, offset);
  }

  /**
   * The document as a Word file: a real Word document styled after the PDF
   * (fonts, colours, headings, header/footer, tables). Cached per version.
   */
  async docx() {
    const version = this.docVersion || 0;
    if (this.docxCache?.version === version) return this.docxCache.data;
    const data = await this.docxFromHtml();
    this.docxCache = { version, data };
    return data;
  }

  async docxFromHtml() {
    const res = await this.request({ html: true });
    if (!res.html) {
      const first = res.diagnostics?.find((d) => d.severity === 'error');
      throw new Error(
        first ? `${first.path ? first.path + ': ' : ''}${first.message}` : 'Word export needs the incremental engine (npm run build:engine)',
      );
    }
    // Fonts that can be embedded: the project's own font files and the server's font library.
    const fontFiles = [];
    this.files.forEach((v, rel) => {
      if (v?.blob && storage.isFontPath(rel)) fontFiles.push(storage.blobPath(this.id, v.blob));
    });
    try {
      for (const f of fs.readdirSync(storage.FONTS_DIR)) if (storage.isFontPath(f)) fontFiles.push(path.join(storage.FONTS_DIR, f));
    } catch {}
    return htmlToDocx(res.html, res.style, fontFiles);
  }

  async pdf() {
    // Exporting a long document with many images is slow; reuse it while nothing changed.
    const version = this.docVersion || 0;
    if (this.pdfCache?.version === version) return this.pdfCache.data;
    const res = await this.request({ pdf: true });
    if (!res.pdf) {
      const first = res.diagnostics.find((d) => d.severity === 'error');
      throw new Error(first ? `${first.path || ''}: ${first.message}` : 'compilation failed');
    }
    const data = Buffer.from(res.pdf);
    this.pdfCache = { version, data };
    return data;
  }
}
