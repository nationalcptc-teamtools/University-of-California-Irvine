import * as Y from 'yjs';
import { Awareness } from 'y-protocols/awareness';
import {
  EditorView,
  keymap,
  lineNumbers,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  drawSelection,
  dropCursor,
  rectangularSelection,
  crosshairCursor,
  Decoration,
} from '@codemirror/view';
import { EditorState, Compartment, EditorSelection, StateField, StateEffect } from '@codemirror/state';
import { defaultKeymap, indentWithTab } from '@codemirror/commands';
import { indentOnInput, bracketMatching, foldGutter, foldKeymap, syntaxTree } from '@codemirror/language';
import { searchKeymap, highlightSelectionMatches } from '@codemirror/search';
import { autocompletion, completionKeymap, closeBrackets, closeBracketsKeymap } from '@codemirror/autocomplete';
import { lintGutter, setDiagnostics } from '@codemirror/lint';
import { yCollab, yUndoManagerKeymap } from 'y-codemirror.next';
import { typst } from './lib/typst-lang.js';
import { Provider } from './lib/provider.js';
import { Preview } from './lib/preview.js';
import { initHistory } from './lib/history.js';
import { initOutline } from './lib/outline.js';
import { api, h, dialog, popupMenu, toast, getUser, saveUser, ensureUserName, initials } from './lib/common.js';

const projectId = location.pathname.split('/').pop();
const $ = (id) => document.getElementById(id);

// ---- document + connection --------------------------------------------------

const ydoc = new Y.Doc();
const files = ydoc.getMap('files');
const settings = ydoc.getMap('settings');
const folders = ydoc.getMap('folders'); // explicit folders (so empty ones exist): path -> true
const awareness = new Awareness(ydoc);
const wsUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/${projectId}`;

let user = getUser();
const setPresence = () =>
  awareness.setLocalStateField('user', { name: user.name || 'Anonymous', color: user.color, colorLight: user.color + '33' });
setPresence();

const provider = new Provider(wsUrl, ydoc, awareness);

const mainFile = () => settings.get('main') || 'main.typ';

// ---- theme ------------------------------------------------------------------

const darkQuery = matchMedia('(prefers-color-scheme: dark)');
const themeCompartment = new Compartment();
const languageFor = (path) => (path.endsWith('.typ') ? typst({ dark: darkQuery.matches }) : []);

const editorTheme = EditorView.theme({
  '&': { height: '100%', fontSize: '14px', backgroundColor: 'var(--editor-bg)', color: 'var(--text)' },
  '.cm-scroller': { fontFamily: 'var(--mono)', lineHeight: '1.6' },
  '.cm-content': { padding: '12px 0', caretColor: 'var(--accent)' },
  '.cm-gutters': { backgroundColor: 'var(--editor-bg)', color: 'var(--text-faint)', border: 'none' },
  '.cm-activeLineGutter': { backgroundColor: 'transparent', color: 'var(--text)' },
  '.cm-activeLine': { backgroundColor: 'var(--active-line)' },
  '&.cm-focused .cm-cursor': { borderLeftColor: 'var(--accent)' },
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection': { backgroundColor: 'var(--selection) !important' },
  '.cm-tooltip': { backgroundColor: 'var(--panel)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' },
  '.cm-tooltip-autocomplete > ul > li[aria-selected]': { backgroundColor: 'var(--accent)', color: 'white' },
  '.cm-panels': { backgroundColor: 'var(--panel)', color: 'var(--text)' },
  '.cm-panels.cm-panels-bottom': { borderTop: '1px solid var(--border)' },
  '.cm-panels.cm-panels-top': { borderBottom: '1px solid var(--border)' },
  // Find & replace panel
  '& .cm-panel.cm-search': { padding: '6px 36px 6px 10px', fontFamily: 'var(--sans)', fontSize: '13px', lineHeight: '36px' },
  '& .cm-panel.cm-search .cm-textfield': {
    margin: '0 6px 0 0',
    verticalAlign: 'middle',
    height: '28px',
    lineHeight: '26px',
    width: '200px',
    padding: '0 8px',
    fontSize: '13px',
    fontFamily: 'var(--sans)',
    color: 'var(--text)',
    backgroundColor: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    outline: 'none',
  },
  '& .cm-panel.cm-search .cm-textfield:focus': { borderColor: 'var(--accent)', boxShadow: '0 0 0 3px var(--accent-soft)' },
  '& .cm-panel.cm-search .cm-button': {
    margin: '0 6px 0 0',
    verticalAlign: 'middle',
    height: '28px',
    lineHeight: '26px',
    padding: '0 10px',
    fontSize: '13px',
    fontFamily: 'var(--sans)',
    color: 'var(--text)',
    backgroundColor: 'var(--panel)',
    backgroundImage: 'none',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  '& .cm-panel.cm-search .cm-button:hover': { backgroundColor: 'var(--hover)' },
  '& .cm-panel.cm-search .cm-button:active': { backgroundImage: 'none', backgroundColor: 'var(--accent-soft)' },
  '& .cm-panel.cm-search label': {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
    margin: '0 10px 0 4px',
    verticalAlign: 'middle',
    fontSize: '13px',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  },
  '& .cm-panel.cm-search input[type=checkbox]': { margin: 0, accentColor: 'var(--accent)' },
  '& .cm-panel.cm-search button[name=close]': {
    top: '8px',
    right: '10px',
    width: '24px',
    height: '24px',
    padding: 0,
    fontSize: '18px',
    lineHeight: '22px',
    color: 'var(--text-muted)',
    borderRadius: '6px',
  },
  '& .cm-panel.cm-search button[name=close]:hover': { color: 'var(--text)', backgroundColor: 'var(--hover)' },
  '.cm-searchMatch': { backgroundColor: 'rgba(255, 190, 0, 0.28)', outline: '1px solid rgba(255, 190, 0, 0.55)', borderRadius: '2px' },
  '.cm-searchMatch.cm-searchMatch-selected': { backgroundColor: 'rgba(255, 140, 0, 0.5)', outline: '1px solid rgb(255, 140, 0)' },
  '.cm-ySelectionInfo': { fontFamily: 'var(--sans)', fontSize: '11px', padding: '1px 4px', borderRadius: '3px 3px 3px 0', opacity: 1, top: '-1.35em' },
});

// Briefly highlights a line (used when jumping to source from the preview).
const flashLine = StateEffect.define();
const flashField = StateField.define({
  create: () => Decoration.none,
  update(deco, tr) {
    deco = deco.map(tr.changes);
    for (const e of tr.effects) {
      if (e.is(flashLine)) deco = e.value === null ? Decoration.none : Decoration.set([Decoration.line({ class: 'cm-jump-flash' }).range(e.value)]);
    }
    return deco;
  },
  provide: (f) => EditorView.decorations.from(f),
});

// ---- editor -----------------------------------------------------------------

let view = null;
let currentPath = null;
let lastCompile = null;

function createEditor(path, ytext) {
  const undoManager = new Y.UndoManager(ytext);
  const state = EditorState.create({
    doc: ytext.toString(),
    extensions: [
      lineNumbers(),
      highlightActiveLineGutter(),
      highlightSpecialChars(),
      foldGutter(),
      drawSelection(),
      dropCursor(),
      EditorState.allowMultipleSelections.of(true),
      indentOnInput(),
      bracketMatching(),
      closeBrackets(),
      autocompletion(),
      rectangularSelection(),
      crosshairCursor(),
      highlightActiveLine(),
      highlightSelectionMatches(),
      lintGutter(),
      flashField,
      EditorView.updateListener.of(followEditor),
      EditorView.domEventHandlers({ paste: pasteIntoEditor, drop: dropIntoEditor, dragover: dragOverEditor }),
      EditorView.lineWrapping,
      EditorState.phrases.of({
        Find: 'Find',
        next: 'Next',
        previous: 'Previous',
        all: 'Select all',
        'match case': 'Match case',
        regexp: 'Regex',
        'by word': 'Whole word',
        Replace: 'Replace with',
        replace: 'Replace',
        'replace all': 'Replace all',
        close: 'Close',
      }),
      themeCompartment.of(languageFor(path)),
      editorTheme,
      keymap.of([
        { key: 'Mod-s', preventDefault: true, run: () => (toast('All changes are saved automatically'), true) },
        ...closeBracketsKeymap,
        ...yUndoManagerKeymap,
        ...defaultKeymap,
        ...searchKeymap,
        ...foldKeymap,
        ...completionKeymap,
        indentWithTab,
      ]),
      yCollab(ytext, awareness, { undoManager }),
    ],
  });
  return new EditorView({ state, parent: $('editor') });
}

function openFile(path, { focus = true } = {}) {
  historyUI.exit({ reopen: false });
  if (!files.has(path)) path = files.has(mainFile()) ? mainFile() : [...files.keys()].sort()[0];
  if (view) {
    view.destroy();
    view = null;
  }
  $('editor').replaceChildren();
  currentPath = path || null;
  awareness.setLocalStateField('file', currentPath);
  if (!path) {
    $('editor').append(h('div.binary-view', null, h('p', null, 'This project has no files yet.')));
    setSoloFile(null);
    renderTree();
    return;
  }
  history.replaceState(null, '', '#' + encodeURIComponent(path));
  $('file-title').textContent = path;
  // The toggle above the preview offers the last .typ file opened on its own.
  setSoloFile(path.endsWith('.typ') && path !== mainFile() ? path : soloPath);

  const entry = files.get(path);
  if (entry instanceof Y.Text) {
    view = createEditor(path, entry);
    applyDiagnostics();
    if (focus) view.focus();
  } else {
    const url = `/api/projects/${projectId}/raw/${path.split('/').map(encodeURIComponent).join('/')}`;
    const isImage = /\.(png|jpe?g|gif|webp|bmp|avif)$/i.test(path);
    $('editor').append(
      h(
        'div.binary-view',
        null,
        isImage ? h('img', { src: url + '?v=' + entry.blob, alt: path }) : h('div.binary-icon', null, fileIcon(path)),
        h('p', null, path, h('span.muted', null, ` · ${formatSize(entry.size)}`)),
        h('a.btn', { href: url + '?download=1' }, 'Download'),
      ),
    );
  }
  renderTree();
}

darkQuery.addEventListener('change', () => {
  if (view && currentPath) view.dispatch({ effects: themeCompartment.reconfigure(languageFor(currentPath)) });
});

const formatSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);

// ---- diagnostics ------------------------------------------------------------

function toRange(doc, range) {
  if (!range) return { from: 0, to: 0 };
  const pos = ({ line, character }) => {
    const l = doc.line(Math.min(Math.max(line + 1, 1), doc.lines));
    return l.from + Math.min(character, l.length);
  };
  const from = pos(range.start);
  return { from, to: Math.max(from, pos(range.end)) };
}

function applyDiagnostics() {
  if (!view || !lastCompile) return;
  const doc = view.state.doc;
  const diags = lastCompile.diagnostics
    .filter((d) => d.path === currentPath)
    .map((d) => ({
      ...toRange(doc, d.range),
      severity: d.severity,
      message: d.message + (d.hints?.length ? '\n' + d.hints.map((x) => 'hint: ' + x).join('\n') : ''),
      source: 'typst',
    }));
  view.dispatch(setDiagnostics(view.state, diags));
}

function jumpTo(d) {
  if (d.path && d.path !== currentPath && files.has(d.path)) openFile(d.path);
  if (!view || d.path !== currentPath) return;
  const { from, to } = toRange(view.state.doc, d.range);
  view.dispatch({ selection: EditorSelection.range(from, to), scrollIntoView: true });
  view.focus();
}

let problemsOpen = true;
function renderProblems() {
  const diags = lastCompile?.diagnostics || [];
  const errors = diags.filter((d) => d.severity === 'error').length;
  const warnings = diags.length - errors;
  const el = $('problems');
  el.classList.toggle('has-items', diags.length > 0);
  el.replaceChildren(
    h(
      'button.problems-head',
      { onclick: () => ((problemsOpen = !problemsOpen), renderProblems()), disabled: !diags.length },
      diags.length
        ? [
            errors > 0 && h('span.count.error', null, `${errors} error${errors > 1 ? 's' : ''}`),
            warnings > 0 && h('span.count.warning', null, `${warnings} warning${warnings > 1 ? 's' : ''}`),
            h('span.chev', null, problemsOpen ? '▾' : '▸'),
          ]
        : h('span.muted', null, 'No problems'),
    ),
    (problemsOpen && diags.length > 0 && h(
        'div.problems-list',
        null,
        diags.map((d) =>
          h(
            'button.problem.' + d.severity,
            { onclick: () => jumpTo(d) },
            h('span.problem-sev', null, d.severity === 'error' ? '✕' : '!'),
            h(
              'span.problem-body',
              null,
              h('span.problem-msg', null, d.message),
              d.hints?.map((x) => h('span.problem-hint', null, 'hint: ' + x)),
            ),
            h(
              'span.problem-loc',
              null,
              d.package ? d.package : d.path ? `${d.path}${d.range ? `:${d.range.start.line + 1}:${d.range.start.character + 1}` : ''}` : '',
            ),
          ),
        ),
      )) ||
      '',
  );
}

// ---- preview ----------------------------------------------------------------

const preview = new Preview($('preview'), {
  onMissing: () => provider.send(JSON.stringify({ type: 'resync', path: previewTarget() })),
});

function renderStatus() {
  const el = $('compile-status');
  if (provider.status !== 'connected') {
    el.className = 'status offline';
    el.textContent = provider.status === 'removed' ? 'Project deleted' : 'Reconnecting…';
    return;
  }
  if (!lastCompile) {
    el.className = 'status busy';
    el.textContent = 'Compiling…';
    return;
  }
  const errors = lastCompile.diagnostics.filter((d) => d.severity === 'error').length;
  if (lastCompile.status === 'error' || errors) {
    el.className = 'status error';
    el.textContent = `${errors || 1} error${errors > 1 ? 's' : ''}`;
  } else {
    el.className = 'status ok';
    el.textContent = `Compiled in ${lastCompile.ms} ms`;
  }
}

function renderZoom() {
  $('zoom-label').textContent = Math.round(preview.effectiveZoom * 100) + '%';
  $('zoom-fit').classList.toggle('active', preview.zoom === 'fit');
  const n = preview.pageCount;
  $('page-info').textContent = n ? `${preview.currentPage + 1} / ${n}` : '';
}
preview.onzoom = renderZoom;
new ResizeObserver(renderZoom).observe($('preview'));
$('preview').addEventListener('scroll', renderZoom, { passive: true });
$('zoom-in').onclick = () => preview.zoomBy(1);
$('zoom-out').onclick = () => preview.zoomBy(-1);
$('zoom-fit').onclick = () => preview.setZoom('fit');
$('preview').addEventListener(
  'wheel',
  (e) => {
    if (!e.ctrlKey && !e.metaKey) return;
    e.preventDefault();
    const factor = Math.exp(-e.deltaY / 300);
    preview.setZoom(Math.min(5, Math.max(0.1, preview.effectiveZoom * factor)), { x: e.clientX, y: e.clientY });
  },
  { passive: false },
);

// ---- cursor-to-preview ------------------------------------------------------

const FOLLOW_KEY = 'typst-local-follow';
let following = true;
try {
  following = localStorage.getItem(FOLLOW_KEY) !== 'off';
} catch {}
let followAfterCompile = false;
let followTimer;
let followSeq = 0;

function renderFollow() {
  $('follow-btn').classList.toggle('active', following);
  $('follow-btn').title = following ? 'Preview follows your cursor (click to turn off)' : 'Preview does not follow your cursor (click to turn on)';
}
$('follow-btn').onclick = () => {
  following = !following;
  try {
    localStorage.setItem(FOLLOW_KEY, following ? 'on' : 'off');
  } catch {}
  renderFollow();
  if (following) followCursor();
};
renderFollow();

/** Editor update hook: follow local typing (after it compiles) and cursor moves. */
function followEditor(update) {
  if (!following || !currentPath?.endsWith('.typ')) return;
  const local = update.transactions.some((tr) => ['input', 'delete', 'select', 'undo', 'redo'].some((e) => tr.isUserEvent(e)));
  if (!local) return;
  if (update.docChanged) {
    followAfterCompile = true; // the preview doesn't contain the edit yet
  } else {
    clearTimeout(followTimer);
    followTimer = setTimeout(followCursor, 120);
  }
}

async function followCursor() {
  if (!following || !view || historyUI.viewing || !currentPath?.endsWith('.typ')) return;
  const seq = ++followSeq;
  const path = currentPath;
  let res;
  try {
    res = await api('POST', `/api/projects/${projectId}/cursor`, {
      path,
      offset: view.state.selection.main.head,
      target: previewTarget(),
    });
  } catch {
    return; // e.g. the fallback compiler, which can't do this
  }
  if (seq !== followSeq || path !== currentPath || res.kind !== 'position') return;
  preview.reveal(res.page, res.x, res.y, res.size);
}

// ---- pasting and dropping files into the editor ---------------------------------

const IMAGE_EXT = /\.(png|jpe?g|gif|svg|webp)$/i;
const MIME_EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/svg+xml': 'svg', 'image/webp': 'webp' };
const isImageFile = (file) => file.type in MIME_EXT || IMAGE_EXT.test(file.name || '');

/** Where new images go: an existing top-level image folder, else "images". */
function imageFolder() {
  const tops = new Set([...files.keys(), ...folders.keys()].filter((p) => p.includes('/') || folders.has(p)).map((p) => p.split('/')[0]));
  for (const want of ['assets', 'images', 'img', 'figures', 'media']) {
    const hit = [...tops].find((t) => t.toLowerCase() === want);
    if (hit) return hit;
  }
  return 'images';
}

/** Path of `target` as written from inside `fromFile` (Typst resolves paths relative to the file). */
function relativePath(fromFile, target) {
  const from = parentOf(fromFile).split('/').filter(Boolean);
  const to = target.split('/');
  let i = 0;
  while (i < from.length && i < to.length - 1 && from[i] === to[i]) i++;
  return [...Array(from.length - i).fill('..'), ...to.slice(i)].join('/');
}

/** Is `pos` in code (function arguments, code blocks) rather than markup? */
function inCodeMode(state, pos) {
  for (let node = syntaxTree(state).resolveInner(pos, -1); node; node = node.parent) {
    if (['Markup', 'ContentBlock', 'Math', 'Equation'].includes(node.name)) return false;
    if (['Code', 'CodeBlock', 'Args', 'Parenthesized', 'Array', 'Dict'].includes(node.name)) return true;
  }
  return false;
}

/** Inserts references to project files at `pos`: images, or #include for .typ files. */
function insertReferences(view, pos, paths) {
  const code = inCodeMode(view.state, pos);
  const hash = code ? '' : '#';
  const snippets = paths.map((p) => {
    const rel = relativePath(currentPath, p);
    return p.endsWith('.typ') ? `${hash}include "${rel}"` : `${hash}image("${rel}")`;
  });
  const text = snippets.join(code ? ', ' : '\n');
  view.dispatch({ changes: { from: pos, insert: text }, selection: { anchor: pos + text.length }, userEvent: 'input.paste' });
  view.focus();
}

const cleanName = (name) =>
  name
    .normalize('NFKD')
    .replace(/[^\w.\-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-(?=\.)/g, '');

/** Picks free project paths for images; pasted ones get a timestamped name. */
function planImagePaths(list, pasted) {
  const folder = imageFolder();
  const taken = new Set(files.keys());
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
  return list.map((file, i) => {
    const ext = (file.name?.match(IMAGE_EXT)?.[1] || MIME_EXT[file.type] || 'png').toLowerCase();
    const generic = pasted || !file.name || /^image\.\w+$/i.test(file.name);
    const stem = generic ? `pasted-${stamp}${list.length > 1 ? `-${i + 1}` : ''}` : cleanName(file.name.replace(/\.[^.]+$/, '')) || 'image';
    let path = `${folder}/${stem}.${ext}`;
    for (let n = 1; taken.has(path); n++) path = `${folder}/${stem}-${n}.${ext}`;
    taken.add(path);
    return { file, path };
  });
}

/** Inserts the references right away (so they land where you meant), then uploads. */
async function insertImages(view, pos, list, pasted) {
  const plan = planImagePaths(list, pasted);
  insertReferences(
    view,
    pos,
    plan.map((p) => p.path),
  );
  const results = await Promise.all(
    plan.map(({ file, path }) =>
      fetch(`/api/projects/${projectId}/upload?path=${encodeURIComponent(path)}`, { method: 'POST', body: file })
        .then((r) => r.ok)
        .catch(() => false),
    ),
  );
  const failed = plan.filter((_, i) => !results[i]).map((p) => p.path);
  if (failed.length) toast(`Upload failed: ${failed.join(', ')}`, 'error');
  else toast(plan.length > 1 ? `Added ${plan.length} images` : `Added ${plan[0].path}`);
}

function pasteIntoEditor(event, view) {
  const data = event.clipboardData;
  if (!data) return false;
  // Pasting text (even if an image came along with it) stays a normal paste.
  if (data.getData('text/plain')) return false;
  const images = [...data.files].filter(isImageFile);
  if (!images.length) return false;
  event.preventDefault();
  insertImages(view, view.state.selection.main.head, images, true);
  return true;
}

function dragOverEditor(event) {
  const types = event.dataTransfer?.types || [];
  if (types.includes('Files') || types.includes(DRAG_TYPE)) {
    event.preventDefault(); // allow the drop; CodeMirror still shows the drop cursor
    event.dataTransfer.dropEffect = 'copy';
  }
  return false;
}

function dropIntoEditor(event, view) {
  const dt = event.dataTransfer;
  if (!dt) return false;
  const pos = view.posAtCoords({ x: event.clientX, y: event.clientY }) ?? view.state.selection.main.head;

  // A file dragged from the Files tab: just reference it.
  if (dt.types.includes(DRAG_TYPE)) {
    event.preventDefault();
    const item = dragging;
    if (item && !item.isFolder && (IMAGE_EXT.test(item.path) || item.path.endsWith('.typ'))) {
      insertReferences(view, pos, [item.path]);
    } else if (item) {
      toast('Only images and .typ files can be dropped into the editor');
    }
    return true;
  }

  const dropped = [...dt.files];
  if (!dropped.length) return false;
  event.preventDefault();
  const images = dropped.filter(isImageFile);
  const others = dropped.filter((f) => !isImageFile(f));
  if (images.length) insertImages(view, pos, images, false);
  if (others.length) {
    uploadEntries(others.map((file) => ({ file, path: file.name })));
    toast(`Uploaded ${others.map((f) => f.name).join(', ')} to the project (only images are inserted)`);
  }
  return true;
}

// ---- click-to-source --------------------------------------------------------

let flashTimer;
function revealSource(path, position) {
  if (path !== currentPath || !view) openFile(path, { focus: false });
  if (!view) return;
  const doc = view.state.doc;
  const line = doc.line(Math.min(Math.max((position?.line ?? 0) + 1, 1), doc.lines));
  const pos = line.from + Math.min(position?.character ?? 0, line.length);
  view.dispatch({
    selection: EditorSelection.cursor(pos),
    effects: [EditorView.scrollIntoView(pos, { y: 'center' }), flashLine.of(line.from)],
  });
  view.focus();
  clearTimeout(flashTimer);
  const flashed = view;
  flashTimer = setTimeout(() => flashed.dispatch({ effects: flashLine.of(null) }), 1600);
}

$('preview').addEventListener('click', async (e) => {
  if (e.button !== 0) return;
  // External links have a URL and open normally; internal ones (table of
  // contents, @references, #link(<label>)) have none and are resolved below.
  const link = e.target.closest('a');
  if (link && (link.getAttribute('href') || link.getAttribute('xlink:href'))) return;
  const pageEl = e.target.closest('.page');
  const index = preview.pages.findIndex((p) => p.el === pageEl);
  if (index < 0) return;
  const page = preview.pages[index];
  const rect = pageEl.getBoundingClientRect();
  const x = ((e.clientX - rect.left) / rect.width) * page.w;
  const y = ((e.clientY - rect.top) / rect.height) * page.h;
  let res;
  try {
    res = await api('POST', `/api/projects/${projectId}/jump`, { page: index, x, y, target: previewTarget() });
  } catch (err) {
    return toast(err.message, 'error');
  }
  if (res.kind === 'file' && files.get(res.path) instanceof Y.Text) revealSource(res.path, res.position);
  else if (res.kind === 'url') window.open(res.url, '_blank', 'noopener');
  else if (res.kind === 'position') followInternalLink(res.page, res.y);
});

// Internal links remember where you came from, like a PDF viewer's back button.
const linkHistory = [];
function followInternalLink(page, y) {
  const here = preview.viewportPoint(40);
  if (here) linkHistory.push(here);
  if (linkHistory.length > 50) linkHistory.shift();
  preview.scrollToPoint(page, y);
  preview.flashAt(page, y);
  $('preview-back').hidden = false;
}
$('preview-back').onclick = () => {
  const back = linkHistory.pop();
  if (back) preview.scrollToPoint(back.page, back.y);
  $('preview-back').hidden = linkHistory.length === 0;
};

// ---- what the preview shows -------------------------------------------------
// Either the project's main file, or the last .typ file you opened, compiled on
// its own. The server compiles whichever one this client asked for.

const TARGET_KEY = 'typst-local-preview-target';
let soloPath = null; // the last .typ file opened that isn't the main file
let soloMode = false; // show that file instead of the main one
try {
  soloMode = localStorage.getItem(TARGET_KEY) === 'file';
} catch {}

/** The file the server compiles for us, or null for the project's main file. */
const previewTarget = () => (soloMode ? soloPath : null);
let sentTarget = null; // what the server was last told

function renderPreviewTarget() {
  $('preview-target').hidden = !soloPath;
  if (!soloPath) return;
  const main = mainFile();
  const name = (path) => path.split('/').pop();
  Object.assign($('target-main'), { textContent: name(main), title: `Preview ${main}, the project's main file` });
  Object.assign($('target-file'), { textContent: name(soloPath), title: `Preview ${soloPath} on its own` });
  $('target-main').classList.toggle('active', !soloMode);
  $('target-file').classList.toggle('active', soloMode);
}

/** Asks the server for the preview we want now, and drops what belonged to the old one. */
function syncTarget({ force = false } = {}) {
  const target = previewTarget();
  if (!force && target === sentTarget) return;
  sentTarget = target;
  lastCompile = null;
  linkHistory.length = 0;
  $('preview-back').hidden = true;
  // The pages still on screen are the other document's; the next compile replaces them.
  $('preview').classList.add('stale');
  renderStatus();
  renderProblems();
  provider.send(JSON.stringify({ type: 'target', path: target }));
}

/**
 * Remembers the file the toggle offers. Called whenever a file is opened and
 * whenever the project changes, so a deleted file or a new main file can't
 * leave the toggle pointing at something that makes no sense.
 */
function setSoloFile(path) {
  soloPath = path && path !== mainFile() && path.endsWith('.typ') && files.has(path) ? path : null;
  renderPreviewTarget();
  syncTarget();
}

function setSoloMode(on) {
  soloMode = on;
  try {
    localStorage.setItem(TARGET_KEY, on ? 'file' : 'main');
  } catch {}
  renderPreviewTarget();
  syncTarget();
  renderTree();
}
$('target-main').onclick = () => setSoloMode(false);
$('target-file').onclick = () => setSoloMode(true);

provider.addEventListener('message', ({ detail: msg }) => {
  if (msg.type === 'compile') {
    if ((msg.target ?? null) !== previewTarget()) return; // a preview we no longer show
    lastCompile = msg;
    if (msg.preview) preview.update(msg.preview);
    if (msg.outline) outlineUI.update(msg.outline);
    $('preview').classList.toggle('stale', msg.status === 'error');
    applyDiagnostics();
    renderProblems();
    renderStatus();
    renderZoom();
    renderTree();
    if (followAfterCompile) {
      followAfterCompile = false;
      followCursor();
    }
  } else if (msg.type === 'history') {
    historyUI.onHistoryChanged();
  } else if (msg.type === 'restored') {
    if (msg.by !== user.name) toast(`${msg.by || 'Someone'} restored ${msg.label}`);
  } else if (msg.type === 'meta') {
    $('project-name').textContent = msg.meta.name;
    document.title = `${msg.meta.name} · Typst Local`;
  }
});

provider.addEventListener('status', () => {
  $('conn').className = 'conn ' + provider.status;
  $('conn').title = provider.status;
  renderStatus();
  // A reconnected server knows nothing about what we chose to preview.
  if (provider.status === 'connected' && previewTarget()) syncTarget({ force: true });
  if (provider.status === 'removed') {
    dialog({ title: 'Project deleted', message: 'This project was deleted by someone else.', confirm: 'Back to projects', cancel: null }).then(
      () => (location.href = '/'),
    );
  }
});

// ---- version history --------------------------------------------------------

const historyUI = initHistory({
  projectId,
  files,
  getUser: () => user,
  editorExtensions: (path) => [languageFor(path), editorTheme],
  onEnter: () => {
    view?.destroy();
    view = null;
  },
  onExit: () => openFile(currentPath, { focus: false }),
  onTab: (tab) => outlineUI.setVisible(tab === 'headings'),
});

// ---- headings tab -------------------------------------------------------------

const outlineUI = initOutline({
  preview,
  onSelect(heading) {
    if (heading.path && files.get(heading.path) instanceof Y.Text) revealSource(heading.path, heading.position);
    preview.scrollToPoint(heading.page, heading.y);
  },
});

// ---- file tree --------------------------------------------------------------

const COLLAPSED_KEY = `typst-local-collapsed-${projectId}`;
const collapsed = new Set(
  (() => {
    try {
      return JSON.parse(localStorage.getItem(COLLAPSED_KEY)) || [];
    } catch {
      return [];
    }
  })(),
);
const saveCollapsed = () => {
  try {
    localStorage.setItem(COLLAPSED_KEY, JSON.stringify([...collapsed]));
  } catch {}
};
function setCollapsed(path, value) {
  if (value) collapsed.add(path);
  else collapsed.delete(path);
  saveCollapsed();
  renderTree();
}

const ICONS = {
  typ: '<path d="M4 2h6l3 3v9H4z"/><path d="M6.5 8h4M8.5 8v4"/>',
  image: '<rect x="2.5" y="3" width="11" height="10" rx="1.5"/><circle cx="6" cy="6.5" r="1.2"/><path d="M3 12l3.5-3.5 2.5 2.5 2-2 2.5 2.5"/>',
  font: '<path d="M4 13L8 3l4 10M5.5 9.5h5"/>',
  data: '<path d="M4 2h6l3 3v9H4z"/><path d="M6 7h5M6 9.5h5M6 12h3"/>',
  folder: '<path d="M2 4.5h4.5l1.5 1.5h6v7H2z"/>',
  folderOpen: '<path d="M2 13V4.5h4.5L8 6h5.5v2"/><path d="M2 13l2-5h11l-2 5z"/>',
  file: '<path d="M4 2h6l3 3v9H4z"/>',
};

function fileIcon(path, isFolder, open = false) {
  const ext = path.split('.').pop().toLowerCase();
  const kind = isFolder
    ? open
      ? 'folderOpen'
      : 'folder'
    : ext === 'typ'
      ? 'typ'
      : /^(png|jpe?g|gif|svg|webp|bmp|avif)$/.test(ext)
        ? 'image'
        : /^(ttf|otf|ttc|otc|woff2?)$/.test(ext)
          ? 'font'
          : /^(bib|yml|yaml|toml|json|csv|xml|txt|md)$/.test(ext)
            ? 'data'
            : 'file';
  const span = h('span.ficon.' + (isFolder ? 'folder' : kind));
  span.innerHTML = `<svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" stroke-linecap="round">${ICONS[kind]}</svg>`;
  return span;
}

const parentOf = (path) => (path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');
const baseName = (path) => path.slice(path.lastIndexOf('/') + 1);
const joinPath = (folder, name) => (folder ? folder + '/' + name : name);
const isInside = (path, folder) => path === folder || path.startsWith(folder + '/');
const folderExists = (path) => folders.has(path) || [...files.keys()].some((p) => p.startsWith(path + '/'));

function buildTree() {
  const root = { name: '', path: '', folders: new Map(), files: [] };
  const ensure = (path) => {
    let node = root;
    if (!path) return node;
    const parts = path.split('/');
    parts.forEach((part, i) => {
      if (!node.folders.has(part)) node.folders.set(part, { name: part, path: parts.slice(0, i + 1).join('/'), folders: new Map(), files: [] });
      node = node.folders.get(part);
    });
    return node;
  };
  for (const path of folders.keys()) ensure(path);
  for (const path of files.keys()) ensure(parentOf(path)).files.push({ name: baseName(path), path });
  return root;
}

function presenceByFile() {
  const map = new Map();
  awareness.getStates().forEach((state, clientId) => {
    if (clientId === ydoc.clientID || !state.file || !state.user) return;
    if (!map.has(state.file)) map.set(state.file, []);
    map.get(state.file).push(state.user);
  });
  return map;
}

// ---- drag and drop: moving inside the tree, uploading from the desktop ----

const DRAG_TYPE = 'application/x-typst-local-path';
let dragging = null; // {path, isFolder} while a tree row is being dragged

function canDropInto(folder) {
  if (!dragging) return true;
  if (parentOf(dragging.path) === folder) return false;
  return !(dragging.isFolder && isInside(folder, dragging.path));
}

/** Makes `el` accept drops into `folder` ('' = project root). */
function dropTarget(el, folder) {
  el.addEventListener('dragover', (e) => {
    const internal = e.dataTransfer.types.includes(DRAG_TYPE);
    if (!internal && !e.dataTransfer.types.includes('Files')) return;
    e.stopPropagation();
    if (internal && !canDropInto(folder)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = internal ? 'move' : 'copy';
    document.querySelectorAll('.drop').forEach((x) => x !== el && x.classList.remove('drop'));
    el.classList.add('drop');
  });
  el.addEventListener('dragleave', (e) => {
    if (!el.contains(e.relatedTarget)) el.classList.remove('drop');
  });
  el.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    el.classList.remove('drop');
    sidebar.classList.remove('dragging');
    if (e.dataTransfer.types.includes(DRAG_TYPE)) {
      if (dragging) moveTo(dragging.path, joinPath(folder, baseName(dragging.path)), dragging.isFolder);
    } else {
      uploadDropped(e.dataTransfer, folder ? folder + '/' : '');
    }
  });
}

function draggableRow(el, path, isFolder) {
  el.draggable = true;
  el.addEventListener('dragstart', (e) => {
    dragging = { path, isFolder };
    e.dataTransfer.setData(DRAG_TYPE, path);
    e.dataTransfer.effectAllowed = 'move';
    requestAnimationFrame(() => el.classList.add('drag-source'));
  });
  el.addEventListener('dragend', () => {
    dragging = null;
    el.classList.remove('drag-source');
    document.querySelectorAll('.drop').forEach((x) => x.classList.remove('drop'));
  });
}

function renderTree() {
  const tree = buildTree();
  const presence = presenceByFile();
  const errorFiles = new Set((lastCompile?.diagnostics || []).filter((d) => d.severity === 'error').map((d) => d.path));
  const main = mainFile();
  const byName = (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true });

  const renderFolder = (node, depth) => {
    const out = [];
    for (const folder of [...node.folders.values()].sort(byName)) {
      const isCollapsed = collapsed.has(folder.path);
      const isEmpty = !folder.folders.size && !folder.files.length;
      const hasOpenFile = currentPath?.startsWith(folder.path + '/');
      const row = h(
        'div.tree-row.folder' + (isCollapsed && hasOpenFile ? '.contains-open' : ''),
        {
          style: { paddingLeft: 8 + depth * 14 + 'px' },
          onclick: () => setCollapsed(folder.path, !isCollapsed),
          oncontextmenu: (e) => folderMenu(e, folder.path),
          title: folder.path,
        },
        h('span.chev', null, isCollapsed ? '▸' : '▾'),
        fileIcon(folder.path, true, !isCollapsed),
        h('span.tree-name', null, folder.name),
        h('button.icon-btn.row-menu', { title: 'More', onclick: (e) => (e.stopPropagation(), folderMenu(e.currentTarget, folder.path)), html: '&#8943;' }),
      );
      draggableRow(row, folder.path, true);
      dropTarget(row, folder.path);
      out.push(row);
      if (!isCollapsed) {
        out.push(...renderFolder(folder, depth + 1));
        if (isEmpty) out.push(h('div.tree-empty', { style: { paddingLeft: 8 + (depth + 1) * 14 + 14 + 'px' } }, 'Empty folder'));
      }
    }
    for (const file of node.files.sort(byName)) {
      const users = presence.get(file.path) || [];
      const row = h(
        'div.tree-row.file' + (file.path === currentPath ? '.selected' : ''),
        {
          style: { paddingLeft: 8 + depth * 14 + 14 + 'px' },
          onclick: () => openFile(file.path),
          oncontextmenu: (e) => fileMenu(e, file.path),
          title: file.path,
        },
        fileIcon(file.path),
        h('span.tree-name' + (errorFiles.has(file.path) ? '.has-error' : ''), null, file.name),
        file.path === main && h('span.badge', { title: 'Main file (compiled)' }, 'main'),
        soloMode && file.path === soloPath && h('span.badge', { title: 'Previewed on its own' }, 'preview'),
        h(
          'span.presence',
          null,
          users.slice(0, 3).map((u) => h('span.dot', { style: { background: u.color }, title: u.name })),
        ),
        h('button.icon-btn.row-menu', { title: 'More', onclick: (e) => (e.stopPropagation(), fileMenu(e.currentTarget, file.path)), html: '&#8943;' }),
      );
      draggableRow(row, file.path, false);
      // Dropping onto a file puts things next to it, in the same folder.
      dropTarget(row, parentOf(file.path));
      out.push(row);
    }
    return out;
  };
  $('tree').replaceChildren(...renderFolder(tree, 0));
}

function fileMenu(anchor, path) {
  if (anchor instanceof MouseEvent) anchor.preventDefault();
  const items = [
    { label: 'Rename / move', onclick: () => renamePath(path) },
    path.endsWith('.typ') && path !== mainFile() && { label: 'Set as main file', onclick: () => settings.set('main', path) },
    {
      label: 'Download',
      onclick: () => (location.href = `/api/projects/${projectId}/raw/${path.split('/').map(encodeURIComponent).join('/')}?download=1`),
    },
    'sep',
    { label: 'Delete', danger: true, onclick: () => deleteFile(path) },
  ].filter(Boolean);
  popupMenu(anchor, items);
}

function folderMenu(anchor, folder) {
  if (anchor instanceof MouseEvent) anchor.preventDefault();
  popupMenu(anchor, [
    { label: 'New file here', onclick: () => newFile(folder + '/') },
    { label: 'New folder here', onclick: () => newFolder(folder + '/') },
    { label: 'Upload files here', onclick: () => pickUpload(folder + '/') },
    { label: 'Upload folder here', onclick: () => pickUpload(folder + '/', true) },
    { label: 'Rename / move folder', onclick: () => renamePath(folder, true) },
    'sep',
    { label: 'Delete folder', danger: true, onclick: () => deleteFolder(folder) },
  ]);
}

const normalize = (p) =>
  p
    .replace(/\\/g, '/')
    .split('/')
    .filter((s) => s && s !== '.' && s !== '..')
    .join('/');

/** Expands every folder on the way to `path` so it is visible. */
function reveal(path) {
  let changed = false;
  for (let p = parentOf(path); p; p = parentOf(p)) changed = collapsed.delete(p) || changed;
  if (changed) saveCollapsed();
}

async function newFile(prefix = '') {
  const res = await dialog({
    title: 'New file',
    message: 'Tip: include a folder in the name to create it too, e.g. chapters/intro.typ',
    fields: [{ name: 'path', label: 'File name', value: prefix + 'untitled.typ' }],
    confirm: 'Create',
  });
  if (!res) return;
  const path = normalize(res.path);
  if (!path) return;
  if (files.has(path) || folderExists(path)) return toast(`"${path}" already exists`, 'error');
  reveal(path);
  files.set(path, new Y.Text(''));
  openFile(path);
}

async function newFolder(prefix = '') {
  const res = await dialog({
    title: 'New folder',
    fields: [{ name: 'path', label: 'Folder name', value: prefix + 'untitled-folder' }],
    confirm: 'Create',
  });
  if (!res) return;
  const path = normalize(res.path);
  if (!path) return;
  if (files.has(path) || folderExists(path)) return toast(`"${path}" already exists`, 'error');
  reveal(path);
  collapsed.delete(path);
  saveCollapsed();
  folders.set(path, true);
}

function movePath(from, to) {
  const entry = files.get(from);
  files.set(to, entry instanceof Y.Text ? new Y.Text(entry.toString()) : { ...entry });
  files.delete(from);
  if (settings.get('main') === from) settings.set('main', to);
  if (soloPath === from) soloPath = to; // the preview toggle follows the rename
}

/** Moves or renames a file or a whole folder. Returns false on a name clash. */
function moveTo(path, to, isFolder) {
  to = normalize(to);
  if (!to || to === path) return false;
  if (isFolder && isInside(to, path)) return toast("A folder can't be moved into itself", 'error'), false;
  const fileMoves = isFolder
    ? [...files.keys()].filter((p) => p.startsWith(path + '/')).map((p) => [p, to + p.slice(path.length)])
    : [[path, to]];
  const folderMoves = isFolder ? [...folders.keys()].filter((p) => isInside(p, path)).map((p) => [p, to + p.slice(path.length)]) : [];
  if (files.has(to) || folderExists(to)) return toast(`"${to}" already exists`, 'error'), false;

  ydoc.transact(() => {
    fileMoves.forEach(([a, b]) => movePath(a, b));
    folderMoves.forEach(([a, b]) => {
      folders.delete(a);
      folders.set(b, true);
    });
    // Like a file system: moving something out leaves its old folder in place.
    const oldParent = parentOf(path);
    if (oldParent) folders.set(oldParent, true);
  });

  if (isFolder) {
    for (const p of [...collapsed]) {
      if (isInside(p, path)) {
        collapsed.delete(p);
        collapsed.add(to + p.slice(path.length));
      }
    }
    saveCollapsed();
  }
  reveal(to);
  const moved = fileMoves.find(([a]) => a === currentPath);
  if (moved) openFile(moved[1], { focus: false });
  else renderTree();
  return true;
}

async function renamePath(path, isFolder = false) {
  const res = await dialog({
    title: isFolder ? 'Rename / move folder' : 'Rename / move file',
    message: 'Change the folder part of the path to move it.',
    fields: [{ name: 'path', label: 'New path', value: path }],
    confirm: 'Rename',
  });
  if (res) moveTo(path, res.path, isFolder);
}

async function deleteFile(path) {
  const ok = await dialog({ title: 'Delete file?', message: `"${path}" will be deleted for everyone.`, confirm: 'Delete', danger: true });
  if (!ok) return;
  ydoc.transact(() => {
    files.delete(path);
    if (parentOf(path)) folders.set(parentOf(path), true);
  });
}

async function deleteFolder(folder) {
  const inside = [...files.keys()].filter((p) => p.startsWith(folder + '/'));
  const ok = await dialog({
    title: 'Delete folder?',
    message: `"${folder}"${inside.length ? ` and the ${inside.length} file${inside.length > 1 ? 's' : ''} in it` : ''} will be deleted for everyone.`,
    confirm: 'Delete',
    danger: true,
  });
  if (!ok) return;
  ydoc.transact(() => {
    inside.forEach((p) => files.delete(p));
    [...folders.keys()].filter((p) => isInside(p, folder)).forEach((p) => folders.delete(p));
    if (parentOf(folder)) folders.set(parentOf(folder), true);
  });
}

// ---- uploads ----

/** Uploads [{file, path}] (paths relative to `prefix`) and creates `dirs` as folders. */
async function uploadEntries(entries, prefix = '', dirs = []) {
  ydoc.transact(() => dirs.forEach((d) => d && folders.set(normalize(prefix + d), true)));
  if (prefix) reveal(prefix + 'x');
  let done = 0;
  let failed = 0;
  for (const { file, path } of entries) {
    const res = await fetch(`/api/projects/${projectId}/upload?path=${encodeURIComponent(normalize(prefix + path))}`, {
      method: 'POST',
      body: file,
    }).catch(() => null);
    if (!res?.ok) failed++;
    if (entries.length > 3) toast(`Uploading… ${++done} / ${entries.length}`);
  }
  if (failed) toast(`${failed} upload${failed > 1 ? 's' : ''} failed`, 'error');
  else if (entries.length) toast(`Uploaded ${entries.length} file${entries.length > 1 ? 's' : ''}`);
}

const isHidden = (name) => name.startsWith('.');

/** Reads files and whole folders dropped from the desktop. */
function uploadDropped(dataTransfer, prefix) {
  // Entries must be grabbed synchronously, before the drop event ends.
  const roots = [...dataTransfer.items].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  if (!roots.length) return uploadEntries([...dataTransfer.files].map((file) => ({ file, path: file.name })), prefix);
  const entries = [];
  const dirs = [];
  const walk = async (entry, base) => {
    if (isHidden(entry.name)) return;
    if (entry.isFile) {
      entries.push({ file: await new Promise((res, rej) => entry.file(res, rej)), path: base + entry.name });
    } else if (entry.isDirectory) {
      dirs.push(base + entry.name);
      const reader = entry.createReader();
      for (;;) {
        const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        if (!batch.length) break;
        for (const child of batch) await walk(child, base + entry.name + '/');
      }
    }
  };
  (async () => {
    for (const root of roots) await walk(root, '');
    await uploadEntries(entries, prefix, dirs);
  })().catch((e) => toast('Upload failed: ' + e.message, 'error'));
}

let uploadPrefix = '';
function pickUpload(prefix = '', folder = false) {
  uploadPrefix = prefix;
  $(folder ? 'upload-folder-input' : 'upload-input').click();
}
for (const id of ['upload-input', 'upload-folder-input']) {
  $(id).onchange = (e) => {
    const list = [...e.target.files].filter((f) => !(f.webkitRelativePath || f.name).split('/').some(isHidden));
    uploadEntries(
      list.map((file) => ({ file, path: file.webkitRelativePath || file.name })),
      uploadPrefix,
    );
    e.target.value = '';
  };
}

// ---- unused images ----

/** Asks the server which images compiling the main file doesn't read, and offers to delete them. */
async function deleteUnusedImages() {
  const done = toast('Checking which images the document uses…', 'info', { duration: null });
  let found;
  try {
    found = await api('GET', `/api/projects/${projectId}/unused-images`);
  } catch (e) {
    done();
    return toast(e.message, 'error', { duration: 6000 });
  }
  done();
  const { main, images } = found;
  if (!images.length) return toast(`Every image in the project is used by ${main}`);
  const n = images.length;
  const total = formatSize(images.reduce((sum, i) => sum + i.size, 0));
  const ok = await dialog({
    title: `Delete ${n} unused image${n > 1 ? 's' : ''}?`,
    message:
      `${n > 1 ? "These aren't" : "This isn't"} used anywhere in ${main} (${total} in total). ` +
      `${n > 1 ? 'They' : 'It'} will be deleted for everyone; you can undo this from History.`,
    list: images.map((i) => [h('span', { title: i.path }, i.path), h('span.dialog-list-meta', null, formatSize(i.size))]),
    confirm: n > 1 ? `Delete ${n} images` : 'Delete image',
    danger: true,
  });
  if (!ok) return;
  try {
    const { deleted } = await api('POST', `/api/projects/${projectId}/unused-images/delete`, {
      paths: images.map((i) => i.path),
      author: user.name,
    });
    const kept = n - deleted.length;
    toast(
      `Deleted ${deleted.length} image${deleted.length === 1 ? '' : 's'}` +
        (kept ? `; kept ${kept} that ${kept > 1 ? 'are' : 'is'} in use now` : ''),
    );
  } catch (e) {
    toast(e.message, 'error', { duration: 6000 });
  }
}

$('new-file-btn').onclick = () => newFile();
$('new-folder-btn').onclick = () => newFolder();
$('unused-images-btn').onclick = () => deleteUnusedImages();
$('upload-btn').onclick = (e) =>
  popupMenu(e.currentTarget, [
    { label: 'Upload files', onclick: () => pickUpload() },
    { label: 'Upload folder', onclick: () => pickUpload('', true) },
  ]);

const sidebar = $('sidebar');
sidebar.addEventListener('dragover', (e) => {
  if (!e.dataTransfer.types.includes('Files') || e.dataTransfer.types.includes(DRAG_TYPE)) return;
  e.preventDefault();
  sidebar.classList.add('dragging');
});
sidebar.addEventListener('dragleave', (e) => {
  if (!sidebar.contains(e.relatedTarget)) sidebar.classList.remove('dragging');
});
sidebar.addEventListener('drop', (e) => {
  e.preventDefault();
  sidebar.classList.remove('dragging');
  if (!e.dataTransfer.types.includes(DRAG_TYPE)) uploadDropped(e.dataTransfer, '');
});
dropTarget($('tree'), '');

files.observe((event) => {
  if (historyUI.viewing) return renderTree();
  // Reopen when the open file was deleted, renamed away, or replaced (falls back to main).
  if (currentPath && event.keysChanged.has(currentPath)) openFile(currentPath, { focus: false });
  else if (!currentPath && files.size) openFile(mainFile(), { focus: false });
  else renderTree();
  setSoloFile(soloPath); // the file the toggle offers may have been deleted or renamed
});
folders.observe(renderTree);
settings.observe(() => {
  renderTree();
  setSoloFile(soloPath); // a different main file changes what the toggle offers
});

// ---- presence ---------------------------------------------------------------

function renderAvatars() {
  const seen = new Set();
  const people = [];
  awareness.getStates().forEach((state, clientId) => {
    if (!state.user) return;
    const self = clientId === ydoc.clientID;
    const key = self ? 'self' : clientId;
    if (seen.has(key)) return;
    seen.add(key);
    people.push({ ...state.user, file: state.file, self });
  });
  people.sort((a, b) => b.self - a.self);
  $('avatars').replaceChildren(
    ...people.slice(0, 6).map((p) =>
      h(
        'button.avatar' + (p.self ? '.self' : ''),
        {
          style: { background: p.color },
          title: p.self ? `${p.name} (you) — click to rename` : `${p.name}${p.file ? ' · ' + p.file : ''}`,
          onclick: p.self ? renameSelf : () => p.file && openFile(p.file),
        },
        initials(p.name),
      ),
    ),
  );
  if (people.length > 6) $('avatars').append(h('span.avatar.more', null, '+' + (people.length - 6)));
}

async function renameSelf() {
  const res = await dialog({ title: 'Your name', fields: [{ name: 'name', label: 'Display name', value: user.name }], confirm: 'Save' });
  if (!res?.name.trim()) return;
  user.name = res.name.trim().slice(0, 40);
  saveUser(user);
  setPresence();
}

let presenceFrame = 0;
awareness.on('change', () => {
  cancelAnimationFrame(presenceFrame);
  presenceFrame = requestAnimationFrame(() => {
    renderAvatars();
    renderTree();
  });
});

// ---- header actions ---------------------------------------------------------

$('project-name').onclick = async () => {
  const res = await dialog({ title: 'Rename project', fields: [{ name: 'name', value: $('project-name').textContent }], confirm: 'Rename' });
  if (res?.name.trim()) await api('PATCH', `/api/projects/${projectId}`, { name: res.name });
};

$('download-btn').onclick = (e) =>
  popupMenu(e.currentTarget, [
    {
      label: 'PDF',
      onclick: () => {
        toast('Preparing PDF…');
        location.href = `/api/projects/${projectId}/pdf`;
      },
    },
    {
      label: 'Open PDF in new tab',
      onclick: () => {
        // Show something while a long document exports, instead of a blank tab.
        const tab = window.open('', '_blank');
        if (!tab) return toast('Your browser blocked the new tab', 'error');
        tab.document.write(
          '<title>Preparing PDF…</title><body style="margin:0;height:100vh;display:grid;place-items:center;font:15px system-ui,sans-serif;color:#888;background:#f4f5f7">Preparing PDF…</body>',
        );
        tab.document.close();
        tab.location.href = `/api/projects/${projectId}/pdf?inline=1`;
      },
    },
    { label: 'Word document (.docx)', onclick: downloadDocx },
    { label: 'Source files (.zip)', onclick: () => (location.href = `/api/projects/${projectId}/zip`) },
  ]);

let docxPending = false;
async function downloadDocx() {
  if (docxPending) return; // its message is still showing
  docxPending = true;
  // Stays up until the file is ready (long documents take a while); an error
  // message replaces it.
  const done = toast('Preparing Word document…', 'info', { duration: null });
  let blob;
  try {
    const res = await fetch(`/api/projects/${projectId}/docx`);
    if (!res.ok) return toast((await res.text()).split('\n').slice(1).join(' ') || 'Word export failed', 'error');
    blob = await res.blob();
  } catch {
    return toast('Word export failed: the server could not be reached', 'error');
  } finally {
    docxPending = false;
  }
  done();
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: ($('project-name').textContent || 'document') + '.docx' });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

$('share-btn').onclick = async () => {
  const info = await api('GET', '/api/info').catch(() => ({ addresses: [] }));
  const path = location.pathname;
  const urls = [location.origin + path];
  for (const addr of info.addresses) {
    const u = `${location.protocol}//${addr}:${location.port || (location.protocol === 'https:' ? 443 : 80)}${path}`;
    if (!urls.includes(u)) urls.push(u);
  }
  const overlay = h(
    'div.overlay',
    { onmousedown: (e) => e.target === overlay && overlay.remove() },
    h(
      'div.dialog',
      null,
      h('h2', null, 'Share this project'),
      h('p.dialog-message', null, 'Anyone on your network with one of these links can edit along with you.'),
      urls.map((u) =>
        h(
          'div.share-row',
          null,
          h('input.text-input', { value: u, readonly: true, onfocus: (e) => e.target.select() }),
          h(
            'button.btn',
            {
              onclick: async () => {
                try {
                  await navigator.clipboard.writeText(u);
                  toast('Link copied');
                } catch {
                  toast('Select the link and copy it manually');
                }
              },
            },
            'Copy',
          ),
        ),
      ),
      h('div.dialog-actions', null, h('button.btn.primary', { onclick: () => overlay.remove() }, 'Done')),
    ),
  );
  document.body.append(overlay);
};

$('toggle-sidebar').onclick = () => document.body.classList.toggle('no-sidebar');
$('mobile-toggle').onclick = (e) => {
  const on = document.body.classList.toggle('show-preview');
  e.currentTarget.textContent = on ? 'Editor' : 'Preview';
};

// ---- split pane -------------------------------------------------------------

const SPLIT_KEY = 'typst-local-split';
const workspace = document.querySelector('.workspace');
let split = 0.5;
const setSplit = (ratio) => {
  split = Math.min(0.8, Math.max(0.2, ratio));
  workspace.style.setProperty('--left', split + 'fr');
  workspace.style.setProperty('--right', 1 - split + 'fr');
};
try {
  setSplit(parseFloat(localStorage.getItem(SPLIT_KEY)) || 0.5);
} catch {
  setSplit(0.5);
}

$('splitter').addEventListener('pointerdown', (e) => {
  e.preventDefault();
  const splitter = e.currentTarget;
  splitter.setPointerCapture(e.pointerId);
  document.body.classList.add('resizing');
  const editorPane = document.querySelector('.editor-pane').getBoundingClientRect();
  const previewPane = document.querySelector('.preview-pane').getBoundingClientRect();
  const left = editorPane.left;
  const total = previewPane.right - left;
  const move = (ev) => setSplit((ev.clientX - left) / total);
  const up = () => {
    splitter.removeEventListener('pointermove', move);
    splitter.removeEventListener('pointerup', up);
    document.body.classList.remove('resizing');
    try {
      localStorage.setItem(SPLIT_KEY, String(split));
    } catch {}
  };
  splitter.addEventListener('pointermove', move);
  splitter.addEventListener('pointerup', up);
});

// ---- boot -------------------------------------------------------------------

renderStatus();
renderProblems();
renderAvatars();

provider.addEventListener(
  'synced',
  () => {
    document.body.classList.remove('loading');
    const fromHash = decodeURIComponent(location.hash.slice(1));
    openFile(fromHash && files.has(fromHash) ? fromHash : mainFile());
  },
  { once: true },
);

ensureUserName().then((u) => {
  user = u;
  setPresence();
});
