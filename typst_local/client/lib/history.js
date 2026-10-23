// Version history, presented like git: the sidebar "History" tab is a commit
// log (with uncommitted changes on top), each commit shows its own changes
// against its parent, and old versions can be previewed, tagged and restored.
// The server mirrors every version into a real git repo that can be cloned.
import * as Y from 'yjs';
import { EditorView, lineNumbers } from '@codemirror/view';
import { EditorState } from '@codemirror/state';
import { unifiedMergeView } from '@codemirror/merge';
import { api, h, dialog, toast, timeAgo } from './common.js';
import { Preview } from './preview.js';

const MARK = { added: 'A', modified: 'M', deleted: 'D' };
const TAG_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/]{0,79}$/;

/**
 * @param {object} ctx
 * @param {string} ctx.projectId
 * @param {Y.Map<any>} ctx.files
 * @param {() => {name: string}} ctx.getUser
 * @param {(path: string) => import('@codemirror/state').Extension} ctx.editorExtensions
 * @param {() => void} ctx.onEnter  called before showing a version (the live editor should close)
 * @param {() => void} ctx.onExit  called after leaving version view so the live editor can reopen
 * @param {(tab: string) => void} [ctx.onTab]
 */
export function initHistory(ctx) {
  const $ = (id) => document.getElementById(id);
  const listEl = $('history-list');
  const versionPreview = new Preview($('version-pages'), { scroller: $('version-preview') });
  const base = `/api/projects/${ctx.projectId}/history`;
  const active = () => document.body.classList.contains('history-tab');

  let versions = []; // newest first
  let gitInfo = null; // {url, branch} when the server mirrors history to git
  let stale = true;
  const snapshots = new Map(); // version id -> {main, files}
  let working = null; // uncommitted changes vs the latest version: [{path, status}]

  // What's open: a commit (mode "commit": its own changes, or "current":
  // compared with the project now), or the uncommitted changes ("working").
  let selected = null; // {meta, mode, working}
  let selectedPath = null;
  let diffView = null;

  const fullFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  const messageOf = (v) => v.name || v.note || 'Auto-save';
  const shortSha = (v) => (v.commit ? v.commit.slice(0, 7) : null);

  async function snapshot(v) {
    if (!v) return { files: {} };
    if (!snapshots.has(v.id)) snapshots.set(v.id, await api('GET', `${base}/${v.id}`));
    return snapshots.get(v.id);
  }

  // ---- data ---------------------------------------------------------------

  async function refresh() {
    stale = false;
    try {
      const res = await api('GET', base);
      versions = res.versions;
      gitInfo = res.git;
    } catch (e) {
      toast(e.message, 'error');
      return;
    }
    if (selected && !selected.working && !versions.some((v) => v.id === selected.meta.id)) exitVersion();
    if (selected && !selected.working) selected.meta = versions.find((v) => v.id === selected.meta.id);
    $('git-clone-btn').hidden = !gitInfo;
    await computeWorking();
    render();
  }

  function currentContent(path) {
    const v = ctx.files.get(path);
    if (v === undefined) return undefined;
    return v instanceof Y.Text ? v.toString() : { blob: v.blob, size: v.size };
  }

  const same = (a, b) => (typeof a === 'string' || typeof b === 'string' ? a === b : a?.blob === b?.blob);

  /** File-level differences between two snapshots' file maps. */
  function diffFiles(before, after) {
    const out = [];
    for (const path of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
      if (before[path] === undefined) out.push({ path, status: 'added' });
      else if (after[path] === undefined) out.push({ path, status: 'deleted' });
      else if (!same(before[path], after[path])) out.push({ path, status: 'modified' });
    }
    return out;
  }

  function currentFiles() {
    const out = {};
    for (const path of ctx.files.keys()) out[path] = currentContent(path);
    return out;
  }

  async function computeWorking() {
    if (!versions.length) {
      working = null;
      return;
    }
    const latest = await snapshot(versions[0]);
    working = diffFiles(latest.files, currentFiles());
  }

  // ---- list ---------------------------------------------------------------

  function render() {
    const rows = [];
    if (versions.length && working) {
      const isSel = selected?.working;
      rows.push(
        h(
          'div.commit.working' + (isSel ? '.selected' : '') + (working.length ? '.dirty' : ''),
          null,
          h(
            'button.commit-head',
            { onclick: () => (isSel ? exitVersion() : selectWorking()), disabled: !working.length },
            h('div.commit-msg', null, working.length ? 'Uncommitted changes' : 'Nothing to commit, working tree clean'),
            working.length > 0 &&
              h('div.commit-meta', null, h('span', null, `${working.length} file${working.length > 1 ? 's' : ''} changed since the last commit`)),
          ),
          isSel && renderFiles(working, null),
        ),
      );
    }
    versions.forEach((v, i) => {
      const isSel = selected && !selected.working && selected.meta.id === v.id;
      const stats = v.stats;
      rows.push(
        h(
          'div.commit' + (isSel ? '.selected' : '') + (v.tag ? '.tagged' : '') + (v.name ? '.manual' : '') + (i === versions.length - 1 ? '.root' : ''),
          null,
          h(
            'button.commit-head',
            { onclick: () => (isSel ? exitVersion() : selectVersion(v)), title: fullFmt.format(v.ts) },
            h('div.commit-msg', null, h('span.commit-text', null, messageOf(v)), v.tag && h('span.tag-chip', null, v.tag)),
            h(
              'div.commit-meta',
              null,
              h('span.sha', null, shortSha(v) || '·······'),
              h('span.commit-who', null, (v.authors?.length ? v.authors.join(', ') : 'Typst Local') + ' · ' + timeAgo(v.ts)),
              stats &&
                h(
                  'span.commit-stat',
                  null,
                  stats.insertions > 0 && h('span.ins', null, '+' + stats.insertions),
                  stats.deletions > 0 && h('span.del', null, '−' + stats.deletions),
                  !stats.insertions && !stats.deletions && h('span', null, stats.files ? `${stats.files} file${stats.files > 1 ? 's' : ''}` : 'empty'),
                ),
            ),
          ),
          isSel && renderDetails(v, i),
        ),
      );
    });
    if (!versions.length) rows.push(h('p.history-empty', null, 'No commits yet.'));
    listEl.replaceChildren(...rows);
  }

  function renderDetails(v, index) {
    const parent = versions[index + 1];
    const mode = selected.mode;
    const copy = (text, what) =>
      navigator.clipboard?.writeText(text).then(
        () => toast(`Copied ${what}`),
        () => toast(text),
      );
    let files;
    if (mode === 'commit') files = v.changes || selected.commitChanges;
    else files = selected.currentChanges;
    return h(
      'div.commit-body',
      null,
      h(
        'div.commit-info',
        null,
        h('div', null, fullFmt.format(v.ts)),
        v.commit &&
          h(
            'div',
            null,
            'commit ',
            h('button.sha-link', { title: 'Copy full hash', onclick: () => copy(v.commit, 'commit hash') }, v.commit.slice(0, 12)),
            parent?.commit && [' · parent ', h('button.sha-link', { onclick: () => selectVersion(parent) }, parent.commit.slice(0, 7))],
          ),
      ),
      h(
        'div.commit-actions',
        null,
        h('button.btn.small.primary', { onclick: () => restore(v) }, 'Restore'),
        h('button.btn.small', { onclick: () => tagVersion(v) }, v.tag ? 'Retag' : 'Tag…'),
        h('a.btn.small', { href: `${base}/${v.id}/pdf` }, 'PDF'),
      ),
      h(
        'div.segmented',
        null,
        h('button' + (mode === 'commit' ? '.active' : ''), { onclick: () => setMode('commit') }, 'This commit'),
        h('button' + (mode === 'current' ? '.active' : ''), { onclick: () => setMode('current') }, 'vs. now'),
      ),
      files ? renderFiles(files, mode) : h('p.version-same', null, 'Loading…'),
    );
  }

  function renderFiles(list, mode) {
    if (!list.length) {
      return h(
        'p.version-same',
        null,
        mode === 'current' ? 'Identical to the current project.' : mode === 'commit' ? 'No changes in this commit.' : 'Nothing changed.',
      );
    }
    return h(
      'div.version-files',
      null,
      list.map((c) =>
        h(
          'button.version-file' + (c.path === selectedPath ? '.selected' : ''),
          { onclick: () => showFile(c.path), title: c.path },
          h('span.change-mark.' + c.status, null, MARK[c.status]),
          h('span.tree-name', null, c.path),
          (c.add != null || c.del != null) &&
            h('span.file-stat', null, c.add ? h('span.ins', null, '+' + c.add) : null, c.del ? h('span.del', null, '−' + c.del) : null),
        ),
      ),
    );
  }

  // ---- opening a commit -----------------------------------------------------

  function enter(bannerText, showVersionPreview) {
    ctx.onEnter();
    document.body.classList.add('viewing-version');
    document.body.classList.toggle('viewing-working', !showVersionPreview);
    $('version-banner-text').textContent = bannerText;
  }

  async function selectVersion(v) {
    selected = { meta: v, mode: 'commit', commitChanges: null, currentChanges: null };
    selectedPath = null;
    enter(`${shortSha(v) ? shortSha(v) + ' · ' : ''}${messageOf(v)} · ${fullFmt.format(v.ts)}`, true);
    render();
    renderVersionPreview(v);
    await loadChanges();
  }

  async function selectWorking() {
    if (!working?.length) return;
    selected = { meta: versions[0], mode: 'current', working: true, currentChanges: working };
    selectedPath = null;
    enter('Uncommitted changes', false);
    render();
    await snapshot(versions[0]);
    showFile(working.find((c) => c.path === 'main.typ')?.path || working[0].path);
  }

  async function setMode(mode) {
    if (!selected || selected.mode === mode) return;
    selected.mode = mode;
    selectedPath = null;
    render();
    await loadChanges();
  }

  /** Loads what the current mode needs, then opens the most relevant file. */
  async function loadChanges() {
    const sel = selected;
    const v = sel.meta;
    const index = versions.findIndex((x) => x.id === v.id);
    try {
      const data = await snapshot(v);
      if (sel.mode === 'commit') {
        const parent = await snapshot(versions[index + 1]);
        if (!v.changes) sel.commitChanges = diffFiles(parent.files, data.files);
      } else {
        sel.currentChanges = diffFiles(data.files, currentFiles());
      }
      if (selected !== sel) return;
      render();
      const list = sel.mode === 'commit' ? v.changes || sel.commitChanges : sel.currentChanges;
      const first = list.find((c) => c.path === data.main) || list[0];
      showFile(first ? first.path : data.main);
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function renderVersionPreview(v) {
    const status = $('version-preview-status');
    status.textContent = 'Rendering…';
    status.hidden = false;
    $('version-pages').classList.add('loading-pages');
    try {
      const res = await api('GET', `${base}/${v.id}/preview`);
      if (selected?.meta.id !== v.id || selected.working) return;
      if (res.preview) {
        versionPreview.update(res.preview);
        status.hidden = true;
      } else {
        status.textContent = 'This version had errors and could not be rendered.';
      }
    } catch {
      status.textContent = 'Could not render this version.';
    } finally {
      $('version-pages').classList.remove('loading-pages');
    }
  }

  /** Shows one file's diff for the open commit, in the editor area. */
  function showFile(path) {
    if (!selected) return;
    selectedPath = path;
    render();
    const editorEl = $('editor');
    diffView?.destroy();
    diffView = null;
    editorEl.replaceChildren();

    const v = selected.meta;
    const index = versions.findIndex((x) => x.id === v.id);
    const data = snapshots.get(v.id);
    let before;
    let after;
    let labels;
    if (selected.mode === 'commit') {
      before = (snapshots.get(versions[index + 1]?.id) || { files: {} }).files[path];
      after = data.files[path];
      labels = ['before this commit', 'in this commit'];
    } else {
      before = data.files[path];
      after = currentContent(path);
      labels = selected.working ? ['last commit', 'uncommitted'] : ['in this commit', 'added since'];
    }
    $('file-title').textContent = path;
    $('diff-legend').hidden = false;
    $('diff-legend').querySelector('.lg-del').textContent = labels[0];
    $('diff-legend').querySelector('.lg-ins').textContent = labels[1];

    if ((before !== undefined && typeof before !== 'string') || (after !== undefined && typeof after !== 'string')) {
      const blobUrl = (hash) => `/api/projects/${ctx.projectId}/blob/${hash}?name=${encodeURIComponent(path)}`;
      const isImage = /\.(png|jpe?g|gif|webp|bmp|avif)$/i.test(path);
      const side = (label, content) =>
        h(
          'div.binary-side',
          null,
          h('div.muted', null, label),
          content === undefined
            ? h('p', null, '(does not exist)')
            : isImage && typeof content !== 'string'
              ? h('img', { src: blobUrl(content.blob) })
              : h('p', null, typeof content === 'string' ? 'Text file' : `Binary file, ${content.size} bytes`),
        );
      editorEl.append(h('div.binary-view.compare', null, side(labels[0], before), side(labels[1], after)));
      return;
    }

    // A file that only exists on one side is shown whole, tinted, rather than diffed against nothing.
    const diff =
      before === undefined
        ? EditorView.editorAttributes.of({ class: 'whole-added' })
        : after === undefined
          ? EditorView.editorAttributes.of({ class: 'whole-deleted' })
          : unifiedMergeView({ original: before, mergeControls: false, gutter: true, collapseUnchanged: { margin: 3, minSize: 6 } });
    diffView = new EditorView({
      parent: editorEl,
      state: EditorState.create({
        doc: after ?? before,
        extensions: [
          lineNumbers(),
          EditorView.lineWrapping,
          EditorState.readOnly.of(true),
          EditorView.editable.of(false),
          ctx.editorExtensions(path),
          diff,
        ],
      }),
    });
  }

  function exitVersion({ reopen = true } = {}) {
    if (!selected) return;
    selected = null;
    selectedPath = null;
    diffView?.destroy();
    diffView = null;
    document.body.classList.remove('viewing-version', 'viewing-working');
    $('diff-legend').hidden = true;
    render();
    if (reopen) ctx.onExit();
  }

  // ---- actions --------------------------------------------------------------

  async function restore(v) {
    const ok = await dialog({
      title: `Restore ${shortSha(v) || 'this version'}?`,
      message: `Every file will be changed back to how it was in "${messageOf(v)}" (${fullFmt.format(v.ts)}), for everyone. This is recorded as new commits, so nothing is lost: you can restore the commit before it to undo.`,
      confirm: 'Restore',
    });
    if (!ok) return;
    await api('POST', `${base}/${v.id}/restore`, { author: ctx.getUser().name });
    exitVersion();
    toast('Restored');
  }

  async function tagVersion(v) {
    const res = await dialog({
      title: v.tag ? `Retag ${shortSha(v) || 'commit'}` : `Tag ${shortSha(v) || 'commit'}`,
      message: 'A git tag like v1.0 or submitted-draft. Leave empty to remove the tag.',
      fields: [{ name: 'tag', label: 'Tag', value: v.tag || '', placeholder: 'v1.0' }],
      confirm: 'Save tag',
    });
    if (!res) return;
    const tag = res.tag.trim().replace(/\s+/g, '-');
    if (tag && (!TAG_RE.test(tag) || tag.includes('..'))) return toast('Tags may use letters, digits, ".", "-", "_" and "/"', 'error');
    try {
      await api('PUT', `${base}/${v.id}/tag`, { tag });
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function commit() {
    await computeWorking();
    const clean = working && !working.length;
    const res = await dialog({
      title: 'Commit',
      message: clean
        ? 'Nothing changed since the last commit, so this will be an empty commit.'
        : `Records the project as it is now${working ? ` (${working.length} changed file${working.length > 1 ? 's' : ''})` : ''}.`,
      fields: [{ name: 'message', label: 'Message', placeholder: 'Describe what changed' }],
      confirm: 'Commit',
    });
    if (!res) return;
    await api('POST', base, { name: res.message.trim() || 'Update', author: ctx.getUser().name });
    toast('Committed');
  }

  function showClone() {
    if (!gitInfo) return;
    const command = `git clone ${location.origin}${gitInfo.url}`;
    const overlay = h(
      'div.overlay',
      { onmousedown: (e) => e.target === overlay && overlay.remove() },
      h(
        'div.dialog',
        null,
        h('h2', null, 'Clone this project'),
        h(
          'p.dialog-message',
          null,
          'The full history as a git repository (read-only). If the server has a password, git asks for it: use any username and the access password.',
        ),
        h(
          'div.share-row',
          null,
          h('input.text-input', { value: command, readonly: true, onfocus: (e) => e.target.select() }),
          h(
            'button.btn',
            {
              onclick: () =>
                navigator.clipboard?.writeText(command).then(
                  () => toast('Copied'),
                  () => toast('Select the command and copy it manually'),
                ),
            },
            'Copy',
          ),
        ),
        h('div.dialog-actions', null, h('button.btn.primary', { onclick: () => overlay.remove() }, 'Done')),
      ),
    );
    document.body.append(overlay);
  }

  // ---- wiring ---------------------------------------------------------------

  function setTab(tab) {
    document.body.classList.toggle('history-tab', tab === 'history');
    document.body.classList.toggle('headings-tab', tab === 'headings');
    for (const name of ['files', 'history', 'headings']) $('tab-' + name).classList.toggle('active', tab === name);
    if (tab === 'history' && stale) refresh();
    if (tab !== 'history') exitVersion();
    ctx.onTab?.(tab);
  }

  // Keep "uncommitted changes" current while the tab is open.
  let workingTimer;
  ctx.files.observeDeep(() => {
    if (!active()) return;
    clearTimeout(workingTimer);
    workingTimer = setTimeout(async () => {
      await computeWorking();
      if (selected?.working && !working.length) exitVersion();
      else render();
    }, 600);
  });

  $('tab-files').onclick = () => setTab('files');
  $('tab-history').onclick = () => setTab('history');
  $('tab-headings').onclick = () => setTab('headings');
  $('save-version-btn').onclick = () => commit().catch((e) => toast(e.message, 'error'));
  $('git-clone-btn').onclick = showClone;
  $('version-exit').onclick = () => exitVersion();
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && selected && !document.querySelector('.overlay')) exitVersion();
  });

  return {
    /** Server says the version list changed. */
    onHistoryChanged() {
      if (active()) refresh();
      else stale = true;
    },
    get viewing() {
      return !!selected;
    },
    exit: exitVersion,
  };
}
