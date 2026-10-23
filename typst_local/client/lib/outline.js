// The "Headings" sidebar tab: every heading in the compiled document, with a
// filter and a depth limit. Clicking one jumps there in the editor and preview;
// the heading you're currently viewing in the preview is highlighted.
import { h } from './common.js';

const DEPTH_KEY = 'typst-local-heading-depth';
const DEPTHS = [1, 2, 3, 'all'];

/**
 * @param {object} ctx
 * @param {import('./preview.js').Preview} ctx.preview
 * @param {(heading: object) => void} ctx.onSelect
 */
export function initOutline({ preview, onSelect }) {
  const $ = (id) => document.getElementById(id);
  const listEl = $('headings-list');
  const filterEl = $('headings-filter');
  const depthEl = $('headings-depth');

  let headings = null; // null until the first compile that reports headings
  let visible = false;
  let rendered = []; // [index into headings, element]
  let current = -1;
  let depth = 2;
  try {
    const saved = localStorage.getItem(DEPTH_KEY);
    if (saved) depth = saved === 'all' ? 'all' : Number(saved);
  } catch {}

  function renderDepth() {
    depthEl.replaceChildren(
      ...DEPTHS.map((d) =>
        h(
          'button' + (d === depth ? '.active' : ''),
          {
            title: d === 'all' ? 'Show all levels' : `Show ${d} level${d > 1 ? 's' : ''}`,
            onclick: () => {
              depth = d;
              try {
                localStorage.setItem(DEPTH_KEY, String(d));
              } catch {}
              renderDepth();
              render();
            },
          },
          d === 'all' ? 'All' : String(d),
        ),
      ),
    );
  }

  function render() {
    if (!visible) return;
    current = -1;
    rendered = [];
    if (!headings) {
      listEl.replaceChildren(h('p.headings-empty', null, 'Headings appear once the document compiles.'));
      return;
    }
    if (!headings.length) {
      listEl.replaceChildren(h('p.headings-empty', null, 'No headings yet. Start a line with = to add one.'));
      return;
    }
    const query = filterEl.value.trim().toLowerCase();
    const items = [];
    headings.forEach((hd, i) => {
      if (query) {
        if (!`${hd.number || ''} ${hd.title}`.toLowerCase().includes(query)) return;
      } else if (depth !== 'all' && hd.level > depth) return;
      const el = h(
        `button.heading-item.level-${Math.min(hd.level, 6)}`,
        {
          style: { paddingLeft: 8 + (query ? 0 : (hd.level - 1) * 14) + 'px' },
          title: `${hd.title || '(untitled)'} · page ${hd.page + 1}${hd.path ? ` · ${hd.path}` : ''}${hd.outlined ? '' : ' · not in the table of contents'}`,
          onclick: () => onSelect(hd),
        },
        hd.number && h('span.heading-number', null, hd.number),
        h('span.heading-title', null, hd.title || '(untitled)'),
        h('span.heading-page', null, String(hd.page + 1)),
      );
      rendered.push([i, el]);
      items.push(el);
    });
    listEl.replaceChildren(...(items.length ? items : [h('p.headings-empty', null, 'No matching headings.')]));
    highlightCurrent();
  }

  /** Highlights the last heading at or above what's showing in the preview. */
  function highlightCurrent() {
    if (!visible || !headings?.length || !rendered.length) return;
    const at = preview.viewportPoint();
    if (!at) return;
    let index = -1;
    for (let i = 0; i < headings.length; i++) {
      const hd = headings[i];
      if (hd.page < at.page || (hd.page === at.page && hd.y <= at.y)) index = i;
      else break;
    }
    // If that heading is hidden by the depth limit, use the closest shown one before it.
    let pick = -1;
    for (let k = 0; k < rendered.length && rendered[k][0] <= index; k++) pick = k;
    if (pick === current) return;
    if (current >= 0) rendered[current]?.[1].classList.remove('current');
    current = pick;
    if (pick >= 0) {
      rendered[pick][1].classList.add('current');
      rendered[pick][1].scrollIntoView({ block: 'nearest' });
    }
  }

  let frame = 0;
  preview.scroller.addEventListener(
    'scroll',
    () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(highlightCurrent);
    },
    { passive: true },
  );
  filterEl.addEventListener('input', render);
  renderDepth();

  return {
    update(list) {
      headings = list;
      render();
    },
    setVisible(value) {
      visible = value;
      if (value) render();
    },
  };
}
