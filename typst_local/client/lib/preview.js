// Renders the server's paged preview: shared defs (glyphs, styles) in one hidden
// <svg>, plus one sheet per page. Updates only carry pages that changed (keyed by
// content hash), and pages are only turned into DOM while near the viewport, so
// long documents stay fast.
const SVG_NS = 'http://www.w3.org/2000/svg';
const NS_ATTRS = `xmlns="${SVG_NS}" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:h5="http://www.w3.org/1999/xhtml"`;
const PT_TO_PX = 96 / 72;
const PAGE_GAP = 16;
const PADDING = 24;

export const ZOOM_STEPS = [0.25, 0.5, 0.67, 0.75, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4];

function parseSvg(markup) {
  const parsed = new DOMParser().parseFromString(markup, 'image/svg+xml');
  if (parsed.querySelector('parsererror')) return null;
  return document.importNode(parsed.documentElement, true);
}

export class Preview {
  /**
   * @param {HTMLElement} container  element the pages go into
   * @param {object} [opts]
   * @param {HTMLElement} [opts.scroller]  scrolling ancestor (defaults to container)
   * @param {() => void} [opts.onMissing]  called when an update references a page we never got
   */
  constructor(container, { scroller = container, onMissing } = {}) {
    this.container = container;
    this.scroller = scroller;
    this.onMissing = onMissing;
    this.pagesEl = document.createElement('div');
    this.pagesEl.className = 'pages';
    this.pagesEl.style.gap = PAGE_GAP + 'px';
    this.pagesEl.style.padding = PADDING + 'px';
    this.defs = document.createElementNS(SVG_NS, 'svg');
    this.defs.setAttribute('class', 'typst-defs');
    // Glyph shapes shared by all pages; only ever added to (ids are content hashes).
    this.glyphs = document.createElementNS(SVG_NS, 'svg');
    this.glyphs.setAttribute('class', 'typst-defs');
    this.glyphIds = new Set();
    container.append(this.defs, this.glyphs, this.pagesEl);
    /** @type {{tid: string, w: number, h: number, svg: string, el: HTMLElement, rendered: boolean}[]} */
    this.pages = [];
    this.zoom = 'fit';
    this.onzoom = null;
    new ResizeObserver(() => this.zoom === 'fit' && this.layout()).observe(container);

    // Render pages coming close to view; drop the DOM of pages far away.
    this.near = new IntersectionObserver(
      (entries) => entries.forEach((e) => e.isIntersecting && this.render(e.target._page)),
      { root: scroller, rootMargin: '1200px 0px' },
    );
    this.far = new IntersectionObserver(
      (entries) => entries.forEach((e) => !e.isIntersecting && this.unrender(e.target._page)),
      { root: scroller, rootMargin: '4000px 0px' },
    );
  }

  /** @param {{defs?: string, glyphs?: Record<string, string>, pages: {tid: string, w: number, h: number, svg?: string}[]}} doc */
  update(doc) {
    const fresh = Object.entries(doc.glyphs || {}).filter(([id]) => !this.glyphIds.has(id));
    if (fresh.length) {
      const parsed = parseSvg(`<svg ${NS_ATTRS}><defs>${fresh.map(([, m]) => m).join('')}</defs></svg>`);
      if (parsed) {
        this.glyphs.append(parsed.firstChild);
        fresh.forEach(([id]) => this.glyphIds.add(id));
      }
    }
    if (doc.defs !== undefined) {
      const defs = parseSvg(`<svg ${NS_ATTRS} class="typst-defs">${doc.defs}</svg>`);
      if (defs) {
        this.defs.replaceWith(defs);
        this.defs = defs;
      }
    }

    const old = new Map();
    for (const p of this.pages) if (!old.has(p.tid)) old.set(p.tid, p);
    const known = new Map(this.pages.map((p) => [p.tid, p.svg]));
    let missing = false;

    const next = doc.pages.map((info, i) => {
      const reused = old.get(info.tid);
      if (reused) {
        old.delete(info.tid);
        return reused;
      }
      const svg = info.svg ?? known.get(info.tid);
      if (svg === undefined) missing = true;
      const el = document.createElement('div');
      el.className = 'page';
      const page = { tid: info.tid, w: info.w, h: info.h, svg: svg ?? '', el, rendered: false };
      el._page = page;
      // Swap a visible page in place without a blank frame.
      if (this.pages[i]?.rendered) this.render(page);
      return page;
    });

    for (const p of old.values()) {
      this.near.unobserve(p.el);
      this.far.unobserve(p.el);
    }
    next.forEach((p, i) => {
      const at = this.pagesEl.children[i];
      if (at !== p.el) this.pagesEl.insertBefore(p.el, at || null);
    });
    while (this.pagesEl.children.length > next.length) this.pagesEl.lastChild.remove();
    this.pages = next;
    this.layout();
    for (const p of next) {
      this.near.observe(p.el);
      this.far.observe(p.el);
    }
    if (missing) this.onMissing?.();
  }

  render(page) {
    if (!page || page.rendered || !page.svg) return;
    // Pages are either complete SVG documents or bare page groups that need a wrapper.
    const svg = parseSvg(page.svg.startsWith('<svg') ? page.svg : `<svg ${NS_ATTRS} viewBox="0 0 ${page.w} ${page.h}">${page.svg}</svg>`);
    if (!svg) return;
    svg.setAttribute('class', 'page-svg');
    svg.removeAttribute('width');
    svg.removeAttribute('height');
    // Replace only the drawing, so overlays like the cursor caret survive.
    page.el.querySelector('.page-svg')?.remove();
    page.el.prepend(svg);
    page.rendered = true;
  }

  unrender(page) {
    if (!page?.rendered) return;
    page.el.querySelector('.page-svg')?.remove();
    page.rendered = false;
  }

  get scale() {
    if (this.zoom !== 'fit') return this.zoom * PT_TO_PX;
    const maxW = Math.max(...this.pages.map((p) => p.w), 1);
    return Math.max(0.1, (this.container.clientWidth - PADDING * 2) / maxW);
  }

  layout() {
    const s = this.scale;
    for (const p of this.pages) {
      p.el.style.width = p.w * s + 'px';
      p.el.style.height = p.h * s + 'px';
    }
  }

  /** Effective zoom as a ratio of 100% (1pt = 1.33px). */
  get effectiveZoom() {
    return this.scale / PT_TO_PX;
  }

  setZoom(zoom, anchor) {
    const c = this.scroller;
    const rect = c.getBoundingClientRect();
    const ax = anchor ? anchor.x - rect.left : c.clientWidth / 2;
    const ay = anchor ? anchor.y - rect.top : c.clientHeight / 2;
    const before = this.scale;
    const fx = (c.scrollLeft + ax) / before;
    const fy = (c.scrollTop + ay) / before;
    this.zoom = zoom;
    this.layout();
    const after = this.scale;
    c.scrollLeft = fx * after - ax;
    c.scrollTop = fy * after - ay;
    this.onzoom?.();
  }

  zoomBy(dir, anchor) {
    const cur = this.effectiveZoom;
    const next = dir > 0 ? ZOOM_STEPS.find((z) => z > cur + 0.001) : [...ZOOM_STEPS].reverse().find((z) => z < cur - 0.001);
    if (next) this.setZoom(next, anchor);
  }

  /**
   * Marks the editor cursor's position (baseline point in pt, font size in pt)
   * and scrolls it into view if it's off-screen.
   */
  reveal(index, x, y, size = 11) {
    const page = this.pages[index];
    if (!page) return;
    const s = this.scale;
    const c = this.scroller;
    const sr = c.getBoundingClientRect();
    const pr = page.el.getBoundingClientRect();
    const top = pr.top - sr.top + (y - size) * s;
    const bottom = pr.top - sr.top + (y + size * 0.3) * s;
    const left = pr.left - sr.left + x * s;
    const margin = 48;
    const dy = top < margin || bottom > c.clientHeight - margin ? top - c.clientHeight / 3 : 0;
    const dx = left < margin || left > c.clientWidth - margin ? left - c.clientWidth / 2 : 0;
    // Absolute targets, so quick successive moves don't stack up; far jumps are instant.
    if (dy || dx) {
      c.scrollTo({
        top: c.scrollTop + dy,
        left: c.scrollLeft + dx,
        behavior: Math.abs(dy) > c.clientHeight * 2 ? 'instant' : 'smooth',
      });
    }

    this.caret?.remove();
    const caret = (this.caret = document.createElement('div'));
    caret.className = 'preview-caret';
    Object.assign(caret.style, { left: x * s + 'px', top: (y - size * 0.8) * s + 'px', height: size * 1.05 * s + 'px' });
    page.el.append(caret);
  }

  /** Briefly highlights the band around point `y` (pt) on page `index`. */
  flashAt(index, y) {
    const page = this.pages[index];
    if (!page) return;
    const band = document.createElement('div');
    band.className = 'link-target';
    band.style.top = Math.max(0, (y - 4) * this.scale) + 'px';
    band.style.height = 24 * this.scale + 'px';
    page.el.append(band);
    setTimeout(() => band.remove(), 1600);
  }

  /** Scrolls so that point `y` (pt) on page `index` is near the top. */
  scrollToPoint(index, y = 0) {
    const page = this.pages[index];
    if (!page) return;
    const offset = page.el.getBoundingClientRect().top - this.scroller.getBoundingClientRect().top;
    const dy = offset + y * this.scale - 40;
    this.scroller.scrollTo({ top: this.scroller.scrollTop + dy, behavior: Math.abs(dy) > this.scroller.clientHeight * 2 ? 'instant' : 'smooth' });
  }

  /** The page and y (pt) of the point `offset` px below the top of the viewport. */
  viewportPoint(offset = 56) {
    if (!this.pages.length) return null;
    const line = this.scroller.getBoundingClientRect().top + offset;
    let index = 0;
    for (let lo = 0, hi = this.pages.length - 1; lo <= hi; ) {
      const mid = (lo + hi) >> 1;
      if (this.pages[mid].el.getBoundingClientRect().top <= line) {
        index = mid;
        lo = mid + 1;
      } else hi = mid - 1;
    }
    const page = this.pages[index];
    const rect = page.el.getBoundingClientRect();
    return { page: index, y: (line - rect.top) / this.scale };
  }

  get pageCount() {
    return this.pages.length;
  }

  /** Index of the page most visible in the viewport (binary search; pages are in order). */
  get currentPage() {
    const line = this.scroller.getBoundingClientRect().top + this.scroller.clientHeight / 3;
    let lo = 0;
    let hi = this.pages.length - 1;
    let idx = 0;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (this.pages[mid].el.getBoundingClientRect().top <= line) {
        idx = mid;
        lo = mid + 1;
      } else hi = mid - 1;
    }
    return idx;
  }
}
