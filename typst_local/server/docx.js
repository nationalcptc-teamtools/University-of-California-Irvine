// Word export: the engine's HTML export converted by pandoc into a real Word
// document (headings, lists, tables, TOC), styled and laid out after the paged
// document using the engine's style probe, with its fonts embedded.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ROOT } from './env.js';
import { buildReferenceDocx } from './docx-template.js';
import { createZip, readZip } from './zip.js';
import { fontFaceInfo } from './font-names.js';
import crypto from 'node:crypto';

/** pandoc from PANDOC_PATH, the project-local .pandoc/ (setup.sh), or PATH. */
function pandocPath() {
  if (process.env.PANDOC_PATH) return process.env.PANDOC_PATH;
  const local = path.join(ROOT, '.pandoc', 'bin', 'pandoc');
  return fs.existsSync(local) ? local : 'pandoc';
}

export class DocxUnavailableError extends Error {}

/**
 * Figures as pandoc expects them: a picture and a <figcaption> directly
 * inside <figure>, not nested in boxes (inline-block spans) or wrapped in a
 * paragraph. Otherwise pandoc lays the figure out as a two-column table.
 */
function cleanFigures(html) {
  html = html.replace(/<p>((?:<span style="display: inline-block">)+)(<figure>[\s\S]*?<\/figure>)((?:<\/span>)+)<\/p>/g, (whole, open, figure, close) =>
    open.split('<span').length === close.split('</span>').length ? figure : whole,
  );
  // A box holding a single paragraph stays inline (pandoc would make it its own paragraph).
  html = html.replace(/<span style="display: inline-block">\s*<(div|p)>((?:(?!<\/?(?:div|p|table|ul|ol|pre|h\d|figure|blockquote)\b)[\s\S])*?)<\/\1>\s*<\/span>/g, '<span>$2</span>');
  // Pictures need a description, or pandoc stores the whole data URI as one.
  html = html.replace(/<img(?![^>]*\balt=)/g, '<img alt="Picture"');
  html = html.replace(/<p>((?:<(?:em|strong|span)\b[^>]*>)*)<figcaption>([\s\S]*?)<\/figcaption>((?:<\/(?:em|strong|span)>)*)<\/p>/g, '<figcaption>$1$2$3</figcaption>');
  // Figures of anything but a picture (e.g. code listings) become their
  // content followed by a caption paragraph.
  return html.replace(/<figure>(?!\s*<(?:svg|img)\b)((?:(?!<\/?figure>)[\s\S])*?)<figcaption>([\s\S]*?)<\/figcaption>\s*<\/figure>/g, '$1<div custom-style="Caption"><p>$2</p></div>');
}

/**
 * Images get the size they have in the PDF (measured by the probe; matched by
 * their source and size settings, in order). HTML export only knows relative
 * sizes like `width: 70%` as CSS, which pandoc can't resolve.
 */
function sizeImages(html, sizes = []) {
  const queues = new Map();
  for (const [key, w, h] of sizes) {
    if (!queues.has(key)) queues.set(key, []);
    queues.get(key).push([w, h]);
  }
  return html.replace(/<span data-tl-img="([^"]*)"><\/span>((?:\s*<\/?p>\s*)*)(<img\b[^>]*?)(\s*\/?>)/g, (whole, key, between, img, end) => {
    const size = queues.get(unescapeAttr(key))?.shift();
    if (!size || !(size[0] > 0)) return between + img + end;
    const sized = img.replace(/\s(?:width|height|style)="[^"]*"/g, '');
    return `${between}${sized} width="${size[0].toFixed(2)}pt" height="${size[1].toFixed(2)}pt"${end}`;
  }).replace(/<p>\s*<span data-tl-img="[^"]*"><\/span>\s*<\/p>|<span data-tl-img="[^"]*"><\/span>/g, '');
}

/**
 * Each image figure's picture gets the size it has in the PDF (measured by
 * the probe, in order), as Typst's HTML export draws it at its natural size.
 */
function sizeFigures(html, sizes = []) {
  const figures = html.match(/<figure><svg\b/g) || [];
  if (!sizes.length || figures.length !== sizes.length) return html;
  let i = 0;
  return html.replace(/<figure><svg\b/g, (m) => {
    const [w, h] = sizes[i++];
    return w > 0 && h > 0 ? `${m} data-tl-size="${w.toFixed(2)},${h.toFixed(2)}"` : m;
  });
}

/**
 * Inline <svg> (equations drawn by html.frame) isn't understood by pandoc's
 * HTML reader, so each top-level <svg> becomes an <img> with an SVG data URI.
 */
function svgsToImages(html) {
  let out = '';
  let pos = 0;
  for (;;) {
    const start = html.indexOf('<svg', pos);
    if (start < 0) break;
    // Find the matching </svg>, allowing nested <svg> elements.
    let depth = 0;
    let i = start;
    let end = -1;
    while (i < html.length) {
      const open = html.indexOf('<svg', i);
      const close = html.indexOf('</svg>', i);
      if (close < 0) break;
      if (open >= 0 && open < close) {
        depth++;
        i = open + 4;
      } else {
        depth--;
        i = close + 6;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end < 0) break;
    let svg = html.slice(start, end);
    const head = svg.slice(0, svg.indexOf('>'));
    // Typst sizes frames with CSS (em); the viewBox is the real size in
    // points, unless the probe measured the picture on the page.
    const box = /viewBox="[\d.\-]+ [\d.\-]+ ([\d.]+) ([\d.]+)"/.exec(head);
    const measured = /data-tl-size="([\d.]+),([\d.]+)"/.exec(head);
    const [w, h] = measured ? [+measured[1], +measured[2]] : box ? [+box[1], +box[2]] : [null, null];
    let newHead = head.replace(/\s(width|height|data-tl-size)="[^"]*"/g, '').replace(/\sstyle="[^"]*"/, '');
    if (!/xmlns=/.test(newHead)) newHead += ' xmlns="http://www.w3.org/2000/svg"';
    if (!/xmlns:xlink=/.test(newHead) && svg.includes('xlink:')) newHead += ' xmlns:xlink="http://www.w3.org/1999/xlink"';
    if (w) newHead += ` width="${w.toFixed(2)}pt" height="${h.toFixed(2)}pt"`;
    svg = newHead + svg.slice(head.length);
    const size = w ? ` width="${w.toFixed(2)}pt" height="${h.toFixed(2)}pt"` : '';
    // A framed picture (e.g. a screenshot with a template's drop shadow) goes in
    // as the plain raster image, which every Word-compatible app can show.
    const rasters = svg.includes('typst-text') ? [] : [...svg.matchAll(/data:image\/(png|jpe?g|gif|webp);base64,([A-Za-z0-9+/=]+)/g)];
    const raster = rasters.sort((a, b) => b[2].length - a[2].length)[0];
    const src = raster ? `data:image/${raster[1]};base64,${raster[2]}` : `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
    // (pandoc would otherwise use the whole data URI as the description.)
    const caption = /^[\s\S]*?<figcaption>([\s\S]*?)<\/figcaption>/.exec(html.slice(end, end + 4000))?.[1];
    // An inline equation says how far below the baseline it reaches (see pictureRuns()).
    const lower = /<span data-tl-lower="([\d.]+)">$/.exec(html.slice(Math.max(0, start - 40), start))?.[1];
    const alt = lower ? `TLLOWER${lower}` : (html.slice(Math.max(0, start - 12), start).endsWith('<figure>') && caption ? caption.replace(/<[^>]+>/g, '').trim() : '') || 'Picture';
    out += html.slice(pos, start) + `<img alt="${alt.replace(/"/g, '&quot;')}"${size} src="${src}">`;
    pos = end;
  }
  return out + html.slice(pos);
}

const unescapeAttr = (s) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

/**
 * Placed elements arrive between <span data-tl-place="alignment|dx|dy"> and
 * <span data-tl-place-end> markers. The ones the probe found positioned on the
 * page itself (a title page's logo, a date block in the corner) become a
 * picture of exactly what Typst drew, which pinPictures() fixes to the same
 * spot on the Word page. Everything else keeps its content in the text flow.
 */
function pinPlacements(html, placements = []) {
  const byKey = new Map(placements.map((p, i) => [p.key, i]));
  const seen = new Map();
  const starts = [];
  const stack = [];
  const MARK = /<span data-tl-place="([^"]*)"><\/span>|<span data-tl-place-end="1"><\/span>/g;
  for (const m of html.matchAll(MARK)) {
    if (m[1] !== undefined) {
      const sig = unescapeAttr(m[1]);
      const n = (seen.get(sig) || 0) + 1;
      seen.set(sig, n);
      const start = { key: `${sig}#${n}`, from: m.index, inner: m.index + m[0].length, end: -1 };
      starts.push(start);
      stack.push(start);
    } else if (stack.length) {
      const start = stack.pop();
      start.end = m.index + m[0].length;
      start.innerEnd = m.index;
    }
  }
  // Replace the outermost pinned ones whose markers sit at the same nesting
  // depth (content like "</p><p>" between them is fine; the HTML stays valid).
  const balanced = (s) => {
    let depth = 0;
    for (const t of s.matchAll(/<(\/?)([a-zA-Z][\w-]*)[^>]*?(\/?)>/g)) {
      if (t[3] || /^(img|br|hr|meta|link|input|col|wbr|source)$/i.test(t[2])) continue;
      depth += t[1] ? -1 : 1;
    }
    return depth === 0;
  };
  let out = '';
  let pos = 0;
  for (const s of starts) {
    if (s.from < pos || s.end < 0) continue;
    const i = byKey.get(s.key);
    if (i === undefined || !balanced(html.slice(s.inner, s.innerEnd))) continue;
    const p = placements[i];
    out += html.slice(pos, s.from) + `<img alt="TLPLACE${i}" width="${p.w.toFixed(2)}pt" height="${p.h.toFixed(2)}pt" src="data:image/png;base64,${p.png}">`;
    pos = s.end;
  }
  out += html.slice(pos);
  // Drop the remaining markers (and paragraphs holding nothing else).
  return out.replace(/<p>(\s*(<span data-tl-place(-end)?="[^"]*"><\/span>)\s*)+<\/p>/g, '').replace(MARK, '');
}

/**
 * Pictures marked by pinPlacements() float at their exact position on the
 * page; a paragraph left holding nothing else takes up no room.
 */
function pinPictures(documentXml, placements = []) {
  let z = 0;
  const emu = (pt) => Math.round(pt * 12700);
  const anchor = (whole, inner) => {
    const m = /<wp:docPr\b[^>]*descr="TLPLACE(\d+)"/.exec(inner);
    const p = m && placements[+m[1]];
    if (!p) return whole;
    const parts = inner.replace(/(<wp:docPr\b[^>]*?)\s*descr="TLPLACE\d+"/, '$1 descr=""');
    const extent = /<wp:extent\b[^>]*\/>/.exec(parts)?.[0] || '';
    const effect = /<wp:effectExtent\b[^>]*\/>/.exec(parts)?.[0] || '<wp:effectExtent l="0" t="0" r="0" b="0"/>';
    const rest = parts.replace(extent, '').replace(/<wp:effectExtent\b[^>]*\/>/, '');
    return (
      `<wp:anchor distT="0" distB="0" distL="0" distR="0" simplePos="0" relativeHeight="${251659264 + z++}" behindDoc="0" locked="0" layoutInCell="1" allowOverlap="1">` +
      '<wp:simplePos x="0" y="0"/>' +
      `<wp:positionH relativeFrom="page"><wp:posOffset>${emu(p.x)}</wp:posOffset></wp:positionH>` +
      `<wp:positionV relativeFrom="page"><wp:posOffset>${emu(p.y)}</wp:posOffset></wp:positionV>` +
      extent +
      effect +
      '<wp:wrapNone/>' +
      rest +
      '</wp:anchor>'
    );
  };
  return documentXml.replace(/<w:p>(?:(?!<\/w:p>)[\s\S])*?descr="TLPLACE[\s\S]*?<\/w:p>|<w:p [^>]*>(?:(?!<\/w:p>)[\s\S])*?descr="TLPLACE[\s\S]*?<\/w:p>/g, (para) => {
    let out = para.replace(/<wp:inline\b[^>]*>([\s\S]*?)<\/wp:inline>/g, anchor);
    if (!/<w:t[ >]/.test(out)) {
      const style = '<w:pStyle w:val="TLAnchor"/>';
      out = /<w:pPr>/.test(out)
        ? out.replace(/<w:pStyle\b[^>]*\/>/, '').replace('<w:pPr>', `<w:pPr>${style}`)
        : out.replace(/^<w:p\b[^>]*>/, (open) => `${open}<w:pPr>${style}</w:pPr>`);
    }
    return out;
  });
}

/** Vertical spacing and rule markers from the HTML export become placeholder paragraphs (see spacers()). */
function markSpacing(html) {
  return html.replace(/<div data-tl-v="([\d.]+)"><\/div>/g, '<p>TLVSPACE$1</p>').replace(/<hr data-tl-rule="([\d.]+)\|#([0-9a-fA-F]{6})[0-9a-fA-F]{0,2}">/g, '<p>TLRULE$1|$2</p>');
}

/**
 * Placeholder paragraphs become empty paragraphs exactly as tall as the Typst
 * spacing. Empty body paragraphs pandoc leaves behind (e.g. around a box that
 * holds whole paragraphs) are dropped, except where a table cell needs one.
 */
function spacers(documentXml) {
  documentXml = documentXml.replace(/(?<!<w:tc>|<\/w:tcPr>)<w:p><w:pPr><w:pStyle w:val="(?:FirstParagraph|BodyText)" ?\/><\/w:pPr><\/w:p>(?!<\/w:tc>)/g, '');
  // Horizontal lines: a paragraph that's only its bottom border, as thick and
  // coloured as the Typst line (border sizes are in eighths of a point).
  documentXml = documentXml.replace(/<w:p\b(?:(?!<\/w:p>)[\s\S])*?TLRULE([\d.]+)\|([0-9a-fA-F]{6})(?:(?!<\/w:p>)[\s\S])*?<\/w:p>/g, (_, pt, color) => {
    const sz = Math.min(96, Math.max(2, Math.round(+pt * 8)));
    return `<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="${sz}" w:space="0" w:color="${color.toUpperCase()}"/></w:pBdr><w:spacing w:before="0" w:after="0" w:line="20" w:lineRule="exact"/></w:pPr></w:p>`;
  });
  return documentXml.replace(/<w:p\b(?:(?!<\/w:p>)[\s\S])*?TLVSPACE([\d.]+)(?:(?!<\/w:p>)[\s\S])*?<\/w:p>/g, (_, pt) => {
    const twips = Math.min(31680, Math.max(1, Math.round(+pt * 20)));
    return `<w:p><w:pPr><w:spacing w:before="0" w:after="0" w:line="${twips}" w:lineRule="exact"/></w:pPr></w:p>`;
  });
}

/** Runs pandoc once to fetch its default reference.docx (cached). */
let defaultReference = null;
function pandocDefaultReference() {
  if (!defaultReference) {
    defaultReference = new Promise((resolve, reject) => {
      const proc = spawn(pandocPath(), ['--print-default-data-file', 'reference.docx'], { stdio: ['ignore', 'pipe', 'ignore'] });
      const out = [];
      proc.stdout.on('data', (d) => out.push(d));
      proc.on('error', (e) => reject(e.code === 'ENOENT' ? new DocxUnavailableError('pandoc is not installed on the server (re-run setup.sh)') : e));
      proc.on('close', (code) => (code === 0 ? resolve(Buffer.concat(out)) : reject(new Error('pandoc could not provide its reference.docx'))));
    }).catch((e) => {
      defaultReference = null;
      throw e;
    });
  }
  return defaultReference;
}

/**
 * Code blocks keep their syntax highlighting: pandoc turns <pre> into plain
 * text, so each line becomes a paragraph (style "TL Code Line") of runs
 * carrying their colour like any other text.
 */
function highlightCode(html) {
  return html.replace(/<pre>\s*<code\b[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/g, (whole, inner) => {
    if (!inner.includes('data-tl=')) return whole;
    // A colour span around text runs: the runs take on its colour.
    inner = inner.replace(/<span style="color: (#[0-9a-fA-F]{6})">((?:<span data-tl="[^"]*">[^<]*<\/span>)+)<\/span>/g, (_, color, runs) =>
      runs.replace(/data-tl="([^"|]*)\|[^"|]*\|/g, `data-tl="$1|${color.toLowerCase()}|`),
    );
    const lines = inner.split(/<br\s*\/?>/).map((line) => {
      // Keep indentation and runs of spaces (HTML would collapse them).
      let start = true;
      const text = line.replace(/>([^<]*)</g, (_, t) => {
        let out = t.replace(/ {2,}/g, (m) => ' '.repeat(m.length));
        if (start && out.startsWith(' ')) out = ' ' + out.slice(1);
        if (out.trim()) start = false;
        return `>${out}<`;
      });
      return /[^\s]/.test(text.replace(/<[^>]+>/g, '')) ? `<p>${text}</p>` : '<p> </p>';
    });
    return `<div custom-style="TL Code Line">${lines.join('')}</div>`;
  });
}

/** Highlighted code lines: the block's first and last line keep the code block's outer spacing. */
function codeBlockEdges(documentXml, style) {
  const before = 60;
  const after = Math.round(((style?.body?.size || 1100) / 100) * 0.8 * 20);
  const isLine = (p) => p.startsWith('<w:p><w:pPr><w:pStyle w:val="TLCodeLine" />');
  const paras = [...documentXml.matchAll(/<w:p>(?:(?!<\/w:p>)[\s\S])*?<\/w:p>/g)];
  let out = '';
  let pos = 0;
  paras.forEach((m, i) => {
    if (!isLine(m[0])) return;
    const prev = paras[i - 1];
    const next = paras[i + 1];
    const adjacent = (a, b) => a && b && a.index + a[0].length === b.index - (documentXml.slice(a.index + a[0].length, b.index).match(/^\s*/)[0].length);
    const first = !(prev && isLine(prev[0]) && adjacent(prev, m));
    const last = !(next && isLine(next[0]) && adjacent(m, next));
    if (!first && !last) return;
    const values = { ...(first ? { before } : {}), ...(last ? { after } : {}) };
    out += documentXml.slice(pos, m.index) + setSpacing(m[0], values);
    pos = m.index + m[0].length;
  });
  return out + documentXml.slice(pos);
}

/**
 * The document's own table of contents becomes the Word table of contents
 * (built by the Lua filter): its entries, levels and page numbers as Typst
 * laid them out, so it's right even before Word refreshes it. Numbered lists
 * that continue (<li value="2">) get a start number pandoc understands.
 */
function markTableOfContents(html, toc) {
  html = html.replace(/<ol>(\s*<li value="(\d+)")/g, '<ol start="$2">$1');
  html = html.replace(/<div data-tl-enum="([aAiI])">(\s*)<ol\b/g, '<div>$2<ol type="$1"');
  return html.replace(/<nav role="doc-toc">([\s\S]*?)<\/nav>/, (_, inner) => {
    const title = (/<h[1-6][^>]*>([\s\S]*?)<\/h[1-6]>/.exec(inner)?.[1] || '').replace(/<[^>]+>/g, '').trim();
    const links = [...inner.matchAll(/<a href="(#[^"]+)">([\s\S]*?)<\/a>/g)];
    const known = toc?.entries?.length === links.length ? toc.entries : null;
    const entries = links.map((m, i) => {
      const before = inner.slice(0, m.index);
      const depth = (before.match(/<ol\b/g) || []).length - (before.match(/<\/ol>/g) || []).length;
      const level = Math.min(9, Math.max(1, known?.[i].level || depth));
      const text = m[2].replace(/<[^>]+>/g, '').trim();
      const page = known?.[i].page || '';
      return `<div custom-style="toc ${level}"><p><a href="${m[1]}">${text}</a> TLTOCTAB${page}</p></div>`;
    });
    return `<p>TYPSTLOCALTOC::${title}</p>${entries.join('')}<p>TYPSTLOCALTOCEND</p>`;
  });
}

/**
 * Table of contents entries: a tab (dot leader) before the page number, a
 * little space on both sides of the dots (as Typst leaves), and plain (not
 * link-styled) text.
 */
function tocEntries(documentXml) {
  documentXml = documentXml.replace(/<w:r>(<w:rPr>(?:(?!<\/w:r>)[\s\S])*?<\/w:rPr>)?<w:t[^>]*>TLTOCTAB([^<]*)<\/w:t><\/w:r>/g, (_, rPr = '', page) =>
    `<w:r>${rPr}<w:tab/></w:r>` + (page ? `<w:r>${rPr}<w:t xml:space="preserve"> ${page}</w:t></w:r>` : ''),
  );
  return documentXml.replace(/<w:sdt><w:sdtPr><w:docPartObj><w:docPartGallery w:val="Table of Contents"\/>[\s\S]*?<\/w:sdt>/, (toc) =>
    toc.replace(/<w:rStyle w:val="Hyperlink" ?\/>/g, ''),
  );
}

const BOLD = new Set(['semibold', 'bold', 'extrabold', 'black']);

/**
 * The export marks every run of text with its look (size|colour|weight|font).
 * Runs that look like body text or a heading lose the mark; the others get a
 * Word character style ("TL Text n"), returned for the reference document.
 */
function styleRuns(html, probe) {
  // Code keeps Word's code styles; drop marks inside code blocks and inline code.
  html = html.replace(/<(pre|code)\b[\s\S]*?<\/\1>/g, (code) => code.replace(/<span data-tl="[^"]*">([^<]*)<\/span>/g, '$1'));
  const norm = (s) => (s ? { size: s.size / 100, color: s.color.toLowerCase(), bold: !!s.bold, font: s.font?.toLowerCase() } : null);
  const known = [norm(probe?.body), ...(probe?.headings || []).map(norm)].filter(Boolean);
  // Typst reports font families in lower case; use the proper names the probe saw.
  const properName = new Map(
    [probe?.body, probe?.code, ...(probe?.headings || []), ...(probe?.header || []).map((b) => b.style), ...(probe?.footer || []).map((b) => b.style)]
      .filter((s) => s?.font)
      .map((s) => [s.font.toLowerCase(), s.font]),
  );
  const body = known[0];
  // Paragraphs justified differently from the document (e.g. a ragged title
  // page in a justified report) get a marker docx.js turns into alignment.
  // (Also text directly in table cells and list items, which has no <p>.)
  html = html.replace(/<(p|td|th|li)\b([^>]*)>((?:(?!<\/?(?:p|td|th|li|div|table|ul|ol|pre|h\d)\b)[\s\S])*?)<\/\1>/g, (whole, tag, attrs, inner) => {
    const flags = [...inner.matchAll(/<span data-tl="[^"|]*\|[^"|]*\|[^"|]*\|[^"|]*\|([jr])">/g)].map((m) => m[1]);
    if (!flags.length) return whole;
    if (probe?.justify && flags.every((f) => f === 'r')) return `<${tag}${attrs}>TLRAGGED${inner}</${tag}>`;
    if (!probe?.justify && flags.every((f) => f === 'j')) return `<${tag}${attrs}>TLJUSTIFY${inner}</${tag}>`;
    return whole;
  });
  const styles = new Map();
  html = html.replace(/<span data-tl="([^"]*)">([^<]*)<\/span>/g, (_, mark, text) => {
    const [size, rawColor, weight, font] = mark.split('|');
    const run = {
      size: Math.round(parseFloat(size) * 10) / 10,
      color: rawColor ? rawColor.toLowerCase() : null,
      bold: BOLD.has(weight) || parseInt(weight, 10) >= 600,
      font: font ? font.toLowerCase() : null,
    };
    const same = (k) =>
      Math.abs(k.size - run.size) < 0.15 && (run.color ?? body?.color) === k.color && k.bold === run.bold && (!run.font || !k.font || run.font === k.font);
    if (!text.trim() || known.some(same)) return text;
    // Only what differs from body text goes into the character style.
    const diff = {
      size: body && Math.abs(body.size - run.size) < 0.15 ? null : run.size,
      color: run.color && run.color !== body?.color ? run.color : null,
      bold: run.bold,
      font: run.font && run.font !== body?.font ? properName.get(run.font) || run.font : null,
    };
    const key = JSON.stringify(diff);
    if (!styles.has(key)) styles.set(key, { name: `TL Text ${styles.size + 1}`, ...diff });
    return `<span custom-style="${styles.get(key).name}">${text}</span>`;
  });
  return { html, charStyles: [...styles.values()] };
}

const TCPR_ORDER = ['cnfStyle', 'tcW', 'gridSpan', 'hMerge', 'vMerge', 'tcBorders', 'shd', 'noWrap', 'tcMar', 'textDirection', 'tcFitText', 'vAlign', 'hideMark'];

/** Adds a property to the cell containing position `at`, in schema order. */
function putCellProp(xml, at, tag, prop) {
  const tc = Math.max(xml.lastIndexOf('<w:tc>', at), xml.lastIndexOf('<w:tc ', at));
  if (tc < 0) return xml;
  const open = xml.indexOf('>', tc) + 1;
  if (!xml.startsWith('<w:tcPr>', open)) return xml.slice(0, open) + `<w:tcPr>${prop}</w:tcPr>` + xml.slice(open);
  const end = xml.indexOf('</w:tcPr>', open);
  const inner = xml.slice(open, end);
  if (inner.includes(`<w:${tag} `) || inner.includes(`<w:${tag}/`)) return xml;
  const later = TCPR_ORDER.slice(TCPR_ORDER.indexOf(tag) + 1);
  const next = new RegExp(`<w:(${later.join('|')})\\b`).exec(inner);
  const pos = next ? open + next.index : end;
  return xml.slice(0, pos) + prop + xml.slice(pos);
}

/** Cell markers (placed by the Lua filter) become real Word cell shading and vertical alignment. */
function applyCellProps(documentXml) {
  // pandoc writes empty cell properties as <w:tcPr />; open them up so new
  // properties go inside (a cell may only have one tcPr).
  documentXml = documentXml.replace(/<w:tcPr\s*\/>/g, '<w:tcPr></w:tcPr>');
  // One marker per cell; going backwards keeps earlier positions valid.
  const marker = /<w:r><w:t>TLCELL(?:#([0-9A-Fa-f]{6})[0-9A-Fa-f]{0,2})?\|(center|bottom)?<\/w:t><\/w:r>/g;
  for (const m of [...documentXml.matchAll(marker)].reverse()) {
    let xml = documentXml.slice(0, m.index) + documentXml.slice(m.index + m[0].length);
    if (m[2]) xml = putCellProp(xml, m.index, 'vAlign', `<w:vAlign w:val="${m[2]}"/>`);
    if (m[1]) xml = putCellProp(xml, m.index, 'shd', `<w:shd w:val="clear" w:color="auto" w:fill="${m[1].toUpperCase()}"/>`);
    documentXml = xml;
  }
  return documentXml;
}

/** The Word text width in twips (page width minus side margins). */
const textWidthTwips = (style) => {
  const [, mRight, , mLeft] = style?.margins || [72, 72, 72, 72];
  return Math.round(((style?.page_width || 612) - mRight - mLeft) * 20);
};

/**
 * Tables marked with their Typst column widths, overall width and cell
 * padding get those; tables at the top level get the space after them that
 * Typst leaves after a block.
 */
function applyTableProps(documentXml, style) {
  const textWidth = textWidthTwips(style);
  // Typst measures a line of text from cap height to baseline (about 0.7em);
  // Word gives it the full line height, so its cell padding is reduced by the
  // difference to get the same row heights.
  const lineHeight = Math.max(1, Math.min(2, style?.line_height || 1.3));
  const marker = /<w:r><w:t>TLTABLE([\d.,]*)\|([\d.]*)\|([\d.]*)\|([\d.]*)\|([\d.]*)<\/w:t><\/w:r>/g;
  for (const m of [...documentXml.matchAll(marker)].reverse()) {
    let xml = documentXml.slice(0, m.index) + documentXml.slice(m.index + m[0].length);
    const tbl = xml.lastIndexOf('<w:tbl>', m.index);
    const prStart = tbl + '<w:tbl>'.length;
    const prEnd = xml.indexOf('</w:tblPr>', prStart);
    if (tbl < 0 || !xml.startsWith('<w:tblPr>', prStart) || prEnd < 0) {
      documentXml = xml;
      continue;
    }
    let pr = xml.slice(prStart, prEnd);
    let grid = null;
    if (m[1] && m[2]) {
      const width = Math.round((+m[2] / 100) * textWidth);
      const pcts = m[1].split(',').map(Number);
      const sum = pcts.reduce((x, y) => x + y, 0) || 1;
      grid = `<w:tblGrid>${pcts.map((pc) => `<w:gridCol w:w="${Math.round((pc / sum) * width)}"/>`).join('')}</w:tblGrid>`;
      pr = pr.replace(/<w:tblW\b[^>]*\/>/, '').replace(/<w:tblLayout\b[^>]*\/>/, '');
      pr = pr.replace(/(<w:tblStyle\b[^>]*\/>)/, `$1<w:tblW w:w="${width}" w:type="dxa"/>`);
      pr = pr.replace(/(<w:tblLook\b|$)/, '<w:tblLayout w:type="fixed"/>$1');
    }
    if (m[3] || m[4]) {
      const size = +m[5] || (style?.body?.size || 1100) / 100;
      const y = m[4] ? String(Math.max(0, +m[4] - ((lineHeight - 0.7) * size) / 2)) : '';
      const side = (v, fallback) => `w:w="${v ? Math.round(+v * 20) : fallback}" w:type="dxa"`;
      const mar = `<w:tblCellMar><w:top ${side(y, 60)}/><w:left ${side(m[3], 100)}/><w:bottom ${side(y, 60)}/><w:right ${side(m[3], 100)}/></w:tblCellMar>`;
      pr = pr.replace(/<w:tblCellMar>[\s\S]*?<\/w:tblCellMar>/, '').replace(/(<w:tblLook\b|$)/, `${mar}$1`);
    }
    xml = xml.slice(0, prStart) + pr + xml.slice(prEnd);
    if (grid) {
      const g = xml.indexOf('<w:tblGrid>', prStart);
      const gEnd = xml.indexOf('</w:tblGrid>', g);
      if (g >= 0 && gEnd >= 0) xml = xml.slice(0, g) + grid + xml.slice(gEnd + '</w:tblGrid>'.length);
    }
    documentXml = xml;
  }
  // Space after top-level tables (Typst separates blocks; Word tables have none).
  const after = Math.round(((style?.body?.size || 1100) / 100) * 0.7 * 20);
  let depth = 0;
  // (Not before headings or captions, which bring their own spacing.)
  return documentXml.replace(/<w:tbl>|<\/w:tbl>(?=\s*(<w:p>(?:<w:pPr><w:pStyle w:val="([^"]*)")?)?)/g, (tag, nextPara, nextStyle) => {
    if (tag === '<w:tbl>') {
      depth++;
      return tag;
    }
    depth--;
    const spaced = depth === 0 && nextPara && !/Heading|Caption|Title|TOC/.test(nextStyle || '');
    return spaced ? `${tag}<w:p><w:pPr><w:spacing w:before="0" w:after="0" w:line="${after}" w:lineRule="exact"/></w:pPr></w:p>` : tag;
  });
}

/**
 * Side-by-side layouts (Typst grids, marked by the Lua filter with their
 * column widths and gutter) become borderless tables spanning the text width.
 * Each cell gets half the gutter on both sides; the table is widened and
 * shifted by half a gutter so the outer columns line up with the text.
 */
function applyLayoutTables(documentXml, style) {
  const textWidth = textWidthTwips(style);
  const marker = /<w:r><w:t>TLLAYOUT([\d.,]+)\|([\d.]+)<\/w:t><\/w:r>/g;
  for (const m of [...documentXml.matchAll(marker)].reverse()) {
    let xml = documentXml.slice(0, m.index) + documentXml.slice(m.index + m[0].length);
    const tbl = xml.lastIndexOf('<w:tbl>', m.index);
    if (tbl < 0) {
      documentXml = xml;
      continue;
    }
    const half = Math.round((+m[2] * 20) / 2);
    const pcts = m[1].split(',').map(Number);
    const sum = pcts.reduce((a, b) => a + b, 0) || 1;
    const content = textWidth - (pcts.length - 1) * 2 * half;
    const cols = pcts.map((p) => Math.round((p / sum) * content) + 2 * half);
    const total = cols.reduce((a, b) => a + b, 0);
    const none = ['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map((side) => `<w:${side} w:val="nil"/>`).join('');
    const tblPr =
      `<w:tblPr><w:tblStyle w:val="TLLayout"/><w:tblW w:w="${total}" w:type="dxa"/><w:tblInd w:w="${-half}" w:type="dxa"/>` +
      `<w:tblBorders>${none}</w:tblBorders><w:tblLayout w:type="fixed"/>` +
      `<w:tblCellMar><w:top w:w="0" w:type="dxa"/><w:left w:w="${half}" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/><w:right w:w="${half}" w:type="dxa"/></w:tblCellMar>` +
      '<w:tblLook w:val="0000" w:firstRow="0" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" w:noHBand="1" w:noVBand="1"/></w:tblPr>' +
      `<w:tblGrid>${cols.map((w) => `<w:gridCol w:w="${w}"/>`).join('')}</w:tblGrid>`;
    const prStart = xml.indexOf('<w:tblPr>', tbl);
    const gridEnd = xml.indexOf('</w:tblGrid>', tbl);
    if (prStart === tbl + '<w:tbl>'.length && gridEnd > prStart) {
      xml = xml.slice(0, prStart) + tblPr + xml.slice(gridEnd + '</w:tblGrid>'.length);
    }
    documentXml = xml;
  }
  return documentXml;
}

/**
 * Page breaks on exactly the headings that start a new page in Typst (the
 * probe lists them in document order), when the headings line up one to one.
 * A page break right before such a heading would leave an empty page.
 */
function headingBreaks(documentXml, style) {
  const breaks = style?.heading_breaks;
  if (!breaks) return documentXml;
  // The document's outline title (a heading in Typst) is Word's TOC heading.
  const heading = /<w:p><w:pPr><w:pStyle w:val="(?:Heading[1-6]|TOCHeading)" ?\/>/g;
  const count = (documentXml.match(heading) || []).length;
  if (count !== breaks.length) {
    // Fall back to breaking before every heading of the levels that usually do.
    const levels = style.heading_page_break || [];
    return documentXml.replace(/<w:p><w:pPr><w:pStyle w:val="Heading([1-6])" \/>/g, (m, level) => (levels[level - 1] ? m + '<w:pageBreakBefore/>' : m));
  }
  let i = 0;
  // (The TOC brings its own page breaks.) Headings left out of the outline
  // get the "not in contents" variant of their style.
  const outlined = style.heading_outlined;
  documentXml = documentXml.replace(heading, (m) => {
    const k = i++;
    if (m.includes('TOCHeading')) return m;
    const unlisted = outlined?.length === breaks.length && outlined[k] === false;
    const tag = unlisted ? m.replace(/w:val="Heading([1-6])"/, 'w:val="Heading$1Unlisted"') : m;
    return breaks[k] ? tag + '<w:pageBreakBefore/>' : tag;
  });
  return documentXml.replace(/<w:p><w:r><w:br w:type="page"\/><\/w:r><\/w:p>(\s*<w:p><w:pPr><w:pStyle w:val="Heading[1-6](?:Unlisted)?" \/><w:pageBreakBefore\/>)/g, '$1');
}

/**
 * A first page with its own margins (a title page) becomes its own section,
 * ending at the first page break, so the rest keeps the document's margins.
 */
function titleSection(documentXml, style) {
  const m = style?.first_page_margins;
  const end = documentXml.lastIndexOf('<w:sectPr');
  if (!m || end < 0) return documentXml;
  const br = '<w:p><w:r><w:br w:type="page"/></w:r></w:p>';
  const at = documentXml.indexOf(br);
  if (at < 0 || at > end) return documentXml;
  let finalPr = documentXml.slice(end, documentXml.indexOf('</w:sectPr>', end) + '</w:sectPr>'.length);
  const twip = (v) => Math.round(v * 20);
  const first = finalPr
    .replace(/<w:(header|footer)Reference\b[^>]*\/>/g, '')
    .replace(/<w:titlePg\/>/, '')
    .replace(/<w:pgMar\b([^>]*)\/>/, (_, attrs) =>
      `<w:pgMar${attrs.replace(/w:top="\d+"/, `w:top="${twip(m[0])}"`).replace(/w:right="\d+"/, `w:right="${twip(m[1])}"`).replace(/w:bottom="\d+"/, `w:bottom="${twip(m[2])}"`).replace(/w:left="\d+"/, `w:left="${twip(m[3])}"`)}/>`,
    );
  // The rest no longer starts with the title page, so its first page has headers.
  const rest = finalPr.replace(/<w:titlePg\/>/, '');
  documentXml = documentXml.slice(0, end) + rest + documentXml.slice(end + finalPr.length);
  return documentXml.slice(0, at) + `<w:p><w:pPr>${first}</w:pPr></w:p>` + documentXml.slice(at + br.length);
}

const PPR_ORDER = ['pStyle', 'keepNext', 'keepLines', 'pageBreakBefore', 'framePr', 'widowControl', 'numPr', 'suppressLineNumbers', 'pBdr', 'shd', 'tabs', 'suppressAutoHyphens', 'kinsoku', 'wordWrap', 'overflowPunct', 'topLinePunct', 'autoSpaceDE', 'autoSpaceDN', 'bidi', 'adjustRightInd', 'snapToGrid', 'spacing', 'ind', 'contextualSpacing', 'mirrorIndents', 'suppressOverlap', 'jc', 'textDirection', 'textAlignment', 'textboxTightWrap', 'outlineLvl', 'divId', 'cnfStyle', 'rPr', 'sectPr', 'pPrChange'];

/** Adds a property to a paragraph's pPr (given the paragraph's opening), in schema order. */
function putParaProp(para, tag, prop) {
  if (!para.startsWith('<w:p><w:pPr>')) return para.replace(/^<w:p>/, `<w:p><w:pPr>${prop}</w:pPr>`);
  const open = '<w:p><w:pPr>'.length;
  const end = para.indexOf('</w:pPr>');
  const inner = para.slice(open, end);
  if (new RegExp(`<w:${tag}[ />]`).test(inner)) return para;
  const later = PPR_ORDER.slice(PPR_ORDER.indexOf(tag) + 1);
  const next = new RegExp(`<w:(${later.join('|')})\\b`).exec(inner);
  const pos = next ? open + next.index : end;
  return para.slice(0, pos) + prop + para.slice(pos);
}

/** Paragraph alignment markers from styleRuns() become real paragraph alignment. */
function paragraphAlignment(documentXml) {
  return documentXml.replace(/<w:p>(?:(?!<\/w:p>)[\s\S])*?TL(RAGGED|JUSTIFY)(?:(?!<\/w:p>)[\s\S])*?<\/w:p>/g, (para, kind) => {
    para = para.replace(/(<w:t[^>]*>)TL(RAGGED|JUSTIFY)/, '$1').replace(/<w:r>(<w:rPr>(?:(?!<\/w:r>)[\s\S])*?<\/w:rPr>)?<w:t[^>]*><\/w:t><\/w:r>/, '');
    const centered = /<w:pStyle w:val="TL(Center|Right)"/.test(para);
    if (kind === 'RAGGED') {
      para = putParaProp(para, 'suppressAutoHyphens', '<w:suppressAutoHyphens/>');
      if (!centered) para = putParaProp(para, 'jc', '<w:jc w:val="left"/>');
    } else if (!centered) {
      para = putParaProp(para, 'jc', '<w:jc w:val="both"/>');
    }
    return para;
  });
}

/** Runs in a character style get its weight as direct formatting (bold is a toggle in styles). */
function runWeights(documentXml, charStyles) {
  const bold = new Map(charStyles.map((cs) => [cs.name.replace(/ /g, ''), cs.bold]));
  return documentXml.replace(/<w:rPr><w:rStyle w:val="(TLText\d+)" \/>((?:(?!<\/w:rPr>)[\s\S])*)<\/w:rPr>/g, (whole, id, rest) => {
    if (!bold.has(id) || /<w:b[ />]/.test(rest)) return whole;
    const b = bold.get(id) ? '<w:b/><w:bCs/>' : '<w:b w:val="0"/><w:bCs w:val="0"/>';
    return `<w:rPr><w:rStyle w:val="${id}" />${b}${rest}</w:rPr>`;
  });
}

/** Sets spacing attributes (before/after, in twips) on a paragraph. */
function setSpacing(para, values) {
  const attrs = Object.entries(values).map(([k, v]) => `w:${k}="${v}"`).join(' ');
  const has = /<w:spacing\b([^>]*)\/>/.exec(para.slice(0, para.indexOf('</w:pPr>') + 1 || 0));
  if (has) {
    let a = has[1];
    for (const [k, v] of Object.entries(values)) a = new RegExp(`w:${k}="`).test(a) ? a.replace(new RegExp(`w:${k}="[^"]*"`), `w:${k}="${v}"`) : `${a} w:${k}="${v}"`;
    return para.replace(has[0], `<w:spacing${a}/>`);
  }
  return putParaProp(para, 'spacing', `<w:spacing ${attrs}/>`);
}

/**
 * Typst drops the spacing above the first and below the last block in a
 * table cell; Word keeps it (a heading in a cell makes the row tall).
 */
function cellEdges(documentXml) {
  return documentXml.replace(/<w:tc>((?:(?!<w:tc>)[\s\S])*?)<\/w:tc>/g, (whole, inner) => {
    const paras = [...inner.matchAll(/<w:p>(?:(?!<\/w:p>)[\s\S])*?<\/w:p>/g)];
    if (!paras.length || inner.includes('<w:tbl>')) return whole;
    const first = paras[0];
    const last = paras[paras.length - 1];
    let out = inner;
    if (first === last) {
      out = out.slice(0, first.index) + setSpacing(first[0], { before: 0, after: 0 }) + out.slice(first.index + first[0].length);
    } else {
      out = out.slice(0, last.index) + setSpacing(last[0], { after: 0 }) + out.slice(last.index + last[0].length);
      out = out.slice(0, first.index) + setSpacing(first[0], { before: 0 }) + out.slice(first.index + first[0].length);
    }
    return `<w:tc>${out}</w:tc>`;
  });
}

/**
 * Word ignores page breaks inside tables: a heading in a table that should
 * start a page (e.g. a finding's header box) moves the break before the table.
 */
function tableBreaks(documentXml) {
  const tags = /<w:tbl>|<\/w:tbl>|<w:pageBreakBefore\/>/g;
  const stack = [];
  const moves = [];
  let m;
  while ((m = tags.exec(documentXml))) {
    if (m[0] === '<w:tbl>') stack.push(m.index);
    else if (m[0] === '</w:tbl>') stack.pop();
    else if (stack.length) moves.push([m.index, stack[0]]);
  }
  // Edits from the end backwards, so earlier positions stay valid.
  const breaker = '<w:p><w:pPr><w:pageBreakBefore/><w:spacing w:before="0" w:after="0" w:line="20" w:lineRule="exact"/></w:pPr></w:p>';
  const edits = [...moves.map(([at]) => [at, 'remove']), ...[...new Set(moves.map(([, tbl]) => tbl))].map((tbl) => [tbl, 'insert'])];
  for (const [at, kind] of edits.sort((a, b) => b[0] - a[0])) {
    documentXml = kind === 'remove' ? documentXml.slice(0, at) + documentXml.slice(at + '<w:pageBreakBefore/>'.length) : documentXml.slice(0, at) + breaker + documentXml.slice(at);
  }
  return documentXml;
}

/**
 * Cell markers that had to go in a paragraph of their own (the cell started
 * with a heading, list, ..) leave it empty once removed; drop it.
 */
function dropMarkerParagraphs(documentXml) {
  // (Also: the empty paragraph pandoc puts between back-to-back tables, so
  // Word keeps them apart, takes no room.)
  documentXml = documentXml.replace(/(<\/w:tbl>\s*)<w:p \/>(\s*<w:tbl>)/g, '$1<w:p><w:pPr><w:spacing w:before="0" w:after="0" w:line="20" w:lineRule="exact"/><w:rPr><w:sz w:val="2"/></w:rPr></w:pPr></w:p>$2');
  return documentXml.replace(/(<w:tc>(?:<w:tcPr>(?:(?!<\/w:tcPr>)[\s\S])*<\/w:tcPr>)?)<w:p><w:pPr><w:pStyle w:val="Compact" \/><\/w:pPr><\/w:p>(?=<w:p[ >]|<w:tbl>)/g, '$1');
}

/** Inline equation pictures sit as far below the baseline as the equation reaches. */
function pictureRuns(documentXml) {
  return documentXml.replace(/<w:r>(<w:drawing><wp:inline\b(?:(?!<\/w:r>)[\s\S])*?descr=")TLLOWER([\d.]+)("(?:(?!<\/w:r>)[\s\S])*?<\/w:r>)/g, (_, head, pt, tail) => {
    const halfPoints = Math.round(+pt * 2);
    return `<w:r><w:rPr><w:position w:val="${-halfPoints}"/></w:rPr>${head}Equation${tail}`;
  });
}

/**
 * pandoc points pictures in footnotes at the main document's relationships;
 * each part needs its own, so copy the missing ones over.
 */
function linkPartRelationships(parts, name) {
  const part = parts.find((p) => p[0] === name);
  const relsName = name.replace(/([^/]+)$/, '_rels/$1.rels');
  const rels = parts.find((p) => p[0] === relsName);
  const docRels = parts.find((p) => p[0] === 'word/_rels/document.xml.rels');
  if (!part || !rels || !docRels) return;
  let xml = rels[1].toString('utf8');
  const docXml = docRels[1].toString('utf8');
  const used = new Set([...part[1].toString('utf8').matchAll(/r:(?:embed|id|link)="([^"]+)"/g)].map((m) => m[1]));
  for (const id of used) {
    if (xml.includes(`Id="${id}"`)) continue;
    const rel = new RegExp(`<Relationship\\b[^>]*\\bId="${id}"[^>]*/>`).exec(docXml);
    if (rel) xml = xml.replace('</Relationships>', rel[0] + '</Relationships>');
  }
  rels[1] = Buffer.from(xml);
}

/** A coloured page becomes the document's background. */
function pageBackground(documentXml, style) {
  const fill = /^#([0-9a-fA-F]{6})/.exec(style?.page_fill || '')?.[1];
  if (!fill || documentXml.includes('<w:background')) return documentXml;
  return documentXml.replace(/<w:body>/, `<w:background w:color="${fill.toUpperCase()}"/><w:body>`);
}

/** Word's font obfuscation: XOR the first 32 bytes with a key taken from the GUID. */
function obfuscateFont(data, guid) {
  const pos = [35, 33, 31, 29, 27, 25, 22, 20, 17, 15, 12, 10, 7, 5, 3, 1];
  const key = pos.map((p) => parseInt(guid.substr(p, 2), 16));
  const out = Buffer.from(data);
  for (let i = 0; i < 32; i++) out[i] ^= key[i % 16];
  return out;
}

/**
 * Embeds the fonts the document uses (from the given font files) into the
 * .docx, so it looks right on machines that don't have them installed.
 * Only TrueType fonts whose licence allows embedding are included.
 */
function embedFonts(parts, fontFiles) {
  const get = (name) => parts.find((p) => p[0] === name);
  const text = (name) => get(name)?.[1].toString('utf8') ?? '';
  const set = (name, data) => {
    const part = get(name);
    if (part) part[1] = Buffer.from(data);
    else parts.push([name, Buffer.from(data)]);
  };
  const used = new Set([...(text('word/styles.xml') + text('word/document.xml')).matchAll(/w:ascii="([^"]+)"/g)].map((m) => m[1]));

  const faces = new Map(); // family -> [{file, weight, italic}]
  for (const file of fontFiles) {
    let info;
    try {
      info = fontFaceInfo(fs.readFileSync(file));
    } catch {
      continue;
    }
    if (!info?.family || !info.trueType || !info.embeddable || !used.has(info.family)) continue;
    if (!faces.has(info.family)) faces.set(info.family, []);
    faces.get(info.family).push({ file, ...info });
  }
  if (!faces.size) return;

  const pick = (list, italic, bold) =>
    list
      .filter((f) => f.italic === italic && (bold ? f.weight >= 600 : f.weight < 600))
      .sort((a, b) => Math.abs(a.weight - (bold ? 700 : 400)) - Math.abs(b.weight - (bold ? 700 : 400)))[0];
  let fontTable = text('word/fontTable.xml');
  let rels = text('word/_rels/fontTable.xml.rels') || '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>';
  if (!/xmlns:r=/.test(fontTable.slice(0, fontTable.indexOf('>', fontTable.indexOf('<w:fonts'))))) {
    fontTable = fontTable.replace('<w:fonts', '<w:fonts xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"');
  }
  let n = 0;
  for (const [family, list] of faces) {
    let embeds = '';
    for (const [tag, italic, bold] of [['embedRegular', false, false], ['embedBold', false, true], ['embedItalic', true, false], ['embedBoldItalic', true, true]]) {
      const face = pick(list, italic, bold);
      if (!face) continue;
      const guid = '{' + crypto.randomUUID().toUpperCase() + '}';
      const id = `rIdTLFont${++n}`;
      set(`word/fonts/font${n}.odttf`, obfuscateFont(fs.readFileSync(face.file), guid));
      rels = rels.replace('</Relationships>', `<Relationship Id="${id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/font" Target="fonts/font${n}.odttf"/></Relationships>`);
      embeds += `<w:${tag} r:id="${id}" w:fontKey="${guid}"/>`;
    }
    const entry = `<w:font w:name="${family.replace(/"/g, '&quot;')}">${embeds}</w:font>`;
    const existing = new RegExp(`<w:font w:name="${family.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"[\s\S]*?</w:font>`);
    fontTable = existing.test(fontTable) ? fontTable.replace(existing, entry) : fontTable.replace('</w:fonts>', entry + '</w:fonts>');
  }
  set('word/fontTable.xml', fontTable);
  set('word/_rels/fontTable.xml.rels', rels);
  const types = text('[Content_Types].xml');
  if (!types.includes('Extension="odttf"')) {
    set('[Content_Types].xml', types.replace('<Default ', '<Default Extension="odttf" ContentType="application/vnd.openxmlformats-officedocument.obfuscatedFont"/><Default '));
  }
  // Tell Word the fonts are embedded (in schema order: before these settings).
  let settings = text('word/settings.xml');
  if (!settings.includes('w:embedTrueTypeFonts')) {
    const later = ['w:embedSystemFonts', 'w:saveSubsetFonts', 'w:saveFormsData', 'w:mirrorMargins', 'w:alignBordersAndEdges', 'w:bordersDoNotSurroundHeader', 'w:bordersDoNotSurroundFooter', 'w:gutterAtTop', 'w:hideSpellingErrors', 'w:hideGrammaticalErrors', 'w:activeWritingStyle', 'w:proofState', 'w:formsDesign', 'w:attachedTemplate', 'w:linkStyles', 'w:stylePaneFormatFilter', 'w:stylePaneSortMethod', 'w:documentType', 'w:mailMerge', 'w:revisionView', 'w:trackRevisions', 'w:doNotTrackMoves', 'w:doNotTrackFormatting', 'w:documentProtection', 'w:autoFormatOverride', 'w:styleLockTheme', 'w:styleLockQFSet', 'w:defaultTabStop'];
    const at = later.map((tag) => settings.indexOf('<' + tag)).filter((i) => i >= 0).sort((a, b) => a - b)[0];
    const tag = '<w:embedTrueTypeFonts/>';
    settings = at === undefined ? settings.replace(/(<w:zoom[^>]*\/>)/, `$1${tag}`) : settings.slice(0, at) + tag + settings.slice(at);
    set('word/settings.xml', settings);
  }
}

/**
 * Converts exported HTML to a .docx buffer, styled after the paged document.
 * @param {string} html  the engine's HTML export
 * @param {object|null} style  the engine's style probe (fonts, margins, header/footer, ...)
 */
export async function htmlToDocx(html, style = null, fontFiles = []) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'typst-local-docx-'));
  const output = path.join(tmp, 'out.docx');
  const reference = path.join(tmp, 'reference.docx');
  try {
    const placements = style?.placements || [];
    const prepared = styleRuns(highlightCode(svgsToImages(sizeFigures(cleanFigures(sizeImages(markSpacing(pinPlacements(markTableOfContents(html, style?.toc), placements)), style?.image_sizes)), style?.figure_sizes))), style);
    fs.writeFileSync(reference, buildReferenceDocx(await pandocDefaultReference(), style, prepared.charStyles));
    const tocBefore = !!style?.toc_page_break;
    const env = {
      ...process.env,
      TYPST_LOCAL_TOC_BREAK_BEFORE: tocBefore ? '1' : '0',
      // A section after the contents starts its own page anyway when level-1 headings do.
      TYPST_LOCAL_TOC_BREAK_AFTER: tocBefore && !style?.heading_page_break?.[0] ? '1' : '0',
      TYPST_LOCAL_TOC_LEVELS: String(Math.min(9, Math.max(1, ...(style?.toc?.entries || []).map((e) => e.level), style?.toc ? 1 : 3))),
    };
    const args = [
      '--from=html',
      '--to=docx',
      `--reference-doc=${reference}`,
      `--lua-filter=${path.join(ROOT, 'scripts', 'typst-docx.lua')}`,
      '--output',
      output,
    ];
    await new Promise((resolve, reject) => {
      const proc = spawn(pandocPath(), args, { stdio: ['pipe', 'ignore', 'pipe'], env });
      const err = [];
      proc.stderr.on('data', (d) => err.push(d));
      proc.on('error', (e) =>
        reject(e.code === 'ENOENT' ? new DocxUnavailableError('pandoc is not installed on the server (re-run setup.sh)') : e),
      );
      proc.on('close', (code) => (code === 0 ? resolve() : reject(new Error('pandoc failed: ' + Buffer.concat(err).toString().slice(-500)))));
      proc.stdin.on('error', () => {});
      proc.stdin.end(prepared.html);
    });
    const parts = readZip(fs.readFileSync(output));
    for (const part of parts) {
      // Lists as in Typst: the marker at the margin (or the parent item's
      // text), the text about 1.5em further in.
      if (part[0] === 'word/numbering.xml') {
        const step = Math.round(((style?.body?.size || 1100) / 100) * 1.5 * 20);
        part[1] = Buffer.from(
          part[1].toString('utf8').replace(/<w:lvl w:ilvl="(\d+)"((?:(?!<\/w:lvl>)[\s\S])*?)<w:ind w:left="\d+" w:hanging="\d+" \/>/g, (_, lvl, mid) => `<w:lvl w:ilvl="${lvl}"${mid}<w:ind w:left="${(+lvl + 1) * step}" w:hanging="${step}" />`),
        );
      }
      // Footnotes carry the same paragraph alignment markers.
      if (part[0] === 'word/footnotes.xml') part[1] = Buffer.from(pictureRuns(paragraphAlignment(part[1].toString('utf8')).replace(/(<pic:cNvPr\b[^>]*?)\sdescr="data:[^"]*"/g, '$1')));
      if (part[0] !== 'word/document.xml') continue;
      // pandoc copies each picture's source (a whole data URI) into its description.
      const xml = pictureRuns(part[1].toString('utf8').replace(/(<pic:cNvPr\b[^>]*?)\sdescr="data:[^"]*"/g, '$1'));
      part[1] = Buffer.from(tocEntries(pageBackground(titleSection(tableBreaks(headingBreaks(codeBlockEdges(cellEdges(runWeights(paragraphAlignment(spacers(pinPictures(dropMarkerParagraphs(applyTableProps(applyLayoutTables(applyCellProps(xml), style), style)), placements))), prepared.charStyles)), style), style)), style), style)));
    }
    linkPartRelationships(parts, 'word/footnotes.xml');
    embedFonts(parts, fontFiles);
    return createZip(parts);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
