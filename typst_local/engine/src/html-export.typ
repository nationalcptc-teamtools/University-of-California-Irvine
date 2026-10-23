// Wrapper for exporting a document to HTML on the way to Word (.docx).
// The engine compiles this instead of the main file; {MAIN} is replaced with
// the main file's path. Everything here is generic: it makes Typst's HTML
// export keep things it would otherwise drop.

// Equations and image figures become inline SVG pictures (HTML export can't
// show math, and templates often decorate images with layout effects).
//
// Every rule here passes content through untouched when it isn't producing
// HTML: inside those pictures (html.frame) Typst lays content out for print.
// Inline equations are drawn with their full extent (not just cap height to
// baseline) and say how far they reach below the baseline, so Word can line
// them up with the text.
#show math.equation: it => context {
  if target() != "html" { return it }
  if it.block { return html.frame(it) }
  let full = { set text(top-edge: "bounds", bottom-edge: "bounds"); box(it) }
  let above = { set text(top-edge: "bounds", bottom-edge: "baseline"); box(it) }
  let below = measure(full).height - measure(above).height
  html.elem("span", attrs: ("data-tl-lower": str(calc.round(below.pt(), digits: 2))), html.frame(full))
}
#show figure.where(kind: image): it => context {
  if target() != "html" { it } else { html.elem("figure", { html.frame(it.body); it.caption }) }
}

// The page's content area in pt (x, y, width, height), from its size and margins.
#let tl-body-area() = {
  let (w, h) = (page.width, page.height)
  if w == auto or h == auto { return none }
  if page.flipped { (w, h) = (h, w) }
  let default = 2.5 / 21 * calc.min(w, h)
  let resolve(v, base) = {
    if v == auto or v == none { default }
    else if type(v) == length { v.to-absolute() }
    else if type(v) == ratio { v * base }
    else if type(v) == relative { v.ratio * base + v.length.to-absolute() }
    else { default }
  }
  let m = page.margin
  let side(k) = if type(m) == dictionary { m.at(k, default: auto) } else { m }
  let (left, right) = (side("left"), side("right"))
  if type(m) == dictionary and ("inside" in m or "outside" in m) {
    // Binding on the left (left-to-right text): odd pages have it on the left.
    let odd = calc.odd(here().page())
    let (inside, outside) = (m.at("inside", default: auto), m.at("outside", default: auto))
    (left, right) = if odd { (inside, outside) } else { (outside, inside) }
  }
  let (l, r) = (resolve(left, w), resolve(right, w))
  let (t, b) = (resolve(side("top"), h), resolve(side("bottom"), h))
  (x: l.pt(), y: t.pt(), w: (w - l - r).pt(), h: (h - t - b).pt())
}

// Identifies an image the same way in the PDF and HTML compiles: its source
// and size settings (paged-probe.typ / html-export.typ).
#let tl-image-key(it) = (if type(it.source) == str { it.source } else { "bytes:" + str(it.source.len()) }) + "|" + repr(it.width) + "|" + repr(it.height)

// Images say which one they are, so docx.js can give them their size in the
// PDF (HTML export keeps relative sizes like `width: 70%` as CSS).
#show image: it => context {
  if target() != "html" { return it }
  html.elem("span", attrs: ("data-tl-img": tl-image-key(it)))
  it
}

// Drawings (cetz/lilaq charts, diagrams: a fixed-size block of placed shapes)
// become pictures, since HTML export can't draw shapes.
// Whether content contains any of these elements (looking a few levels deep).
#let tl-has(c, funcs, depth: 0) = {
  if type(c) == array { return c.any(x => tl-has(x, funcs, depth: depth)) }
  if type(c) != content or depth > 8 { return false }
  if c.func() in funcs { return true }
  c.fields().values().any(v => type(v) in (content, array) and tl-has(v, funcs, depth: depth + 1))
}
#let tl-draws(c) = tl-has(c, (place, curve, path, line, polygon, rect, square, circle, ellipse))
#let tl-abs(v) = type(v) == length or (type(v) == relative and v.ratio == 0%)
#let tl-fixed(it) = tl-abs(it.width) and tl-abs(it.height)
#show block: it => context {
  if target() == "html" and tl-fixed(it) and tl-draws(it.body) { html.frame(it) } else { it }
}
// The plain text in some content.
#let tl-plain(c) = {
  if type(c) == str { return c }
  if type(c) != content { return "" }
  if c.func() == text { return c.text }
  c.fields().values().map(v => if type(v) == array { v.map(tl-plain).join() } else { tl-plain(v) }).join()
}
// A box that's a drawing, or that holds placed content over blank space (e.g.
// an icon drawn on top of some spaces), becomes a picture of exactly that.
#show box: it => context {
  if target() == "html" and ((tl-fixed(it) and tl-draws(it.body)) or (tl-has(it.body, (place,)) and tl-plain(it.body).trim() == "")) { html.elem("span", html.frame(it)) } else { it }
}

// HTML export drops layout-only elements along with their contents. A grid
// of short cells (e.g. a legend: "12 | Critical") becomes one line per row; a
// side-by-side layout (text next to a chart) becomes a borderless table with
// the same column widths (see docx.js); anything else (e.g. a grid holding a
// heading) keeps its contents in reading order.
#let tl-styled = text(red)[x].func()
#let tl-inline(c) = {
  if type(c) in (str, int, float) { return true }
  if type(c) != content { return false }
  let f = c.func()
  if f == [].func() { return c.children.all(tl-inline) }
  if f == tl-styled { return tl-inline(c.child) }
  if f in (strong, emph, underline, highlight, link, smallcaps, sub, super) { return tl-inline(c.body) }
  f in (text, [ ].func(), smartquote, h, box) or (f == raw and not c.block)
}
// Column widths in pt (without gutters), sized the way Typst does: fixed
// columns first, then fractions share what's left. Auto columns (sized by
// their content) count as 1fr here.
#let tl-column-pts(columns, n, gap) = {
  let specs = if type(columns) == array { columns } else { (auto,) * n }
  let area = tl-body-area()
  let total = if area == none { 450.0 } else { area.w }
  let fixed = specs.map(c => if type(c) == length { c.to-absolute().pt() } else if type(c) == ratio { float(c) * total } else if type(c) == relative { float(c.ratio) * total + c.length.to-absolute().pt() } else { none })
  let frs = specs.map(c => if type(c) == fraction { c / 1fr } else if c == auto { 1.0 } else { 0.0 })
  let rest = calc.max(0.0, total - (n - 1) * gap - fixed.filter(x => x != none).sum(default: 0.0))
  let fr-sum = frs.sum()
  specs.enumerate().map(((i, c)) => if fixed.at(i) != none { fixed.at(i) } else if fr-sum > 0 { rest * frs.at(i) / fr-sum } else { 0.0 })
}
// The same as percentages of their total.
#let tl-widths(columns, n, gap) = {
  let pts = tl-column-pts(columns, n, gap)
  let sum = calc.max(1.0, pts.sum())
  pts.map(x => str(calc.round(x / sum * 100, digits: 2)))
}
#let tl-gap(g) = {
  let g = if type(g) == array { g.at(0, default: 0pt) } else { g }
  if type(g) == length { g.to-absolute().pt() } else if type(g) == relative { g.length.to-absolute().pt() } else { 0 }
}
#show grid: it => context {
  if target() != "html" { return it }
  let cols = if type(it.columns) == int { it.columns } else if type(it.columns) == array { calc.max(1, it.columns.len()) } else { 1 }
  let items = it.children.filter(c => c.func() not in (grid.hline, grid.vline, grid.header, grid.footer))
  let cells = items.map(c => if c.func() == grid.cell { c.body } else { c })
  if cols == 1 { return cells.join(parbreak()) }
  if cells.all(tl-inline) { return html.elem("div", attrs: ("custom-style": "Compact"), cells.chunks(cols).map(row => row.join([#sym.space.quad])).join(parbreak())) }
  let spans = items.any(c => c.func() == grid.cell and (c.at("colspan", default: 1) > 1 or c.at("rowspan", default: 1) > 1))
  if spans or tl-has(cells, (heading,)) { return cells.join(parbreak()) }
  let gap = tl-gap(it.column-gutter)
  let widths = tl-widths(it.columns, cols, gap)
  let rows = cells.chunks(cols).map(row => html.elem("tr", row.map(c => html.elem("td", c)).join()))
  html.elem("table", attrs: ("data-tl-layout": widths.join(",") + "|" + str(calc.round(gap, digits: 2))), rows.join())
}
#show stack: it => context {
  if target() != "html" { it } else { it.children.filter(c => type(c) == content).join(parbreak()) }
}
// Placed elements get empty marker spans around their content, carrying
// their alignment and offsets (as in paged-probe.typ), so the Word export can
// pin the ones positioned on the page itself at their exact spot. Spans keep
// paragraphs intact. Inside pictures (html.frame) placement works as usual.
#show place: it => context {
  if it.float or target() != "html" { return it }
  let sig = repr(it.alignment) + "|" + repr(it.dx) + "|" + repr(it.dy)
  html.elem("span", attrs: ("data-tl-place": sig))
  it.body
  html.elem("span", attrs: ("data-tl-place-end": "1"))
}
// Vertical spacing (dropped by HTML export) is kept as a marker the Word
// export turns into an empty paragraph of exactly that height.
#show v: it => context {
  if target() != "html" { return it }
  let a = it.amount
  let area = tl-body-area()
  let base = if area == none { 0 } else { area.h }
  let pt = if type(a) == length { a.to-absolute().pt() } else if type(a) == ratio { float(a) * base } else if type(a) == relative { float(a.ratio) * base + a.length.to-absolute().pt() } else { 0 }
  if pt > 0.5 { html.elem("div", attrs: ("data-tl-v": str(calc.round(pt, digits: 2)))) }
}

// A horizontal line across the text (a separator) becomes a horizontal rule.
#show line: it => context {
  if target() != "html" or it.angle != 0deg or it.end != none { return it }
  let l = it.length
  let wide = if type(l) == ratio { l >= 50% } else if type(l) == relative { l.ratio >= 50% } else { false }
  if not wide { return it }
  let st = stroke(it.stroke)
  let thickness = if st.thickness == auto { 1.0 } else { st.thickness.to-absolute().pt() }
  let paint = if type(st.paint) == color { st.paint.to-hex() } else { "#000000" }
  html.elem("hr", attrs: ("data-tl-rule": str(calc.round(thickness, digits: 2)) + "|" + paint))
}

// Layout wrappers HTML export drops along with their content: keep the
// content, or for visual transforms, a picture of the result.
#show pad: it => context { if target() != "html" { it } else { it.body } }
#show move: it => context { if target() != "html" { it } else { it.body } }
#show rotate: it => context { if target() != "html" { it } else { html.elem("span", html.frame(it)) } }
#show scale: it => context { if target() != "html" { it } else { html.elem("span", html.frame(it)) } }
#show skew: it => context { if target() != "html" { it } else { html.elem("span", html.frame(it)) } }

// Numbered lists keep their kind of numbering (a., A., i., I.), as a marker
// docx.js turns into the list type.
#show enum: it => context {
  let n = it.numbering
  let kind = if type(n) == str { n.clusters().find(c => c in ("1", "a", "A", "i", "I")) } else { none }
  if target() != "html" or kind == none or kind == "1" { it } else { html.elem("div", attrs: ("data-tl-enum": kind), it) }
}

#show columns: it => context { if target() != "html" { it } else { it.body } }

// Horizontal alignment becomes a Word paragraph style (see docx-template.js).
#show align: it => context {
  let x = it.alignment.x
  // Keep the alignment as a style too, so tables inside can inherit it.
  let body = { set align(it.alignment); it.body }
  if target() != "html" { it }
  else if x == center { html.elem("div", attrs: ("custom-style": "TL Center"), body) }
  else if x == right or x == end { html.elem("div", attrs: ("custom-style": "TL Right"), body) }
  else { html.elem("div", body) }
}

// Control characters (e.g. pasted terminal output) are invalid in HTML.
#show regex("[\u{0}-\u{8}\u{b}\u{c}\u{e}-\u{1f}\u{7f}]"): none

// Carry each run's look (size|colour|weight|font|justified) for the Word styles.
#show text: it => context {
  if target() != "html" { return it }
  let font = text.font
  let font = if type(font) == array { font.at(0, default: "") } else { font }
  let font = if type(font) == dictionary { font.at("name", default: "") } else { font }
  let fill = if type(text.fill) == color { text.fill.to-hex() } else { "" }
  html.elem("span", attrs: ("data-tl": str(text.size.pt()) + "|" + fill + "|" + str(text.weight) + "|" + str(font) + "|" + (if par.justify { "j" } else { "r" })), it)
}

// Per-cell settings (`align: (x, y) => ..` etc.) resolved for one cell.
#let tl-at(v, x, y) = if type(v) == function { v(x, y) } else if type(v) == array { if v.len() > 0 { v.at(calc.rem(x, v.len())) } else { auto } } else { v }
// A length setting (inset) in pt along one axis, if it's a plain length.
#let tl-pt(v, keys) = {
  let v = if type(v) == dictionary { keys.map(k => v.at(k, default: none)).find(x => x != none) } else { v }
  if type(v) == length { v.to-absolute().pt() } else if type(v) == relative and v.ratio == 0% { v.length.to-absolute().pt() } else { none }
}

// Tables are rebuilt so every cell carries what HTML export drops: its
// resolved background colour (including `fill: (x, y) => ..`) and alignment.
// The table carries its column widths and cell padding (see docx.js).
#show table: it => context {
  if target() != "html" { return it }
  let outer = align.alignment
  let cols = if type(it.columns) == int { it.columns } else if type(it.columns) == array { calc.max(1, it.columns.len()) } else { 1 }
  let items = ()
  for child in it.children {
    let f = child.func()
    if f == table.header or f == table.footer {
      for c in child.children {
        if c.func() not in (table.hline, table.vline) { items.push((c, f == table.header)) }
      }
    } else if f not in (table.hline, table.vline) {
      items.push((child, false))
    }
  }
  let taken = (:)
  let rows = ()
  let x = 0
  let y = 0
  for (c, head) in items {
    while taken.at(str(x) + "," + str(y), default: false) {
      x += 1
      if x >= cols { x = 0; y += 1 }
    }
    let is-cell = c.func() == table.cell
    let colspan = if is-cell { c.at("colspan", default: 1) } else { 1 }
    let rowspan = if is-cell { c.at("rowspan", default: 1) } else { 1 }
    let own = if is-cell { c.at("fill", default: auto) } else { auto }
    let fill = tl-at(if own != auto { own } else { it.fill }, x, y)
    let own-align = if is-cell { c.at("align", default: auto) } else { auto }
    let a = if own-align != auto { own-align } else { tl-at(it.align, x, y) }
    let (ax, ay) = if type(a) == alignment { (a.x, a.y) } else { (none, none) }
    if ax == none and type(outer) == alignment { ax = outer.x }
    for dy in range(rowspan) {
      for dx in range(colspan) { taken.insert(str(x + dx) + "," + str(y + dy), true) }
    }
    while rows.len() <= y { rows.push(()) }
    let attrs = (:)
    if colspan > 1 { attrs.insert("colspan", str(colspan)) }
    if rowspan > 1 { attrs.insert("rowspan", str(rowspan)) }
    if type(fill) == color { attrs.insert("data-tl-fill", fill.to-hex()) }
    if ax == center { attrs.insert("align", "center") } else if ax in (right, end) { attrs.insert("align", "right") }
    if ay == horizon { attrs.insert("data-tl-valign", "center") } else if ay == bottom { attrs.insert("data-tl-valign", "bottom") }
    rows.at(y).push(html.elem(if head { "th" } else { "td" }, attrs: attrs, if is-cell { c.body } else { c }))
    x += colspan
    if x >= cols { x = 0; y += 1 }
  }
  let inset = tl-at(it.inset, 0, 0)
  let ix = tl-pt(inset, ("left", "x", "rest"))
  let iy = tl-pt(inset, ("top", "y", "rest"))
  // Column widths as Typst sizes them: fixed ones as given, auto ones as wide
  // as their widest cell, fractions share what's left of the text width.
  let specs = if type(it.columns) == array { it.columns } else if type(it.columns) == int { (auto,) * cols } else { () }
  let widths = ""
  let width = ""
  let area = tl-body-area()
  if specs.len() > 0 and area != none {
    let pad = 2 * (if ix == none { 5.0 } else { ix })
    let natural = range(cols).map(_ => 0.0)
    // Natural width of each auto column: its widest single-column cell.
    let (x, y) = (0, 0)
    let taken = (:)
    for (c, _) in items {
      while taken.at(str(x) + "," + str(y), default: false) {
        x += 1
        if x >= cols { x = 0; y += 1 }
      }
      let is-cell = c.func() == table.cell
      let colspan = if is-cell { c.at("colspan", default: 1) } else { 1 }
      let rowspan = if is-cell { c.at("rowspan", default: 1) } else { 1 }
      for dy in range(rowspan) { for dx in range(colspan) { taken.insert(str(x + dx) + "," + str(y + dy), true) } }
      if colspan == 1 and specs.at(x, default: none) == auto {
        // (A little slack: Word's line breaking is less tight than Typst's.)
        let w = measure(if is-cell { c.body } else { c }).width.pt() + pad + 3
        natural.at(x) = calc.max(natural.at(x), w)
      }
      x += colspan
      if x >= cols { x = 0; y += 1 }
    }
    let base = tl-column-pts(specs.map(c => if c == auto { 0pt } else { c }), cols, 0.0)
    let fixed = specs.enumerate().map(((i, c)) => if c == auto { natural.at(i) } else if type(c) == fraction { 0.0 } else { base.at(i) })
    let used = fixed.sum()
    let fr-sum = specs.map(c => if type(c) == fraction { c / 1fr } else { 0.0 }).sum()
    let pts = if fr-sum > 0 {
      let rest = calc.max(0.0, area.w - used)
      specs.enumerate().map(((i, c)) => if type(c) == fraction { rest * (c / 1fr) / fr-sum } else { fixed.at(i) })
    } else if used > area.w {
      fixed.map(w => w * area.w / used)
    } else { fixed }
    let sum = calc.max(1.0, pts.sum())
    widths = pts.map(w => str(calc.round(w / sum * 100, digits: 2))).join(",")
    width = str(calc.round(calc.min(100, sum / area.w * 100), digits: 2))
  }
  let table-attr = widths + "|" + width + "|" + (if ix == none { "" } else { str(calc.round(ix, digits: 2)) }) + "|" + (if iy == none { "" } else { str(calc.round(iy, digits: 2)) }) + "|" + str(calc.round(text.size.pt(), digits: 2))
  html.elem("table", attrs: ("data-tl-table": table-attr), rows.map(r => html.elem("tr", r.join())).join())
}

#include "/{MAIN}"
