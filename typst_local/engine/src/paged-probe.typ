// Wrapper for measuring a document's paged layout (see probe.rs). The engine
// compiles this instead of the main file; {MAIN} is replaced with its path.
//
// Every placed element's content is wrapped in a plain block (no spacing,
// inset or fill, so the layout doesn't change) holding invisible start/end
// markers. That shows exactly where it landed on the page, so Word exports can
// pin the ones positioned on the page itself at the same spot.

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

// Report each page's content area (its exact margins) for the Word page setup.
#set page(foreground: context [#metadata((tl-page-area: tl-body-area()))])

#let tl-factor(a, axis) = {
  if a == none { return none }
  if axis == "x" { if a in (left, start) { 0.0 } else if a == center { 0.5 } else { 1.0 } }
  else { if a == top { 0.0 } else if a == horizon { 0.5 } else { 1.0 } }
}

#let tl-offset(v, base) = if type(v) == length { v.to-absolute().pt() } else if type(v) == ratio { float(v) * base } else { float(v.ratio) * base + v.length.to-absolute().pt() }

#show place: it => {
  if it.float or (it.has("label") and it.label == <tl-placed>) { return it }
  counter("tl-place").step()
  context {
    let key = str(counter("tl-place").get().first()) + "|" + repr(it.alignment) + "|" + repr(it.dx) + "|" + repr(it.dy)
    let area = tl-body-area()
    let info = (tl-place: "start", key: key)
    let a = it.alignment
    let ay = if a.y == none { none } else { tl-factor(a.y, "y") }
    if area != none and ay != none {
      info.insert("area", area)
      info.insert("ax", tl-factor(if a.x == none { start } else { a.x }, "x"))
      info.insert("ay", ay)
      info.insert("dx", tl-offset(it.dx, area.w))
      info.insert("dy", tl-offset(it.dy, area.h))
    }
    [#place(it.alignment, dx: it.dx, dy: it.dy, scope: it.scope, block(inset: 0pt, outset: 0pt, fill: none, stroke: none, radius: 0pt, clip: false, spacing: 0pt, {
      metadata(info)
      it.body
      metadata((tl-place: "end", key: key))
    }))<tl-placed>]
  }
}

// Explicit page breaks are marked, so headings after them start a new page in Word.
#show pagebreak: it => {
  metadata((tl-pagebreak: true))
  it
}

// Identifies an image the same way in the PDF and HTML compiles: its source
// and size settings (paged-probe.typ / html-export.typ).
#let tl-image-key(it) = (if type(it.source) == str { it.source } else { "bytes:" + str(it.source.len()) }) + "|" + repr(it.width) + "|" + repr(it.height)

// Every image is marked, so the Word export can give it its size on the page.
#show image: it => {
  metadata((tl-image: tl-image-key(it)))
  it
}

// Image figures get markers too, so the Word export can size each picture
// exactly as it came out on the page.
#show figure.where(kind: image): it => {
  metadata((tl-figure: "start"))
  it
  metadata((tl-figure: "end"))
}

#include "/{MAIN}"
