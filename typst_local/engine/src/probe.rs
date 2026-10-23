//! Measures what a compiled document actually looks like (fonts, sizes,
//! colours, margins, running headers/footers), so other formats (Word) can be
//! styled to match any template without knowing anything about it.

use std::collections::HashMap;

use serde::Serialize;
use base64::Engine as _;
use typst::foundations::{Dict, NativeElement, Smart, StyleChain, Value};
use typst::introspection::{MetadataElem, Tag};
use typst::layout::{Abs, Frame, FrameItem, GroupItem, PagedDocument, Point, Size, Transform};
use typst::model::{HeadingElem, Numbering, OutlineElem, OutlineEntry};
use typst::text::FontStyle;
use typst::visualize::Paint;

#[derive(Serialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct TextStyle {
    pub font: String,
    /// Size in hundredths of a point (so the struct can be hashed).
    pub size: u32,
    pub color: String,
    pub bold: bool,
    pub italic: bool,
}

#[derive(Serialize, Clone)]
pub struct Band {
    /// Text with `{page}` / `{pages}` where page numbers appear.
    pub text: String,
    pub align: &'static str,
    pub style: TextStyle,
}

#[derive(Serialize, Default)]
pub struct Probe {
    pub page_width: f64,
    pub page_height: f64,
    /// top, right, bottom, left in pt
    pub margins: [f64; 4],
    pub body: Option<TextStyle>,
    pub code: Option<TextStyle>,
    /// Index 0 is heading level 1.
    pub headings: Vec<Option<TextStyle>>,
    pub heading_page_break: Vec<bool>,
    /// For every heading in document order: whether it starts a new page.
    pub heading_breaks: Vec<bool>,
    /// For every heading in document order: whether it's listed in the outline.
    pub heading_outlined: Vec<bool>,
    pub toc: Option<Toc>,
    pub link_color: Option<String>,
    /// Baseline distance divided by font size.
    pub line_height: Option<f64>,
    pub justify: bool,
    pub header: Vec<Band>,
    pub footer: Vec<Band>,
    pub toc_page_break: bool,
    /// No running header/footer on the first page (e.g. a title page).
    pub first_page_plain: bool,
    /// The first page's margins (top, right, bottom, left), if they differ (e.g. a title page).
    pub first_page_margins: Option<[f64; 4]>,
    /// The page background colour, if not white.
    pub page_fill: Option<String>,
    /// Placed elements (`place(..)`): where their content landed, drawn as a picture.
    pub placements: Vec<Placement>,
    /// Each image figure's picture size on the page (w, h in pt), in order.
    pub figure_sizes: Vec<[f64; 2]>,
    /// Every image's size on the page: (key, w, h in pt), in order.
    pub image_sizes: Vec<(String, f64, f64)>,
}

/// How the document's table of contents (its outline) looks, so the Word
/// table of contents can be styled the same.
#[derive(Serialize)]
pub struct Toc {
    pub title_center: bool,
    pub title_style: Option<TextStyle>,
    /// Per level (1 first): text style, indent from the margin (pt) and the
    /// extra space above entries of that level (pt).
    pub levels: Vec<Option<TocLevel>>,
    /// Baseline-to-baseline distance between entries (pt).
    pub pitch: Option<f64>,
    /// Each entry in order: its level and the page number it shows.
    pub entries: Vec<TocEntry>,
}

#[derive(Serialize, Clone)]
pub struct TocLevel {
    pub style: TextStyle,
    pub indent: f64,
    pub above: f64,
}

#[derive(Serialize)]
pub struct TocEntry {
    pub level: usize,
    pub page: String,
}

#[derive(Serialize)]
pub struct Placement {
    /// Matches the `data-tl-place` key in the HTML export: the placement's
    /// alignment and offsets, plus `#n` for the nth placement with those.
    pub key: String,
    pub page: usize,
    /// Top-left corner and size in pt, measured from the page's top-left.
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    /// Transparent PNG of just the placed content (base64).
    pub png: String,
}

/// Grows `bb` (min x, min y, max x, max y) by a rectangle transformed by `ts`.
fn grow(bb: &mut [f64; 4], ts: Transform, w: Abs, h: Abs, top: Abs) {
    for (x, y) in [(Abs::zero(), top), (w, top), (Abs::zero(), top + h), (w, top + h)] {
        let p = Point::new(x, y).transform(ts);
        bb[0] = bb[0].min(p.x.to_pt());
        bb[1] = bb[1].min(p.y.to_pt());
        bb[2] = bb[2].max(p.x.to_pt());
        bb[3] = bb[3].max(p.y.to_pt());
    }
}

/// A placed element found on a page: its marker key, whether it sits exactly
/// where the page's content area (plus its alignment and offsets) puts it,
/// its bounding box and a copy of just its content.
struct Found {
    key: String,
    page: usize,
    on_page: bool,
    bb: [f64; 4],
    frame: Frame,
}

fn num(dict: &Dict, key: &str) -> Option<f64> {
    match dict.get(key).ok()? {
        Value::Float(v) => Some(*v),
        Value::Int(v) => Some(*v as f64),
        _ => None,
    }
}

/// Whether a placed element (its wrapper block at `origin` with `size`) is
/// positioned relative to the page's content area rather than to something
/// in the text flow: then it lands exactly where that area says.
fn placed_on_page(info: &Dict, origin: Point, size: Size) -> bool {
    let Ok(Value::Dict(area)) = info.get("area") else { return false };
    let (Some(ax), Some(ay), Some(dx), Some(dy)) = (num(info, "ax"), num(info, "ay"), num(info, "dx"), num(info, "dy")) else { return false };
    let (Some(x), Some(y), Some(w), Some(h)) = (num(area, "x"), num(area, "y"), num(area, "w"), num(area, "h")) else { return false };
    let ex = x + ax * (w - size.x.to_pt()) + dx;
    let ey = y + ay * (h - size.y.to_pt()) + dy;
    (origin.x.to_pt() - ex).abs() < 1.0 && (origin.y.to_pt() - ey).abs() < 1.0
}

/// Finds the content between each placed element's start/end markers.
/// `groups` holds the page position and size of the frames enclosing `frame`.
fn find_placed(frame: &Frame, ts: Transform, page: usize, groups: &mut Vec<(Point, Size)>, open: &mut Vec<Found>, found: &mut Vec<Found>) {
    for (pos, item) in frame.items() {
        let item_ts = ts.pre_concat(Transform::translate(pos.x, pos.y));
        let extent = match item {
            FrameItem::Group(group) => {
                let group_ts = item_ts.pre_concat(group.transform);
                groups.push((Point::zero().transform(group_ts), group.frame.size()));
                find_placed(&group.frame, group_ts, page, groups, open, found);
                groups.pop();
                continue;
            }
            FrameItem::Tag(Tag::Start(content, _)) => {
                let Some(meta) = content.to_packed::<MetadataElem>() else { continue };
                let Value::Dict(info) = &meta.value else { continue };
                let (Ok(Value::Str(kind)), Ok(Value::Str(key))) = (info.get("tl-place"), info.get("key")) else { continue };
                if kind.as_str() == "start" {
                    // The markers sit in the wrapper block, the innermost frame here.
                    let (origin, size) = groups.last().copied().unwrap_or((Point::zero(), frame.size()));
                    let on_page = placed_on_page(info, origin, size);
                    let bb = [f64::MAX, f64::MAX, f64::MIN, f64::MIN];
                    open.push(Found { key: key.to_string(), page, on_page, bb, frame: Frame::soft(Size::zero()) });
                } else if let Some(i) = open.iter().rposition(|f| f.key == key.as_str()) {
                    let done = open.remove(i);
                    if done.bb[2] > done.bb[0] && done.bb[3] > done.bb[1] {
                        found.push(done);
                    }
                }
                continue;
            }
            FrameItem::Text(text) => {
                let width: Abs = text.glyphs.iter().map(|g| g.x_advance.at(text.size)).sum();
                (width, text.size * 1.15, -(text.size * 0.9))
            }
            FrameItem::Image(_, size, _) => (size.x, size.y, Abs::zero()),
            FrameItem::Shape(shape, _) => {
                let size = shape.geometry.bbox_size();
                (size.x, size.y, Abs::zero())
            }
            _ => continue,
        };
        // Everything drawn belongs to every placement it's nested in.
        for f in open.iter_mut() {
            grow(&mut f.bb, item_ts, extent.0, extent.1, extent.2);
            let mut leaf = Frame::soft(Size::zero());
            leaf.push(Point::zero(), item.clone());
            let mut group = GroupItem::new(leaf);
            group.transform = item_ts;
            f.frame.push(Point::zero(), FrameItem::Group(group));
        }
    }
}

/// The size (w, h in pt) of the picture in each image figure, in document
/// order (figures are marked by paged-probe.typ).
fn figure_sizes(doc: &PagedDocument) -> Vec<[f64; 2]> {
    fn walk(frame: &Frame, ts: Transform, open: &mut Option<()>, best: &mut [f64; 2], out: &mut Vec<[f64; 2]>) {
        for (pos, item) in frame.items() {
            let item_ts = ts.pre_concat(Transform::translate(pos.x, pos.y));
            match item {
                FrameItem::Group(group) => walk(&group.frame, item_ts.pre_concat(group.transform), open, best, out),
                FrameItem::Tag(Tag::Start(content, _)) => {
                    let Some(meta) = content.to_packed::<MetadataElem>() else { continue };
                    let Value::Dict(info) = &meta.value else { continue };
                    match info.get("tl-figure") {
                        Ok(Value::Str(k)) if k.as_str() == "start" => {
                            *open = Some(());
                            *best = [0.0, 0.0];
                        }
                        Ok(Value::Str(k)) if k.as_str() == "end" && open.is_some() => {
                            out.push(*best);
                            *open = None;
                        }
                        _ => {}
                    }
                }
                // The picture is drawn last, on top of any decoration (e.g. a
                // drop shadow, itself drawn as a larger image underneath).
                FrameItem::Image(_, size, _) => {
                    if open.is_some() {
                        *best = [size.x.to_pt() * item_ts.sx.get().abs(), size.y.to_pt() * item_ts.sy.get().abs()];
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    let (mut open, mut best) = (None, [0.0, 0.0]);
    for page in &doc.pages {
        walk(&page.frame, Transform::identity(), &mut open, &mut best, &mut out);
    }
    out
}

/// Every image's size on the page (key from paged-probe.typ, w, h in pt), in
/// document order: the first picture drawn after each image's marker.
fn image_sizes(doc: &PagedDocument) -> Vec<(String, f64, f64)> {
    fn walk(frame: &Frame, ts: Transform, pending: &mut Option<String>, out: &mut Vec<(String, f64, f64)>) {
        for (pos, item) in frame.items() {
            let item_ts = ts.pre_concat(Transform::translate(pos.x, pos.y));
            match item {
                FrameItem::Group(group) => walk(&group.frame, item_ts.pre_concat(group.transform), pending, out),
                FrameItem::Tag(Tag::Start(content, _)) => {
                    let Some(meta) = content.to_packed::<MetadataElem>() else { continue };
                    let Value::Dict(info) = &meta.value else { continue };
                    if let Ok(Value::Str(key)) = info.get("tl-image") {
                        *pending = Some(key.to_string());
                    }
                }
                FrameItem::Image(_, size, _) => {
                    if let Some(key) = pending.take() {
                        out.push((key, size.x.to_pt() * item_ts.sx.get().abs(), size.y.to_pt() * item_ts.sy.get().abs()));
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    let mut pending = None;
    for page in &doc.pages {
        walk(&page.frame, Transform::identity(), &mut pending, &mut out);
    }
    out
}

/// Finds the placed elements that are positioned on the page itself (not
/// inside a paragraph, box or block that moves with the text) and draws each
/// one as a transparent PNG. Small decorations placed inside the flow (icons,
/// shadows, labels) are left to the normal export.
fn placements(doc: &PagedDocument) -> Vec<Placement> {
    const SCALE: f32 = 3.0; // 216 dpi
    let mut found = Vec::new();
    for (i, page) in doc.pages.iter().enumerate() {
        let mut open = Vec::new();
        find_placed(&page.frame, Transform::identity(), i, &mut Vec::new(), &mut open, &mut found);
    }
    // Keys arrive as "n|alignment|dx|dy" with n in document order; the HTML
    // export can't count reliably, so number each alignment/offset combo.
    found.sort_by_key(|f| f.key.split('|').next().and_then(|n| n.parse::<usize>().ok()).unwrap_or(0));
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::new();
    for f in found {
        let sig = f.key.splitn(2, '|').nth(1).unwrap_or("").to_string();
        let nth = seen.entry(sig.clone()).or_insert(0);
        *nth += 1;
        let key = format!("{sig}#{nth}");
        if !f.on_page {
            continue;
        }
        let page = &doc.pages[f.page];
        let mut alone = page.clone();
        alone.frame = { let mut fr = Frame::hard(page.frame.size()); fr.push_frame(Point::zero(), f.frame); fr };
        alone.fill = Smart::Custom(None);
        let pixmap = typst_render::render(&alone, SCALE);
        let bb = f.bb;
        let (x0, y0) = ((bb[0] * SCALE as f64).floor().max(0.0), (bb[1] * SCALE as f64).floor().max(0.0));
        let (x1, y1) = ((bb[2] * SCALE as f64).ceil().min(pixmap.width() as f64), (bb[3] * SCALE as f64).ceil().min(pixmap.height() as f64));
        if x1 <= x0 || y1 <= y0 {
            continue;
        }
        let Some(rect) = tiny_skia::IntRect::from_xywh(x0 as i32, y0 as i32, (x1 - x0) as u32, (y1 - y0) as u32) else { continue };
        let Some(png) = pixmap.clone_rect(rect).and_then(|p| p.encode_png().ok()) else { continue };
        out.push(Placement {
            key,
            page: f.page,
            x: x0 / SCALE as f64,
            y: y0 / SCALE as f64,
            w: (x1 - x0) / SCALE as f64,
            h: (y1 - y0) / SCALE as f64,
            png: base64::engine::general_purpose::STANDARD.encode(png),
        });
    }
    out
}

/// The page number a page shows (its numbering pattern applied, else plain).
fn page_label(doc: &PagedDocument, page: usize) -> String {
    let Some(p) = doc.pages.get(page) else { return String::new() };
    match &p.numbering {
        Some(Numbering::Pattern(pattern)) => {
            let label = pattern.apply(&[p.number]);
            // Patterns like "Page 1 of 2" only make sense in footers; keep the number.
            if label.chars().filter(|c| c.is_alphabetic()).count() > 4 { p.number.to_string() } else { label.to_string() }
        }
        _ => p.number.to_string(),
    }
}

/// Measures the table of contents: where each entry's text sits and how it looks.
fn table_of_contents(doc: &PagedDocument, runs: &[Run], left: f64, width: f64) -> Option<Toc> {
    let outline = doc.introspector.query(&OutlineElem::ELEM.select()).iter().filter_map(|c| c.location()).next()?;
    let mut title_center = false;
    let mut title_style = None;
    {
        let pos = doc.introspector.position(outline);
        let page = pos.page.get() - 1;
        let py = pos.point.y.to_pt();
        let near: Vec<&Run> = runs.iter().filter(|r| r.page == page && r.y >= py - 1.0 && r.y <= py + 60.0 && !r.mono).collect();
        if let Some(min_y) = near.iter().map(|r| r.y).reduce(f64::min) {
            let line: Vec<&&Run> = near.iter().filter(|r| (r.y - min_y).abs() < 2.0).collect();
            let (x0, x1) = line.iter().fold((f64::MAX, f64::MIN), |(a, b), r| (a.min(r.x), b.max(r.x + r.width)));
            title_center = ((x0 + x1) / 2.0 - (left + width / 2.0)).abs() < 6.0 && x0 > left + 12.0;
            title_style = line.iter().max_by_key(|r| r.style.size).map(|r| r.style.clone());
        }
    }
    let mut entries = Vec::new();
    let mut found: Vec<(usize, usize, f64, f64, TextStyle)> = Vec::new(); // level, page, y, x, style
    for content in doc.introspector.query(&OutlineEntry::ELEM.select()).iter() {
        let (Some(entry), Some(loc)) = (content.to_packed::<OutlineEntry>(), content.location()) else { continue };
        let level = entry.level.get();
        let target = entry.element.location().map(|l| doc.introspector.page(l).get() - 1);
        entries.push(TocEntry { level, page: target.map(|p| page_label(doc, p)).unwrap_or_default() });
        let pos = doc.introspector.position(loc);
        let page = pos.page.get() - 1;
        let (px, py) = (pos.point.x.to_pt(), pos.point.y.to_pt());
        let near: Vec<&Run> = runs.iter().filter(|r| r.page == page && r.y >= py - 1.0 && r.y <= py + 30.0 && r.x >= px - 2.0).collect();
        if let Some(min_y) = near.iter().map(|r| r.y).reduce(f64::min) {
            if let Some(first) = near.iter().filter(|r| (r.y - min_y).abs() < 2.0).min_by(|a, b| a.x.partial_cmp(&b.x).unwrap()) {
                found.push((level, page, first.y, first.x, first.style.clone()));
            }
        }
    }
    if entries.is_empty() {
        return None;
    }
    // Spacing: the usual distance between entries, and any extra above a level.
    let mut gaps: Vec<(usize, f64)> = Vec::new();
    for w in found.windows(2) {
        if w[0].1 == w[1].1 && w[1].2 > w[0].2 {
            gaps.push((w[1].0, w[1].2 - w[0].2));
        }
    }
    let pitch = percentile(gaps.iter().map(|g| g.1).collect(), 0.1);
    let max_level = found.iter().map(|f| f.0).max().unwrap_or(0);
    let levels = (1..=max_level)
        .map(|level| {
            let of: Vec<&(usize, usize, f64, f64, TextStyle)> = found.iter().filter(|f| f.0 == level).collect();
            let style = most_common(of.iter().map(|f| (&f.4, 1)))?;
            let indent = median(of.iter().map(|f| f.3 - left).collect()).unwrap_or(0.0).max(0.0);
            let above = match (median(gaps.iter().filter(|g| g.0 == level).map(|g| g.1).collect()), pitch) {
                (Some(g), Some(p)) => (g - p).max(0.0),
                _ => 0.0,
            };
            Some(TocLevel { style, indent, above })
        })
        .collect();
    Some(Toc { title_center, title_style, levels, pitch, entries })
}

struct Run {
    page: usize,
    x: f64,
    y: f64,
    width: f64,
    glyphs: usize,
    mono: bool,
    style: TextStyle,
    text: String,
}

fn is_light(hex: &str) -> bool {
    let h = hex.trim_start_matches('#');
    if h.len() < 6 {
        return false;
    }
    let c = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).unwrap_or(0) as f64 / 255.0;
    0.2126 * c(0) + 0.7152 * c(2) + 0.0722 * c(4) > 0.85
}

fn collect(frame: &Frame, ts: Transform, page: usize, runs: &mut Vec<Run>, links: &mut Vec<(usize, f64, f64, f64, f64)>) {
    for (pos, item) in frame.items() {
        let item_ts = ts.pre_concat(Transform::translate(pos.x, pos.y));
        match item {
            FrameItem::Group(group) => collect(&group.frame, item_ts.pre_concat(group.transform), page, runs, links),
            FrameItem::Text(text) => {
                let origin = Point::zero().transform(item_ts);
                let info = text.font.info();
                let color = match &text.fill {
                    Paint::Solid(c) => c.to_hex().to_string(),
                    _ => "#000000".to_string(),
                };
                let width: Abs = text.glyphs.iter().map(|g| g.x_advance.at(text.size)).sum();
                runs.push(Run {
                    page,
                    x: origin.x.to_pt(),
                    y: origin.y.to_pt(),
                    width: width.to_pt(),
                    glyphs: text.glyphs.len(),
                    mono: info.flags.contains(typst::text::FontFlags::MONOSPACE),
                    style: TextStyle {
                        font: info.family.clone(),
                        size: (text.size.to_pt() * 100.0).round() as u32,
                        color,
                        bold: info.variant.weight.to_number() >= 600,
                        italic: info.variant.style != FontStyle::Normal,
                    },
                    text: text.text.to_string(),
                });
            }
            FrameItem::Link(_, size) => {
                let a = Point::zero().transform(item_ts);
                links.push((page, a.x.to_pt(), a.y.to_pt(), size.x.to_pt(), size.y.to_pt()));
            }
            _ => {}
        }
    }
}

fn most_common<'a>(items: impl Iterator<Item = (&'a TextStyle, usize)>) -> Option<TextStyle> {
    let mut counts: HashMap<&TextStyle, usize> = HashMap::new();
    for (s, n) in items {
        *counts.entry(s).or_default() += n;
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(s, _)| s.clone())
}

/// The value at fraction `q` (0..1) of the sorted values.
fn percentile(mut v: Vec<f64>, q: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Some(v[((v.len() - 1) as f64 * q).round() as usize])
}

fn median(mut v: Vec<f64>) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Some(v[v.len() / 2])
}

/// Splits one page's band runs into text segments (left/center/right).
fn band_segments(runs: &[&Run], page_w: f64) -> Vec<(String, f64, f64, TextStyle)> {
    let mut lines: Vec<Vec<&Run>> = Vec::new();
    let mut sorted: Vec<&Run> = runs.to_vec();
    sorted.sort_by(|a, b| a.y.partial_cmp(&b.y).unwrap().then(a.x.partial_cmp(&b.x).unwrap()));
    for r in sorted {
        match lines.last_mut() {
            Some(line) if (line[0].y - r.y).abs() < 2.0 => line.push(r),
            _ => lines.push(vec![r]),
        }
    }
    let mut out = Vec::new();
    for mut line in lines {
        line.sort_by(|a, b| a.x.partial_cmp(&b.x).unwrap());
        let mut seg: Option<(String, f64, f64, TextStyle)> = None;
        for r in line {
            let size = r.style.size as f64 / 100.0;
            match &mut seg {
                Some((text, _, end, _)) if r.x - *end < 24.0_f64.max(size * 2.0) => {
                    if r.x - *end > size * 0.15 {
                        text.push(' ');
                    }
                    text.push_str(&r.text);
                    *end = r.x + r.width;
                }
                _ => {
                    if let Some(s) = seg.take() {
                        out.push(s);
                    }
                    seg = Some((r.text.clone(), r.x, r.x + r.width, r.style.clone()));
                }
            }
        }
        if let Some(s) = seg {
            out.push(s);
        }
    }
    let _ = page_w;
    out
}

pub fn probe(doc: &PagedDocument) -> Probe {
    let mut runs = Vec::new();
    let mut links = Vec::new();
    for (i, page) in doc.pages.iter().enumerate() {
        collect(&page.frame, Transform::identity(), i, &mut runs, &mut links);
    }
    let pages = doc.pages.len();
    // The page colour most pages have (Typst pages are white unless filled).
    let mut fills: HashMap<String, usize> = HashMap::new();
    for page in &doc.pages {
        if let Smart::Custom(Some(Paint::Solid(c))) = &page.fill {
            *fills.entry(c.to_hex().to_string()).or_default() += 1;
        }
    }
    let page_fill = fills.into_iter().filter(|(_, n)| *n * 2 > pages).max_by_key(|(_, n)| *n).map(|(c, _)| c).filter(|c| !c.to_lowercase().starts_with("#ffffff"));
    // On a dark page, light text is the normal text.
    let dark_page = page_fill.as_deref().is_some_and(|c| !is_light(c));
    let is_light = |c: &str| !dark_page && is_light(c);
    let Some(first) = doc.pages.first() else { return Probe::default() };
    let (pw, ph) = (first.frame.width().to_pt(), first.frame.height().to_pt());

    // Running headers/footers: text in the top/bottom 12% repeated on many pages.
    let in_top = |r: &Run| r.y < ph * 0.12;
    let in_bottom = |r: &Run| r.y > ph * 0.88;
    let mut bands: [HashMap<(String, &'static str), (usize, TextStyle)>; 2] = [HashMap::new(), HashMap::new()];
    for page in 0..pages {
        for (b, pick) in [(0usize, &in_top as &dyn Fn(&Run) -> bool), (1, &in_bottom)] {
            let band: Vec<&Run> = runs.iter().filter(|r| r.page == page && pick(r)).collect();
            for (text, start, end, style) in band_segments(&band, pw) {
                let normalized = text
                    .split(' ')
                    .map(|w| {
                        let digits: String = w.chars().filter(|c| c.is_ascii_digit()).collect();
                        if !digits.is_empty() && digits.len() == w.trim_matches(|c: char| !c.is_ascii_digit()).len() {
                            if digits == (page + 1).to_string() {
                                return w.replacen(&digits, "{page}", 1);
                            }
                            if digits == pages.to_string() {
                                return w.replacen(&digits, "{pages}", 1);
                            }
                        }
                        w.to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                let center = (start + end) / 2.0;
                let align = if (center - pw / 2.0).abs() < pw * 0.08 {
                    "center"
                } else if center > pw / 2.0 {
                    "right"
                } else {
                    "left"
                };
                let entry = bands[b].entry((normalized, align)).or_insert((0, style));
                entry.0 += 1;
            }
        }
    }
    let repeated = |map: &HashMap<(String, &'static str), (usize, TextStyle)>| {
        let mut v: Vec<Band> = map
            .iter()
            .filter(|(_, (n, _))| *n >= 2 && (*n as f64) >= pages as f64 * 0.4)
            .map(|((text, align), (_, style))| Band { text: text.clone(), align, style: style.clone() })
            .collect();
        v.sort_by_key(|b| match b.align {
            "left" => 0,
            "center" => 1,
            _ => 2,
        });
        v
    };
    let header = repeated(&bands[0]);
    let footer = repeated(&bands[1]);
    let band_text: Vec<&str> = header.iter().chain(footer.iter()).map(|b| b.text.as_str()).collect();
    let first_page_plain = !band_text.is_empty() && !runs.iter().any(|r| r.page == 0 && (in_top(r) || in_bottom(r)));
    let is_band_run = |r: &Run| (in_top(r) || in_bottom(r)) && !band_text.is_empty();

    // Body and code text.
    let body = most_common(
        runs.iter()
            .filter(|r| !r.mono && !is_light(&r.style.color) && !is_band_run(r))
            .map(|r| (&r.style, r.glyphs)),
    );
    let code = most_common(runs.iter().filter(|r| r.mono).map(|r| (&r.style, r.glyphs)));

    // Margins from where body text sits on each page.
    let (mut lefts, mut rights, mut tops, mut bottoms) = (vec![], vec![], vec![], vec![]);
    for page in 0..pages {
        let on: Vec<&Run> = runs.iter().filter(|r| r.page == page && !is_band_run(r)).collect();
        if on.len() < 5 {
            continue;
        }
        lefts.push(on.iter().map(|r| r.x).fold(f64::MAX, f64::min));
        rights.push(pw - on.iter().map(|r| r.x + r.width).fold(0.0, f64::max));
        tops.push(on.iter().map(|r| r.y - r.style.size as f64 / 100.0).fold(f64::MAX, f64::min));
        bottoms.push(ph - on.iter().map(|r| r.y).fold(0.0, f64::max));
    }
    let clamp = |v: Option<f64>, d: f64| v.unwrap_or(d).clamp(18.0, 144.0);
    // Full pages show the real bottom margin; short final pages would inflate it.
    let mut margins = [clamp(median(tops), 72.0), clamp(median(rights), 72.0), clamp(percentile(bottoms, 0.15), 72.0), clamp(median(lefts), 72.0)];
    // Better: the margins each page actually has (reported by paged-probe.typ),
    // the most common ones for the document, and the first page's if different.
    let mut first_page_margins = None;
    let mut by_page: Vec<Option<[f64; 4]>> = vec![None; pages];
    for content in doc.introspector.query(&MetadataElem::ELEM.select()).iter() {
        let (Some(meta), Some(loc)) = (content.to_packed::<MetadataElem>(), content.location()) else { continue };
        let Value::Dict(info) = &meta.value else { continue };
        let Ok(Value::Dict(area)) = info.get("tl-page-area") else { continue };
        let page = doc.introspector.page(loc).get() - 1;
        if let (Some(x), Some(y), Some(w), Some(h), Some(slot)) = (num(area, "x"), num(area, "y"), num(area, "w"), num(area, "h"), by_page.get_mut(page)) {
            *slot = Some([y, pw - x - w, ph - y - h, x]);
        }
    }
    let key = |m: &[f64; 4]| m.map(|v| (v * 10.0).round() as i64);
    let mut counts: HashMap<[i64; 4], (usize, [f64; 4])> = HashMap::new();
    for m in by_page.iter().skip(if pages > 1 { 1 } else { 0 }).flatten() {
        counts.entry(key(m)).or_insert((0, *m)).0 += 1;
    }
    if let Some((_, (_, common))) = counts.into_iter().max_by_key(|(_, (n, _))| *n) {
        margins = common.map(|v| v.clamp(0.0, 288.0));
        if let Some(Some(first)) = by_page.first() {
            if key(first) != key(&common) {
                first_page_margins = Some(first.map(|v| v.clamp(0.0, 288.0)));
            }
        }
    }

    // Line height and justification from body text lines.
    let mut gaps = Vec::new();
    let (mut lines_total, mut lines_full) = (0usize, 0usize);
    if let Some(body) = &body {
        let size = body.size as f64 / 100.0;
        for page in 0..pages {
            // Each line: (baseline y, start x, end x).
            let mut ys: Vec<(f64, f64, f64)> = runs
                .iter()
                .filter(|r| r.page == page && &r.style == body)
                .map(|r| (r.y, r.x, r.x + r.width))
                .collect();
            ys.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            let mut lines: Vec<(f64, f64, f64)> = Vec::new();
            for (y, start, end) in ys {
                match lines.last_mut() {
                    Some(l) if (l.0 - y).abs() < 1.0 => {
                        l.1 = l.1.min(start);
                        l.2 = l.2.max(end);
                    }
                    _ => lines.push((y, start, end)),
                }
            }
            // A line followed closely by one starting at the same place is
            // inside a paragraph: justified text fills those to the same edge.
            let mut inner_ends = Vec::new();
            for w in lines.windows(2) {
                let gap = w[1].0 - w[0].0;
                if gap > size * 1.0 && gap < size * 2.2 {
                    gaps.push(gap / size);
                }
                if gap < size * 1.9 && (w[1].1 - w[0].1).abs() < 1.0 {
                    inner_ends.push(w[0].2);
                }
            }
            // Typst lets hyphens and punctuation hang slightly past the edge.
            // Clearly short lines (list items) say nothing about justification.
            // The edge is where most such lines end.
            let mut bins: HashMap<i64, usize> = HashMap::new();
            for e in &inner_ends {
                *bins.entry(e.round() as i64).or_default() += 1;
            }
            let Some(edge) = bins.into_iter().max_by_key(|(e, n)| (*n, *e)).map(|(e, _)| e as f64) else { continue };
            let left = lines.iter().map(|l| l.1).fold(f64::MAX, f64::min);
            let long: Vec<f64> = inner_ends.into_iter().filter(|e| *e > left + (edge - left) * 0.7).collect();
            lines_total += long.len();
            lines_full += long.iter().filter(|e| (**e - edge) > -1.5 && (**e - edge) < 3.0).count();
        }
    }
    let line_height = median(gaps);
    let justify = lines_total >= 5 && lines_full as f64 > lines_total as f64 * 0.6;

    // Heading styles: the text found at each heading's position.
    let styles = StyleChain::default();
    let mut per_level: Vec<Vec<TextStyle>> = vec![Vec::new(); 6];
    let mut at_top: Vec<(usize, usize)> = vec![(0, 0); 6];
    for content in doc.introspector.query(&HeadingElem::ELEM.select()).iter() {
        let (Some(heading), Some(loc)) = (content.to_packed::<HeadingElem>(), content.location()) else { continue };
        let level = heading.resolve_level(styles).get().min(6) - 1;
        let pos = doc.introspector.position(loc);
        let page = pos.page.get() - 1;
        let (px, py) = (pos.point.x.to_pt(), pos.point.y.to_pt());
        let near: Vec<&Run> = runs
            .iter()
            .filter(|r| r.page == page && r.y >= py - 1.0 && r.y <= py + 60.0 && r.x >= px - 2.0 && !r.mono)
            .collect();
        if let Some(min_y) = near.iter().map(|r| r.y).reduce(f64::min) {
            if let Some(r) = near.iter().filter(|r| (r.y - min_y).abs() < 2.0).max_by_key(|r| r.style.size) {
                if !is_light(&r.style.color) {
                    per_level[level].push(r.style.clone());
                }
            }
        }
        if page > 0 {
            at_top[level].1 += 1;
            if py <= margins[0] + 24.0 {
                at_top[level].0 += 1;
            }
        }
    }
    // Which headings (in document order) start a new page on purpose: at the
    // top of a page after an explicit page break (marked by paged-probe.typ),
    // or after a page left well short of full.
    let mut broken = vec![false; pages];
    for content in doc.introspector.query(&MetadataElem::ELEM.select()).iter() {
        let (Some(meta), Some(loc)) = (content.to_packed::<MetadataElem>(), content.location()) else { continue };
        if let Value::Dict(info) = &meta.value {
            if info.get("tl-pagebreak").is_ok() {
                if let Some(b) = broken.get_mut(doc.introspector.page(loc).get() - 1) {
                    *b = true;
                }
            }
        }
    }
    let mut lowest = vec![0.0f64; pages];
    for r in runs.iter().filter(|r| !is_band_run(r)) {
        lowest[r.page] = lowest[r.page].max(r.y);
    }
    let body_height = ph - margins[0] - margins[2];
    let heading_breaks: Vec<bool> = doc
        .introspector
        .query(&HeadingElem::ELEM.select())
        .iter()
        .filter_map(|c| c.location())
        .map(|loc| {
            let pos = doc.introspector.position(loc);
            let page = pos.page.get() - 1;
            page > 0 && pos.point.y.to_pt() <= margins[0] + 24.0 && (broken[page - 1] || (ph - margins[2]) - lowest[page - 1] > body_height * 0.2)
        })
        .collect();
    let heading_outlined: Vec<bool> = doc
        .introspector
        .query(&HeadingElem::ELEM.select())
        .iter()
        .map(|c| c.to_packed::<HeadingElem>().is_some_and(|h| h.outlined.get(styles)))
        .collect();
    let toc = table_of_contents(doc, &runs, margins[3], pw - margins[1] - margins[3]);
    let headings: Vec<Option<TextStyle>> = per_level.iter().map(|v| most_common(v.iter().map(|s| (s, 1)))).collect();
    let heading_page_break = at_top.iter().map(|(top, total)| *total >= 2 && *top as f64 >= *total as f64 * 0.6).collect();

    // Link colour: text inside link areas.
    let mut link_styles = Vec::new();
    for (page, x, y, w, h) in &links {
        for r in runs.iter().filter(|r| r.page == *page) {
            if r.x >= x - 1.0 && r.x <= x + w && r.y >= *y && r.y <= y + h + 2.0 && !is_light(&r.style.color) {
                link_styles.push(r.style.clone());
            }
        }
    }
    // Prefer a colour that sets links apart from body text, if links use one often.
    let mut by_color: HashMap<&str, usize> = HashMap::new();
    for s in &link_styles {
        *by_color.entry(s.color.as_str()).or_default() += 1;
    }
    let body_color = body.as_ref().map(|b| b.color.as_str()).unwrap_or("#000000");
    let distinct = by_color.iter().filter(|(c, _)| **c != body_color).max_by_key(|(_, n)| **n);
    let link_color = match distinct {
        Some((c, n)) if *n as f64 >= link_styles.len() as f64 * 0.15 => Some(c.to_string()),
        _ => by_color.into_iter().max_by_key(|(_, n)| *n).map(|(c, _)| c.to_string()),
    };

    // Does the table of contents start on its own page?
    let toc_page_break = doc
        .introspector
        .query(&OutlineElem::ELEM.select())
        .iter()
        .filter_map(|c| c.location())
        .next()
        .map(|loc| {
            let pos = doc.introspector.position(loc);
            pos.page.get() > 1 && pos.point.y.to_pt() <= margins[0] + 24.0
        })
        .unwrap_or(false);

    Probe {
        page_width: pw,
        page_height: ph,
        margins,
        body,
        code,
        headings,
        heading_page_break,
        heading_breaks,
        heading_outlined,
        toc,
        link_color,
        line_height,
        justify,
        header,
        footer,
        toc_page_break,
        first_page_plain,
        first_page_margins,
        page_fill,
        placements: placements(doc),
        figure_sizes: figure_sizes(doc),
        image_sizes: image_sizes(doc),
    }
}
