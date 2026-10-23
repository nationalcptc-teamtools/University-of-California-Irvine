//! Incremental Typst compile service for Typst Local.
//!
//! Speaks newline-delimited JSON over stdin/stdout. Each project keeps its own
//! `World` between requests, so Typst's memoization makes recompiles cheap, and
//! remembers which pages it already rendered: a compile only turns pages whose
//! content hash changed into SVG.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use chrono::{Datelike, Local};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use typst::diag::{FileError, FileResult, Severity, SourceDiagnostic};
use typst::foundations::{Bytes, Datetime};
use typst::layout::PagedDocument;
use typst::syntax::{FileId, Source, Span, VirtualPath};
use typst::text::{Font, FontBook};
use typst::utils::LazyHash;
use typst::{Library, LibraryExt, World, WorldExt};
use typst_kit::download::{Downloader, ProgressSink};
use typst_kit::fonts::{FontSearcher, FontSlot};
use typst_kit::package::PackageStorage;

mod probe;

// ---- protocol ---------------------------------------------------------------

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Request {
    Compile(CompileRequest),
    /// Where in the source did a click on the preview come from?
    Jump { id: u64, project: String, page: usize, x: f64, y: f64 },
    /// Where in the preview is the text at this cursor? (`offset` in UTF-16 units)
    Cursor { id: u64, project: String, path: String, offset: usize },
    Drop { project: String },
}

#[derive(Serialize, Default)]
struct JumpResponse {
    id: u64,
    /// "file", "url", "position" or "none"
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    position: Option<Position>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<f64>,
    /// Font size at that point, in pt.
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<f64>,
}

#[derive(Deserialize)]
struct CompileRequest {
    id: u64,
    project: String,
    main: String,
    #[serde(default)]
    set: Vec<(String, Content)>,
    #[serde(default)]
    remove: Vec<String>,
    /// Full list of project font files; only sent when it changed.
    fonts: Option<Vec<String>>,
    /// Write a PDF to this path instead of rendering pages.
    pdf: Option<String>,
    /// Render every page, even ones the caller should already have.
    #[serde(default)]
    full: bool,
    /// Export as HTML (for conversion to other formats) instead of pages.
    #[serde(default)]
    html: bool,
    /// Only report which project files the document reads (no pages).
    #[serde(default)]
    deps: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Content {
    Text(String),
    Disk { disk: String },
}

#[derive(Serialize)]
struct Response {
    id: u64,
    status: &'static str,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pages: Option<Vec<PageOut>>,
    #[serde(rename = "numPages", skip_serializing_if = "Option::is_none")]
    num_pages: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<String>,
    /// How the paged document looks (for styling exports like Word).
    #[serde(skip_serializing_if = "Option::is_none")]
    style: Option<probe::Probe>,
    /// Every heading in the document, in order.
    #[serde(skip_serializing_if = "Option::is_none")]
    outline: Option<Vec<Heading>>,
    /// Project files the compile read (for `deps` requests).
    #[serde(skip_serializing_if = "Option::is_none")]
    deps: Option<Vec<String>>,
    pdf: bool,
    ms: u64,
}

#[derive(Serialize)]
struct Heading {
    level: usize,
    title: String,
    /// Rendered number like "2.1", if the heading is numbered.
    #[serde(skip_serializing_if = "Option::is_none")]
    number: Option<String>,
    /// Whether it would appear in an #outline().
    outlined: bool,
    page: usize,
    x: f64,
    y: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    position: Option<Position>,
}

#[derive(Serialize)]
struct PageOut {
    tid: String,
    w: f64,
    h: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    svg: Option<String>,
}

#[derive(Serialize)]
struct Diagnostic {
    message: String,
    severity: &'static str,
    path: Option<String>,
    package: Option<String>,
    range: Option<Range>,
    hints: Vec<String>,
}

#[derive(Serialize)]
struct Range {
    start: Position,
    end: Position,
}

#[derive(Serialize)]
struct Position {
    line: usize,
    character: usize,
}

// ---- shared resources -------------------------------------------------------

/// System, embedded and server-library fonts: scanned once, shared by all projects.
struct SharedFonts {
    book: FontBook,
    slots: Vec<FontSlot>,
}

fn shared_fonts() -> &'static SharedFonts {
    static FONTS: OnceLock<SharedFonts> = OnceLock::new();
    FONTS.get_or_init(|| {
        let dirs: Vec<PathBuf> = std::env::var_os("TYPST_FONT_LIBRARY").map(PathBuf::from).into_iter().collect();
        let fonts = FontSearcher::new().include_system_fonts(true).search_with(dirs);
        SharedFonts { book: fonts.book, slots: fonts.fonts }
    })
}

fn packages() -> &'static PackageStorage {
    static STORAGE: OnceLock<PackageStorage> = OnceLock::new();
    STORAGE.get_or_init(|| PackageStorage::new(None, None, Downloader::new("typst-local/1.0")))
}

// ---- world ------------------------------------------------------------------

enum Slot {
    Text { source: Source, bytes: Bytes },
    Binary { bytes: Bytes, disk: String },
}

struct Project {
    library: LazyHash<Library>,
    book: LazyHash<FontBook>,
    fonts: Vec<Font>,
    font_files: Vec<String>,
    main: FileId,
    files: HashMap<FileId, Slot>,
    package_sources: Mutex<HashMap<FileId, FileResult<Source>>>,
    package_files: Mutex<HashMap<FileId, FileResult<Bytes>>>,
    /// Generated sources for wildcard paths like `chapters/*` (see `glob_source`).
    glob_sources: Mutex<HashMap<FileId, Source>>,
    /// Pages the caller already has, by content hash.
    rendered: HashSet<u128>,
    /// The last successfully compiled document, for click-to-source.
    document: Option<PagedDocument>,
    /// Project files read since the last compile started. Typst re-checks the
    /// files a cached result depends on, so this is complete even for
    /// recompiles that reuse almost everything.
    accessed: Mutex<HashSet<FileId>>,
    today: Datetime,
}

fn project_id(path: &str) -> FileId {
    FileId::new(None, VirtualPath::new(path))
}

fn not_found(id: FileId) -> FileError {
    FileError::NotFound(id.vpath().as_rootless_path().to_path_buf())
}

impl Project {
    fn new() -> Self {
        let mut project = Self {
            // HTML export (used for .docx downloads) is an opt-in Typst feature.
            library: LazyHash::new(Library::builder().with_features([typst::Feature::Html].into_iter().collect()).build()),
            book: LazyHash::new(shared_fonts().book.clone()),
            fonts: Vec::new(),
            font_files: Vec::new(),
            main: project_id("main.typ"),
            files: HashMap::new(),
            package_sources: Mutex::new(HashMap::new()),
            package_files: Mutex::new(HashMap::new()),
            glob_sources: Mutex::new(HashMap::new()),
            rendered: HashSet::new(),
            document: None,
            accessed: Mutex::new(HashSet::new()),
            today: Datetime::from_ymd(1970, 1, 1).unwrap(),
        };
        project.set_fonts(Vec::new());
        project
    }

    /// Project fonts come after the shared ones, so they extend the shared book.
    fn set_fonts(&mut self, files: Vec<String>) {
        let mut book = shared_fonts().book.clone();
        let mut fonts = Vec::new();
        for file in &files {
            if let Ok(data) = std::fs::read(file) {
                for font in Font::iter(Bytes::new(data)) {
                    book.push(font.info().clone());
                    fonts.push(font);
                }
            }
        }
        self.book = LazyHash::new(book);
        self.fonts = fonts;
        self.font_files = files;
    }

    fn set_file(&mut self, path: &str, content: Content) {
        let id = project_id(path);
        match content {
            Content::Text(text) => match self.files.get_mut(&id) {
                // Reusing the Source lets Typst reparse only what changed.
                Some(Slot::Text { source, bytes }) => {
                    if source.text() != text {
                        source.replace(&text);
                        *bytes = Bytes::from_string(text);
                    }
                }
                _ => {
                    let bytes = Bytes::from_string(text.clone());
                    self.files.insert(id, Slot::Text { source: Source::new(id, text), bytes });
                }
            },
            Content::Disk { disk } => {
                if matches!(self.files.get(&id), Some(Slot::Binary { disk: d, .. }) if *d == disk) {
                    return;
                }
                let bytes = Bytes::new(std::fs::read(&disk).unwrap_or_default());
                self.files.insert(id, Slot::Binary { bytes, disk });
            }
        }
    }

    fn package_path(&self, id: FileId) -> FileResult<PathBuf> {
        let spec = id.package().ok_or_else(|| not_found(id))?;
        let dir = packages().prepare_package(spec, &mut ProgressSink).map_err(FileError::Package)?;
        id.vpath().resolve(&dir).ok_or(FileError::AccessDenied)
    }

    fn read_package(&self, id: FileId) -> FileResult<Bytes> {
        let path = self.package_path(id)?;
        std::fs::read(&path).map(Bytes::new).map_err(|e| FileError::from_io(e, &path))
    }

    /// Typst can't list folders, so `#include "chapters/*"` is handled here: a
    /// missing path whose last segment has `*` or `?` becomes a generated source
    /// that includes every matching .typ file in that folder, in natural order
    /// (ch2 before ch10). The source sits in the folder itself, so the files'
    /// own relative paths keep working. None if `id` isn't such a pattern.
    fn glob_source(&self, id: FileId) -> Option<FileResult<Source>> {
        let path = id.vpath().as_rootless_path().to_string_lossy().replace('\\', "/");
        let (dir, pattern) = path.rsplit_once('/').unwrap_or(("", &path));
        if !pattern.contains(['*', '?']) || dir.contains(['*', '?']) {
            return None;
        }
        let mut names: Vec<String> = self
            .files
            .keys()
            .filter_map(|file| {
                // `#include "*"` next to the main file shouldn't include the main file itself.
                if *file == self.main {
                    return None;
                }
                let file = file.vpath().as_rootless_path().to_string_lossy().replace('\\', "/");
                let (parent, name) = file.rsplit_once('/').unwrap_or(("", &file));
                let wanted = parent == dir && name.ends_with(".typ") && !name.starts_with("__typst_local_") && wildcard(pattern, name);
                wanted.then(|| name.to_string())
            })
            .collect();
        if names.is_empty() {
            return Some(Err(FileError::Other(Some(format!("no .typ files match \"{path}\"").into()))));
        }
        names.sort_by(|a, b| natural_cmp(a, b));
        let text: String = names.iter().map(|n| format!("#include \"{}\"\n", n.replace('\\', "\\\\").replace('"', "\\\""))).collect();
        // Reuse the parsed source while the folder's contents stay the same.
        let mut cache = self.glob_sources.lock().unwrap();
        if let Some(source) = cache.get(&id).filter(|s| s.text() == text) {
            return Some(Ok(source.clone()));
        }
        let source = Source::new(id, text);
        cache.insert(id, source.clone());
        Some(Ok(source))
    }
}

/// Shell-style match of one path segment: `*` is any run of characters, `?` any one.
fn wildcard(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None; // (pattern index after the *, name index it resumes at)
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi + 1, ni));
            pi += 1;
        } else if let Some((after, at)) = star {
            // Let the last * swallow one more character and try again.
            star = Some((after, at + 1));
            pi = after;
            ni = at + 1;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// Orders names with numbers by value, so "ch2.typ" comes before "ch10.typ".
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    use std::iter::Peekable;
    use std::str::Chars;
    fn number(it: &mut Peekable<Chars>) -> String {
        let mut digits = String::new();
        while let Some(c) = it.peek().copied().filter(char::is_ascii_digit) {
            digits.push(c);
            it.next();
        }
        digits
    }
    let (mut a, mut b) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (a.peek().copied(), b.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let (m, n) = (number(&mut a), number(&mut b));
                let (m, n) = (m.trim_start_matches('0'), n.trim_start_matches('0'));
                let order = m.len().cmp(&n.len()).then_with(|| m.cmp(n));
                if order != Ordering::Equal {
                    return order;
                }
            }
            (Some(x), Some(y)) => {
                if x != y {
                    return x.cmp(&y);
                }
                a.next();
                b.next();
            }
        }
    }
}

impl typst_ide::IdeWorld for Project {
    fn upcast(&self) -> &dyn World {
        self
    }
}

impl World for Project {
    fn library(&self) -> &LazyHash<Library> {
        &self.library
    }

    fn book(&self) -> &LazyHash<FontBook> {
        &self.book
    }

    fn main(&self) -> FileId {
        self.main
    }

    fn source(&self, id: FileId) -> FileResult<Source> {
        if id.package().is_some() {
            let mut cache = self.package_sources.lock().unwrap();
            return cache
                .entry(id)
                .or_insert_with(|| {
                    let bytes = self.read_package(id)?;
                    let text = std::str::from_utf8(bytes.as_slice()).map_err(|_| FileError::InvalidUtf8)?;
                    Ok(Source::new(id, text.into()))
                })
                .clone();
        }
        self.accessed.lock().unwrap().insert(id);
        match self.files.get(&id) {
            Some(Slot::Text { source, .. }) => Ok(source.clone()),
            Some(Slot::Binary { bytes, .. }) => {
                let text = std::str::from_utf8(bytes.as_slice()).map_err(|_| FileError::InvalidUtf8)?;
                Ok(Source::new(id, text.into()))
            }
            None => self.glob_source(id).unwrap_or_else(|| Err(not_found(id))),
        }
    }

    fn file(&self, id: FileId) -> FileResult<Bytes> {
        if id.package().is_some() {
            let mut cache = self.package_files.lock().unwrap();
            return cache.entry(id).or_insert_with(|| self.read_package(id)).clone();
        }
        self.accessed.lock().unwrap().insert(id);
        match self.files.get(&id) {
            Some(Slot::Text { bytes, .. }) | Some(Slot::Binary { bytes, .. }) => Ok(bytes.clone()),
            None => Err(not_found(id)),
        }
    }

    fn font(&self, index: usize) -> Option<Font> {
        let shared = &shared_fonts().slots;
        match shared.get(index) {
            Some(slot) => slot.get(),
            None => self.fonts.get(index - shared.len()).cloned(),
        }
    }

    fn today(&self, offset: Option<i64>) -> Option<Datetime> {
        match offset {
            None => Some(self.today),
            Some(hours) => {
                let now = chrono::Utc::now() + chrono::Duration::hours(hours);
                Datetime::from_ymd(now.year(), now.month() as u8, now.day() as u8)
            }
        }
    }
}

// ---- diagnostics ------------------------------------------------------------

fn position(source: &Source, byte: usize) -> Option<Position> {
    let lines = source.lines();
    let line = lines.byte_to_line(byte)?;
    let line_start = lines.line_to_byte(line)?;
    let character = lines.byte_to_utf16(byte)? - lines.byte_to_utf16(line_start)?;
    Some(Position { line, character })
}

fn convert_diagnostic(world: &Project, diag: &SourceDiagnostic) -> Diagnostic {
    let in_project = |span: Span| span.id().is_some_and(|id| id.package().is_none());
    // Errors inside a package are reported where the project calls into it.
    let span = if in_project(diag.span) {
        diag.span
    } else {
        diag.trace.iter().map(|t| t.span).find(|s| in_project(*s)).unwrap_or(diag.span)
    };
    let id = span.id();
    let range = id.and_then(|id| {
        let source = world.source(id).ok()?;
        let bytes = world.range(span)?;
        Some(Range { start: position(&source, bytes.start)?, end: position(&source, bytes.end)? })
    });
    Diagnostic {
        message: diag.message.to_string(),
        severity: match diag.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        },
        path: id.filter(|id| id.package().is_none()).map(|id| id.vpath().as_rootless_path().to_string_lossy().replace('\\', "/")),
        package: diag.span.id().and_then(|id| id.package().map(|p| p.to_string())),
        range,
        hints: diag.hints.iter().map(|h| h.to_string()).collect(),
    }
}

fn error_response(id: u64, message: String) -> Response {
    Response {
        id,
        status: "error",
        diagnostics: vec![Diagnostic { message, severity: "error", path: None, package: None, range: None, hints: vec![] }],
        pages: None,
        num_pages: None,
        outline: None,
        html: None, style: None,
        deps: None,
        pdf: false,
        ms: 0,
    }
}

// ---- click-to-source --------------------------------------------------------

fn jump(project: &Project, id: u64, page: usize, x: f64, y: f64) -> JumpResponse {
    use typst::layout::{Abs, Point};
    let none = JumpResponse { id, kind: "none", ..Default::default() };
    let Some(doc) = &project.document else { return none };
    let Some(target) = doc.pages.get(page) else { return none };
    let click = Point::new(Abs::pt(x), Abs::pt(y));
    match typst_ide::jump_from_click(project, doc, &target.frame, click) {
        Some(typst_ide::Jump::File(file, offset)) if file.package().is_none() => {
            let position = project.source(file).ok().and_then(|source| position(&source, offset));
            JumpResponse {
                id,
                kind: "file",
                path: Some(file.vpath().as_rootless_path().to_string_lossy().replace('\\', "/")),
                position,
                ..Default::default()
            }
        }
        Some(typst_ide::Jump::Url(url)) => JumpResponse { id, kind: "url", url: Some(url.as_str().to_string()), ..Default::default() },
        Some(typst_ide::Jump::Position(pos)) => JumpResponse {
            id,
            kind: "position",
            page: Some(pos.page.get() - 1),
            x: Some(pos.point.x.to_pt()),
            y: Some(pos.point.y.to_pt()),
            ..Default::default()
        },
        _ => none,
    }
}

/// Best glyph in `frame` produced by `span` at or before character `target`
/// of that span's text: (offset in span, baseline point, font size in pt).
fn glyph_for(frame: &typst::layout::Frame, span: Span, target: u16) -> Option<(u16, typst::layout::Point, f64)> {
    use typst::layout::{FrameItem, Point};
    let mut best: Option<(u16, Point, f64)> = None;
    let mut consider = |cand: (u16, Point, f64)| {
        if best.is_none_or(|b| cand.0 >= b.0) {
            best = Some(cand);
        }
    };
    for (pos, item) in frame.items() {
        match item {
            FrameItem::Group(group) => {
                if let Some((off, point, size)) = glyph_for(&group.frame, span, target) {
                    consider((off, *pos + point.transform(group.transform), size));
                }
            }
            FrameItem::Text(text) => {
                let mut x = pos.x;
                for glyph in &text.glyphs {
                    if glyph.span.0 == span && glyph.span.1 <= target {
                        consider((glyph.span.1, Point::new(x, pos.y), text.size.to_pt()));
                    }
                    x += glyph.x_advance.at(text.size);
                }
            }
            _ => {}
        }
    }
    best
}

/// Like typst-ide's `jump_from_cursor`, but lands on the exact character
/// instead of the start of the surrounding run of text, and works anywhere:
/// if the syntax at the cursor (math, code, markup) produced no glyphs, it
/// falls back to the nearest earlier piece of source that did.
fn cursor_position(project: &Project, id: u64, path: &str, offset_utf16: usize) -> JumpResponse {
    use typst::syntax::{LinkedNode, Side};
    let none = JumpResponse { id, kind: "none", ..Default::default() };
    let Some(doc) = &project.document else { return none };
    let Ok(source) = project.source(project_id(path)) else { return none };
    let Some(cursor) = source.lines().utf16_to_byte(offset_utf16.min(source.lines().len_utf16())) else { return none };

    let locate = |node: &LinkedNode, target: u16| {
        let mut best: Option<(usize, u16, typst::layout::Point, f64)> = None;
        for (i, page) in doc.pages.iter().enumerate() {
            if let Some((off, point, size)) = glyph_for(&page.frame, node.span(), target) {
                if best.is_none_or(|b| off >= b.1) {
                    best = Some((i, off, point, size));
                }
            }
        }
        best
    };

    let root = LinkedNode::new(source.root());
    let at_cursor = [Side::Before, Side::After].into_iter().filter_map(|side| root.leaf_at(cursor, side));
    let mut found = at_cursor
        .clone()
        .find_map(|node| locate(&node, u16::try_from(cursor.saturating_sub(node.offset())).unwrap_or(u16::MAX)));
    if found.is_none() {
        // Walk backwards through earlier syntax until something produced output.
        let mut node = at_cursor.into_iter().next().and_then(|n| n.prev_leaf());
        for _ in 0..200 {
            let Some(n) = node else { break };
            if let Some(hit) = locate(&n, u16::MAX) {
                found = Some(hit);
                break;
            }
            node = n.prev_leaf();
        }
    }
    match found {
        Some((page, _, point, size)) => JumpResponse {
            id,
            kind: "position",
            page: Some(page),
            x: Some(point.x.to_pt()),
            y: Some(point.y.to_pt()),
            size: Some(size),
            ..Default::default()
        },
        None => none,
    }
}

// ---- outline ----------------------------------------------------------------

fn outline(project: &Project, doc: &PagedDocument) -> Vec<Heading> {
    use typst::foundations::{NativeElement, StyleChain};
    use typst::model::HeadingElem;
    let styles = StyleChain::default();
    doc.introspector
        .query(&HeadingElem::ELEM.select())
        .iter()
        .filter_map(|content| {
            let heading = content.to_packed::<HeadingElem>()?;
            let at = doc.introspector.position(content.location()?);
            // Prefer where the heading's text was written (e.g. a `title: [...]`
            // passed into a template) over where the template builds the heading.
            let in_project = |s: Span| s.id().is_some_and(|id| id.package().is_none());
            let span = [heading.body.span(), content.span()].into_iter().find(|s| in_project(*s)).unwrap_or(content.span());
            let file = span.id().filter(|id| id.package().is_none());
            let position = file.and_then(|id| {
                let source = project.source(id).ok()?;
                position(&source, project.range(span)?.start)
            });
            Some(Heading {
                level: heading.resolve_level(styles).get(),
                title: heading.body.plain_text().trim().to_string(),
                number: heading.numbers.as_ref().map(|n| n.to_string()).filter(|n| !n.is_empty()),
                outlined: heading.outlined.get(styles),
                page: at.page.get() - 1,
                x: at.point.x.to_pt(),
                y: at.point.y.to_pt(),
                path: file.map(|id| id.vpath().as_rootless_path().to_string_lossy().replace('\\', "/")),
                position,
            })
        })
        .collect()
}

// ---- HTML export ---------------------------------------------------------------

/// Exports the document as HTML through a wrapper (html-export.typ) that
/// includes the real main file and keeps what HTML export would drop.
fn export_html(project: &mut Project, id: u64, main: &str, start: Instant) -> Response {
    let wrapper = project_id("__typst_local_export__.typ");
    let text = include_str!("html-export.typ").replace("{MAIN}", &main.replace('\\', "/").replace('"', "\\\""));
    let bytes = Bytes::from_string(text.clone());
    project.files.insert(wrapper, Slot::Text { source: Source::new(wrapper, text), bytes });
    let real_main = project.main;
    project.main = wrapper;
    let result = typst::compile::<typst_html::HtmlDocument>(&*project);
    project.main = real_main;
    project.files.remove(&wrapper);

    let warnings: Vec<Diagnostic> = result.warnings.iter().map(|d| convert_diagnostic(project, d)).collect();
    let html = result.output.and_then(|doc| typst_html::html(&doc));
    // Measure the paged layout (through a wrapper that marks placed elements)
    // so the export can be styled, and placed things pinned, like it.
    let probe_wrapper = project_id("__typst_local_probe__.typ");
    let probe_src = include_str!("paged-probe.typ").replace("{MAIN}", &main.replace('\\', "/").replace('"', "\\\""));
    let probe_bytes = Bytes::from_string(probe_src.clone());
    project.files.insert(probe_wrapper, Slot::Text { source: Source::new(probe_wrapper, probe_src), bytes: probe_bytes });
    let real_main = project.main;
    project.main = probe_wrapper;
    let style = typst::compile::<PagedDocument>(&*project).output.ok().map(|doc| probe::probe(&doc));
    project.main = real_main;
    project.files.remove(&probe_wrapper);
    let ms = start.elapsed().as_millis() as u64;
    match html {
        Ok(html) => Response { id, status: "ok", diagnostics: warnings, pages: None, num_pages: None, outline: None, html: Some(html), style, deps: None, pdf: false, ms },
        Err(errors) => {
            let mut all: Vec<Diagnostic> = errors.iter().map(|d| convert_diagnostic(project, d)).collect();
            all.extend(warnings);
            Response { id, status: "error", diagnostics: all, pages: None, num_pages: None, outline: None, html: None, style: None, deps: None, pdf: false, ms }
        }
    }
}

// ---- compiling --------------------------------------------------------------

fn compile(project: &mut Project, req: CompileRequest) -> Response {
    let start = Instant::now();
    if let Some(fonts) = req.fonts {
        if fonts != project.font_files {
            project.set_fonts(fonts);
        }
    }
    for path in &req.remove {
        project.files.remove(&project_id(path));
    }
    for (path, content) in req.set {
        project.set_file(&path, content);
    }
    project.main = project_id(&req.main);
    if !project.files.contains_key(&project.main) {
        return error_response(req.id, format!("main file \"{}\" does not exist", req.main));
    }
    let now = Local::now();
    project.today = Datetime::from_ymd(now.year(), now.month() as u8, now.day() as u8).unwrap_or(project.today);
    // Package files are cheap to re-read and may have been downloaded meanwhile.
    project.package_sources.lock().unwrap().retain(|_, v| v.is_ok());
    project.package_files.lock().unwrap().retain(|_, v| v.is_ok());

    if req.html {
        return export_html(project, req.id, &req.main, start);
    }

    project.accessed.lock().unwrap().clear();
    let result = typst::compile::<PagedDocument>(&*project);
    let mut diagnostics: Vec<Diagnostic> = result.warnings.iter().map(|d| convert_diagnostic(project, d)).collect();
    let doc = match result.output {
        Ok(doc) => doc,
        Err(errors) => {
            let mut all: Vec<Diagnostic> = errors.iter().map(|d| convert_diagnostic(project, d)).collect();
            all.append(&mut diagnostics);
            return Response {
                id: req.id,
                status: "error",
                diagnostics: all,
                pages: None,
                num_pages: None,
                outline: None,
                html: None, style: None,
                deps: None,
                pdf: false,
                ms: start.elapsed().as_millis() as u64,
            };
        }
    };
    let status = if diagnostics.is_empty() { "ok" } else { "warning" };

    if req.deps {
        let mut deps: Vec<String> = project
            .accessed
            .lock()
            .unwrap()
            .iter()
            .map(|id| id.vpath().as_rootless_path().to_string_lossy().replace('\\', "/"))
            .collect();
        deps.sort();
        let ms = start.elapsed().as_millis() as u64;
        return Response { id: req.id, status, diagnostics, pages: None, num_pages: Some(doc.pages.len()), outline: None, html: None, style: None, deps: Some(deps), pdf: false, ms };
    }

    if let Some(out) = req.pdf {
        let written = typst_pdf::pdf(&doc, &typst_pdf::PdfOptions::default())
            .map_err(|errs| errs.iter().map(|d| convert_diagnostic(project, d)).collect::<Vec<_>>())
            .and_then(|bytes| {
                std::fs::write(Path::new(&out), bytes).map_err(|e| {
                    vec![Diagnostic { message: format!("could not write PDF: {e}"), severity: "error", path: None, package: None, range: None, hints: vec![] }]
                })
            });
        return match written {
            Ok(()) => Response { id: req.id, status, diagnostics, pages: None, num_pages: Some(doc.pages.len()), outline: None, html: None, style: None, deps: None, pdf: true, ms: start.elapsed().as_millis() as u64 },
            Err(mut errs) => {
                errs.append(&mut diagnostics);
                Response { id: req.id, status: "error", diagnostics: errs, pages: None, num_pages: None, outline: None, html: None, style: None, deps: None, pdf: false, ms: start.elapsed().as_millis() as u64 }
            }
        };
    }

    // Only pages the caller doesn't have yet are turned into SVG (in parallel).
    let hashes: Vec<u128> = doc.pages.par_iter().map(typst::utils::hash128).collect();
    let mut todo: Vec<usize> = Vec::new();
    let mut queued = HashSet::new();
    for (i, hash) in hashes.iter().enumerate() {
        if (req.full || !project.rendered.contains(hash)) && queued.insert(*hash) {
            todo.push(i);
        }
    }
    let rendered: HashMap<usize, String> = todo.par_iter().map(|&i| (i, typst_svg::svg(&doc.pages[i]))).collect();
    let mut rendered = rendered;
    let pages = doc
        .pages
        .iter()
        .enumerate()
        .map(|(i, page)| PageOut {
            tid: format!("{:032x}", hashes[i]),
            w: page.frame.width().to_pt(),
            h: page.frame.height().to_pt(),
            svg: rendered.remove(&i),
        })
        .collect();
    project.rendered = hashes.into_iter().collect();
    let num_pages = doc.pages.len();
    let outline = outline(project, &doc);
    project.document = Some(doc);

    Response {
        id: req.id,
        status,
        diagnostics,
        pages: Some(pages),
        num_pages: Some(num_pages),
        outline: Some(outline),
        html: None, style: None,
        deps: None,
        pdf: false,
        ms: start.elapsed().as_millis() as u64,
    }
}

fn main() {
    // Warm up the font scan in the background so the first compile is quicker.
    std::thread::spawn(shared_fonts);

    let mut projects: HashMap<String, Project> = HashMap::new();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let mut compiles = 0u64;

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[typst-engine] bad request: {e}");
                continue;
            }
        };
        let response = match request {
            Request::Drop { project } => {
                projects.remove(&project);
                continue;
            }
            Request::Jump { .. } | Request::Cursor { .. } => {
                let (id, name) = match &request {
                    Request::Jump { id, project, .. } | Request::Cursor { id, project, .. } => (*id, project.clone()),
                    _ => unreachable!(),
                };
                let answer = match projects.get(&name) {
                    Some(p) => catch_unwind(AssertUnwindSafe(|| match &request {
                        Request::Jump { page, x, y, .. } => jump(p, id, *page, *x, *y),
                        Request::Cursor { path, offset, .. } => cursor_position(p, id, path, *offset),
                        _ => unreachable!(),
                    }))
                    .unwrap_or(JumpResponse { id, kind: "none", ..Default::default() }),
                    None => JumpResponse { id, kind: "none", ..Default::default() },
                };
                if serde_json::to_writer(&mut stdout, &answer).is_err() || stdout.write_all(b"\n").is_err() || stdout.flush().is_err() {
                    break;
                }
                continue;
            }
            Request::Compile(req) => {
                let id = req.id;
                let project = projects.entry(req.project.clone()).or_insert_with(Project::new);
                let outcome = catch_unwind(AssertUnwindSafe(|| compile(project, req)));
                outcome.unwrap_or_else(|_| {
                    // A panic may have left the project half-updated; start it fresh next time.
                    error_response(id, "the compiler crashed on this document".into())
                })
            }
        };
        compiles += 1;
        if compiles % 10 == 0 {
            comemo::evict(30);
        }
        if serde_json::to_writer(&mut stdout, &response).is_err() || stdout.write_all(b"\n").is_err() || stdout.flush().is_err() {
            break;
        }
    }
}
