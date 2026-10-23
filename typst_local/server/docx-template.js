// Builds a Word reference document (styles, page setup, header/footer) from
// the engine's style probe, so pandoc's .docx output looks like the Typst
// document it came from, whatever template that document uses.
//
// Starts from pandoc's own default reference.docx (which defines every style
// pandoc emits) and replaces the parts that carry the look.
import { createZip, readZip } from './zip.js';

const W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"';

const twip = (pt) => Math.round(pt * 20);
const halfPt = (pt) => Math.round(pt * 2);
const hex = (c) => (c || '#000000').replace('#', '').slice(0, 6).toUpperCase();
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const pt = (style) => (style ? style.size / 100 : null);

/** Mixes a hex colour with white; `amount` 0 = colour, 1 = white. */
function tint(color, amount) {
  const h = hex(color);
  const mix = (i) => Math.round(parseInt(h.slice(i, i + 2), 16) * (1 - amount) + 255 * amount);
  return [0, 2, 4].map((i) => mix(i).toString(16).padStart(2, '0')).join('').toUpperCase();
}

function runProps({ font, size, color, bold, italic }) {
  return [
    font && `<w:rFonts w:ascii="${esc(font)}" w:hAnsi="${esc(font)}" w:eastAsia="${esc(font)}" w:cs="${esc(font)}"/>`,
    bold === true ? '<w:b/><w:bCs/>' : bold === false ? '<w:b w:val="0"/><w:bCs w:val="0"/>' : '',
    italic === true ? '<w:i/><w:iCs/>' : '',
    color && `<w:color w:val="${hex(color)}"/>`,
    size && `<w:sz w:val="${halfPt(size)}"/><w:szCs w:val="${halfPt(size)}"/>`,
  ]
    .filter(Boolean)
    .join('');
}

function styleXml({ type = 'paragraph', id, name, basedOn, next, link, pPr = '', rPr = '', extra = '', custom = false }) {
  return (
    `<w:style w:type="${type}"${custom ? ' w:customStyle="1"' : ''} w:styleId="${id}"><w:name w:val="${esc(name)}"/>` +
    (basedOn ? `<w:basedOn w:val="${basedOn}"/>` : '') +
    (next ? `<w:next w:val="${next}"/>` : '') +
    (link ? `<w:link w:val="${link}"/>` : '') +
    '<w:qFormat/>' +
    (pPr ? `<w:pPr>${pPr}</w:pPr>` : '') +
    (rPr ? `<w:rPr>${rPr}</w:rPr>` : '') +
    extra +
    '</w:style>'
  );
}

/** Replaces (or adds) the style with this id. */
function putStyle(xml, id, replacement) {
  const re = new RegExp(`<w:style\\b[^>]*w:styleId="${id}"[\\s\\S]*?</w:style>`);
  return re.test(xml) ? xml.replace(re, replacement) : xml.replace('</w:styles>', replacement + '</w:styles>');
}

/** A header/footer paragraph: left, center and right text on tab stops; {page}/{pages} become fields. */
function bandParagraph(bands, styleId, textWidth) {
  const slot = { left: [], center: [], right: [] };
  for (const b of bands) slot[b.align].push(b);
  const runs = (band) =>
    band.text
      .split(/(\{page\}|\{pages\})/)
      .filter(Boolean)
      .map((part) => {
        const rPr = `<w:rPr>${runProps({ color: band.style.color, bold: band.style.bold, italic: band.style.italic })}</w:rPr>`;
        if (part === '{page}' || part === '{pages}') {
          const field = part === '{page}' ? 'PAGE' : 'NUMPAGES';
          return (
            `<w:r>${rPr}<w:fldChar w:fldCharType="begin"/></w:r><w:r>${rPr}<w:instrText xml:space="preserve"> ${field} </w:instrText></w:r>` +
            `<w:r>${rPr}<w:fldChar w:fldCharType="separate"/></w:r><w:r>${rPr}<w:t>1</w:t></w:r><w:r>${rPr}<w:fldChar w:fldCharType="end"/></w:r>`
          );
        }
        return `<w:r>${rPr}<w:t xml:space="preserve">${esc(part)}</w:t></w:r>`;
      })
      .join('');
  const tab = '<w:r><w:tab/></w:r>';
  const join = (list) => list.map(runs).join('<w:r><w:t xml:space="preserve">  </w:t></w:r>');
  return (
    `<w:p><w:pPr><w:pStyle w:val="${styleId}"/><w:tabs><w:tab w:val="center" w:pos="${twip(textWidth / 2)}"/><w:tab w:val="right" w:pos="${twip(textWidth)}"/></w:tabs></w:pPr>` +
    join(slot.left) +
    (slot.center.length || slot.right.length ? tab + join(slot.center) : '') +
    (slot.right.length ? tab + join(slot.right) : '') +
    '</w:p>'
  );
}

/**
 * @param {Buffer} defaultReference pandoc's default reference.docx
 * @param {object|null} probe the engine's style probe (see engine/src/probe.rs)
 * @returns {Buffer} a reference.docx for pandoc's --reference-doc
 */
export function buildReferenceDocx(defaultReference, probe, charStyles = []) {
  const parts = new Map(readZip(defaultReference));
  const p = probe || {};
  const body = p.body || { font: null, size: 1100, color: '#000000', bold: false, italic: false };
  const bodyPt = pt(body) || 11;
  const code = p.code;
  const pageW = p.page_width || 612;
  const pageH = p.page_height || 792;
  const [mTop, mRight, mBottom, mLeft] = p.margins || [72, 72, 72, 72];
  const textWidth = pageW - mLeft - mRight;
  const accent = p.headings?.find((h) => h && hex(h.color) !== hex(body.color))?.color || p.link_color || '#4F81BD';
  const lineHeight = p.line_height ? Math.max(1, Math.min(2, p.line_height)) : 1.3;
  // Word's "single" spacing is about 1.2x the font size for typical fonts.
  const lineRule = `w:line="${Math.round((240 * lineHeight) / 1.2)}" w:lineRule="auto"`;

  // ---- styles ----
  let styles = parts.get('word/styles.xml').toString('utf8');
  styles = styles.replace(
    /<w:docDefaults>[\s\S]*?<\/w:docDefaults>/,
    // Typst always kerns; Word only does so from the given size (half-points) up.
    `<w:docDefaults><w:rPrDefault><w:rPr>${runProps({ font: body.font, size: bodyPt, color: body.color })}<w:kern w:val="2"/><w:lang w:val="en-US"/></w:rPr></w:rPrDefault>` +
      `<w:pPrDefault><w:pPr><w:spacing w:after="${twip(bodyPt * 0.7)}" ${lineRule}/></w:pPr></w:pPrDefault></w:docDefaults>`,
  );
  const justify = p.justify ? '<w:jc w:val="both"/>' : '';
  styles = putStyle(styles, 'Normal', `<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/><w:pPr>${justify}</w:pPr><w:rPr>${runProps({ font: body.font, size: bodyPt, color: body.color })}</w:rPr></w:style>`);
  styles = putStyle(styles, 'BodyText', styleXml({ id: 'BodyText', name: 'Body Text', basedOn: 'Normal', link: 'BodyTextChar', pPr: `<w:spacing w:before="0" w:after="${twip(bodyPt * 0.7)}"/>` }));
  styles = putStyle(styles, 'FirstParagraph', styleXml({ id: 'FirstParagraph', name: 'First Paragraph', basedOn: 'BodyText', next: 'BodyText', custom: true }));
  // Tight list items and table cells: no gap beyond the line spacing (as in Typst).
  styles = putStyle(styles, 'Compact', styleXml({ id: 'Compact', name: 'Compact', basedOn: 'BodyText', custom: true, pPr: '<w:spacing w:before="0" w:after="0"/>' }));

  const defaults = [1.8, 1.45, 1.25, 1.1, 1, 1];
  for (let level = 1; level <= 6; level++) {
    const h = p.headings?.[level - 1] || { font: body.font, size: Math.round(bodyPt * defaults[level - 1] * 100), color: accent, bold: true, italic: false };
    const size = pt(h);
    // Page breaks go on the individual headings when known (see docx.js).
    const pageBreak = !p.heading_breaks && p.heading_page_break?.[level - 1] ? '<w:pageBreakBefore/>' : '';
    styles = putStyle(
      styles,
      `Heading${level}`,
      styleXml({
        id: `Heading${level}`,
        name: `heading ${level}`,
        basedOn: 'Normal',
        next: 'BodyText',
        link: `Heading${level}Char`,
        // (Typst doesn't hyphenate headings.)
        pPr: `<w:keepNext/><w:keepLines/>${pageBreak}<w:suppressAutoHyphens/><w:spacing w:before="${twip(size * (level === 1 ? 0.8 : 1))}" w:after="${twip(size * 0.45)}" w:line="240" w:lineRule="auto"/><w:jc w:val="left"/><w:outlineLvl w:val="${level - 1}"/>`,
        rPr: runProps({ ...h, size }),
      }),
    );
    styles = putStyle(styles, `Heading${level}Char`, styleXml({ type: 'character', id: `Heading${level}Char`, name: `Heading ${level} Char`, link: `Heading${level}`, custom: true, rPr: runProps({ ...h, size }) }));
  }
  const h1 = p.headings?.[0] || { font: body.font, size: bodyPt * 180, color: accent, bold: true };
  styles = putStyle(styles, 'Title', styleXml({ id: 'Title', name: 'Title', basedOn: 'Normal', next: 'BodyText', pPr: '<w:spacing w:before="0" w:after="240"/>', rPr: runProps({ ...h1, size: pt(h1) * 1.4 }) }));
  // The table of contents looks like the document's own (measured by the
  // probe): title alignment and style, and each level's style, indent and spacing.
  const toc = p.toc;
  const tocTitle = toc?.title_style || { ...h1 };
  styles = putStyle(
    styles,
    'TOCHeading',
    styleXml({
      id: 'TOCHeading',
      name: 'TOC Heading',
      basedOn: 'Normal',
      next: 'BodyText',
      pPr: `<w:keepNext/><w:spacing w:before="0" w:after="${twip(pt(tocTitle) * 0.4)}" w:line="240" w:lineRule="auto"/>${toc?.title_center ? '<w:jc w:val="center"/>' : '<w:jc w:val="left"/>'}`,
      rPr: runProps({ ...tocTitle, size: pt(tocTitle) }),
    }),
  );
  const tocLevels = Math.max(3, toc?.levels?.length || 0);
  for (let level = 1; level <= Math.min(9, tocLevels); level++) {
    const measured = toc?.levels?.[level - 1];
    const spacing = measured
      ? `<w:spacing w:before="${twip(measured.above)}" w:after="0"${toc.pitch ? ` w:line="${twip(toc.pitch)}" w:lineRule="exact"` : ''}/>`
      : `<w:spacing w:before="${level === 1 ? 120 : 0}" w:after="40"/>`;
    const indent = measured ? twip(measured.indent) : (level - 1) * 280;
    const rPr = measured ? runProps({ ...measured.style, size: pt(measured.style), bold: !!measured.style.bold }) : level === 1 ? '<w:b/>' : '';
    styles = putStyle(
      styles,
      `TOC${level}`,
      styleXml({ id: `TOC${level}`, name: `toc ${level}`, basedOn: 'Normal', next: 'Normal', pPr: `<w:tabs><w:tab w:val="right" w:leader="dot" w:pos="${twip(textWidth)}"/></w:tabs>${spacing}<w:ind w:left="${indent}"/><w:jc w:val="left"/>`, rPr }),
    );
  }
  // Headings the document leaves out of its outline stay out of the Word
  // table of contents too (same look, but body-text outline level).
  for (let level = 1; level <= 6; level++) {
    styles = putStyle(
      styles,
      `Heading${level}Unlisted`,
      styleXml({ id: `Heading${level}Unlisted`, name: `Heading ${level} (not in contents)`, basedOn: `Heading${level}`, next: 'BodyText', custom: true, pPr: '<w:outlineLvl w:val="9"/>' }),
    );
  }

  const codeFont = code?.font || 'Consolas';
  const codeSize = pt(code) || bodyPt * 0.85;
  styles = putStyle(
    styles,
    'SourceCode',
    styleXml({
      id: 'SourceCode',
      name: 'Source Code',
      basedOn: 'Normal',
      link: 'VerbatimChar',
      custom: true,
      pPr: `<w:pBdr><w:top w:val="single" w:sz="4" w:space="4" w:color="D0D7DE"/><w:left w:val="single" w:sz="4" w:space="4" w:color="D0D7DE"/><w:bottom w:val="single" w:sz="4" w:space="4" w:color="D0D7DE"/><w:right w:val="single" w:sz="4" w:space="4" w:color="D0D7DE"/></w:pBdr><w:shd w:val="clear" w:color="auto" w:fill="F6F8FA"/><w:wordWrap w:val="off"/><w:spacing w:before="60" w:after="${twip(bodyPt * 0.8)}" w:line="240" w:lineRule="auto"/><w:jc w:val="left"/>`,
      rPr: runProps({ font: codeFont, size: codeSize }),
    }),
  );
  // One paragraph per line of a highlighted code block (see docx.js); lines
  // share the block's border and shading, the block keeps its outer spacing.
  styles = putStyle(styles, 'TLCodeLine', styleXml({ id: 'TLCodeLine', name: 'TL Code Line', basedOn: 'SourceCode', custom: true, pPr: '<w:spacing w:before="0" w:after="0"/>' }));
  styles = putStyle(styles, 'VerbatimChar', styleXml({ type: 'character', id: 'VerbatimChar', name: 'Verbatim Char', link: 'SourceCode', custom: true, rPr: runProps({ font: codeFont, size: codeSize }) }));
  styles = putStyle(styles, 'Hyperlink', styleXml({ type: 'character', id: 'Hyperlink', name: 'Hyperlink', rPr: runProps({ color: p.link_color || accent }) }));
  styles = putStyle(styles, 'Caption', styleXml({ id: 'Caption', name: 'caption', basedOn: 'Normal', pPr: `<w:spacing w:before="60" w:after="${twip(bodyPt)}"/><w:jc w:val="center"/>`, rPr: runProps({ italic: true, size: bodyPt * 0.92 }) }));
  styles = putStyle(styles, 'ImageCaption', styleXml({ id: 'ImageCaption', name: 'Image Caption', basedOn: 'Caption', custom: true }));
  styles = putStyle(styles, 'TableCaption', styleXml({ id: 'TableCaption', name: 'Table Caption', basedOn: 'Caption', custom: true, pPr: '<w:keepNext/>' }));
  styles = putStyle(styles, 'Figure', styleXml({ id: 'Figure', name: 'Figure', basedOn: 'Normal', custom: true, pPr: '<w:keepNext/><w:spacing w:before="120" w:after="0"/><w:jc w:val="center"/>' }));
  styles = putStyle(styles, 'CaptionedFigure', styleXml({ id: 'CaptionedFigure', name: 'Captioned Figure', basedOn: 'Figure', custom: true }));

  const border = (side) => `<w:${side} w:val="single" w:sz="4" w:space="0" w:color="C9CED6"/>`;
  styles = putStyle(
    styles,
    'Table',
    `<w:style w:type="table" w:default="1" w:styleId="Table"><w:name w:val="Table"/><w:basedOn w:val="TableNormal"/><w:qFormat/>` +
      // Typst table text is body text: same size and line spacing.
      `<w:pPr><w:spacing w:before="0" w:after="0" ${lineRule}/><w:jc w:val="left"/></w:pPr>` +
      `<w:tblPr><w:tblBorders>${['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map(border).join('')}</w:tblBorders>` +
      `<w:tblCellMar><w:top w:w="60" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="60" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar></w:tblPr>` +
      `<w:tblStylePr w:type="firstRow"><w:rPr><w:b/><w:bCs/></w:rPr><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="${tint(accent, 0.82)}"/></w:tcPr></w:tblStylePr></w:style>`,
  );

  // Borderless table for side-by-side layouts (see applyLayoutTables in docx.js).
  styles = putStyle(
    styles,
    'TLLayout',
    `<w:style w:type="table" w:customStyle="1" w:styleId="TLLayout"><w:name w:val="TL Layout"/><w:basedOn w:val="TableNormal"/><w:qFormat/>` +
      `<w:tblPr><w:tblBorders>${['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map((side) => `<w:${side} w:val="nil"/>`).join('')}</w:tblBorders></w:tblPr></w:style>`,
  );

  const headerStyle = (id, name, band) =>
    styleXml({ id, name, basedOn: 'Normal', pPr: '<w:spacing w:before="0" w:after="0"/>', rPr: runProps({ font: band?.style.font, size: pt(band?.style) || bodyPt * 0.85, color: band?.style.color }) });
  styles = putStyle(styles, 'Header', headerStyle('Header', 'header', p.header?.[0]));
  styles = putStyle(styles, 'Footer', headerStyle('Footer', 'footer', p.footer?.[0]));
  // Paragraph alignment carried over from align(center/right).
  styles = putStyle(styles, 'TLCenter', styleXml({ id: 'TLCenter', name: 'TL Center', basedOn: 'BodyText', custom: true, pPr: '<w:jc w:val="center"/>' }));
  styles = putStyle(styles, 'TLRight', styleXml({ id: 'TLRight', name: 'TL Right', basedOn: 'BodyText', custom: true, pPr: '<w:jc w:val="right"/>' }));
  // Holds pictures pinned to an exact spot on the page (see docx.js); takes no room itself.
  styles = putStyle(styles, 'TLAnchor', styleXml({ id: 'TLAnchor', name: 'TL Anchor', basedOn: 'Normal', custom: true, pPr: '<w:spacing w:before="0" w:after="0" w:line="20" w:lineRule="exact"/>', rPr: '<w:sz w:val="2"/><w:szCs w:val="2"/>' }));

  // Character styles for text that looks different from body text and headings.
  for (const cs of charStyles) {
    const id = cs.name.replace(/\s+/g, '');
    // Bold is a toggle in Word (a bold character style in a bold heading turns it
    // off), so it's applied to the runs directly instead (see docx.js).
    styles = putStyle(styles, id, styleXml({ type: 'character', id, name: cs.name, custom: true, rPr: runProps({ font: cs.font, size: cs.size, color: cs.color }) }));
  }
  parts.set('word/styles.xml', Buffer.from(styles));

  // ---- page setup, header and footer ----
  const rels = [];
  let refs = '';
  const addBand = (bands, kind) => {
    if (!bands?.length) return;
    const file = `${kind}1.xml`;
    const tag = kind === 'header' ? 'hdr' : 'ftr';
    parts.set(`word/${file}`, Buffer.from(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:${tag} ${W_NS}>${bandParagraph(bands, kind === 'header' ? 'Header' : 'Footer', textWidth)}</w:${tag}>`));
    const id = `rIdTypstLocal${kind}`;
    rels.push(`<Relationship Id="${id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/${kind}" Target="${file}"/>`);
    refs += `<w:${kind}Reference w:type="default" r:id="${id}"/>`;
    const ct = parts.get('[Content_Types].xml').toString('utf8');
    parts.set(
      '[Content_Types].xml',
      Buffer.from(ct.replace('</Types>', `<Override PartName="/word/${file}" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.${kind}+xml"/></Types>`)),
    );
  };
  addBand(p.header, 'header');
  addBand(p.footer, 'footer');
  if (rels.length) {
    const r = parts.get('word/_rels/document.xml.rels').toString('utf8');
    parts.set('word/_rels/document.xml.rels', Buffer.from(r.replace('</Relationships>', rels.join('') + '</Relationships>')));
  }
  const sectPr =
    `<w:sectPr>${refs}<w:footnotePr><w:numRestart w:val="eachSect"/></w:footnotePr>` +
    `<w:pgSz w:w="${twip(pageW)}" w:h="${twip(pageH)}"${pageW > pageH ? ' w:orient="landscape"' : ''}/>` +
    `<w:pgMar w:top="${twip(mTop)}" w:right="${twip(mRight)}" w:bottom="${twip(mBottom)}" w:left="${twip(mLeft)}" w:header="${twip(Math.max(18, mTop * 0.45))}" w:footer="${twip(Math.max(18, mBottom * 0.45))}" w:gutter="0"/>` +
    (p.first_page_plain ? '<w:titlePg/>' : '') +
    '</w:sectPr>';
  const doc = parts.get('word/document.xml').toString('utf8');
  parts.set('word/document.xml', Buffer.from(doc.replace(/<w:sectPr>[\s\S]*<\/w:sectPr>/, sectPr)));

  // Word requires settings in schema order: each goes before the first of the
  // elements that must follow it.
  let settings = parts.get('word/settings.xml').toString('utf8');
  const ORDER = ['w:displayBackgroundShape', 'w:embedTrueTypeFonts', 'w:embedSystemFonts', 'w:saveSubsetFonts', 'w:saveFormsData', 'w:mirrorMargins', 'w:alignBordersAndEdges', 'w:bordersDoNotSurroundHeader', 'w:bordersDoNotSurroundFooter', 'w:gutterAtTop', 'w:hideSpellingErrors', 'w:hideGrammaticalErrors', 'w:activeWritingStyle', 'w:proofState', 'w:formsDesign', 'w:attachedTemplate', 'w:linkStyles', 'w:stylePaneFormatFilter', 'w:stylePaneSortMethod', 'w:documentType', 'w:mailMerge', 'w:revisionView', 'w:trackRevisions', 'w:doNotTrackMoves', 'w:doNotTrackFormatting', 'w:documentProtection', 'w:autoFormatOverride', 'w:styleLockTheme', 'w:styleLockQFSet', 'w:defaultTabStop', 'w:autoHyphenation', 'w:consecutiveHyphenLimit', 'w:hyphenationZone', 'w:doNotHyphenateCaps', 'w:showEnvelope', 'w:summaryLength', 'w:clickAndTypeStyle', 'w:defaultTableStyle', 'w:evenAndOddHeaders', 'w:bookFoldRevPrinting', 'w:bookFoldPrinting', 'w:bookFoldPrintingSheets', 'w:drawingGridHorizontalSpacing', 'w:drawingGridVerticalSpacing', 'w:displayHorizontalDrawingGridEvery', 'w:displayVerticalDrawingGridEvery', 'w:doNotUseMarginsForDrawingGridOrigin', 'w:drawingGridHorizontalOrigin', 'w:drawingGridVerticalOrigin', 'w:doNotShadeFormData', 'w:noPunctuationKerning', 'w:characterSpacingControl', 'w:printTwoOnOne', 'w:strictFirstAndLastChars', 'w:noLineBreaksAfter', 'w:noLineBreaksBefore', 'w:savePreviewPicture', 'w:doNotValidateAgainstSchema', 'w:saveInvalidXml', 'w:ignoreMixedContent', 'w:alwaysShowPlaceholderText', 'w:doNotDemarcateInvalidXml', 'w:saveXmlDataOnly', 'w:useXSLTWhenSaving', 'w:saveThroughXslt', 'w:showXMLTags', 'w:alwaysMergeEmptyNamespace', 'w:updateFields', 'w:hdrShapeDefaults', 'w:footnotePr', 'w:endnotePr', 'w:compat', 'w:docVars', 'w:rsids', 'm:mathPr', 'w:attachedSchema', 'w:themeFontLang', 'w:clrSchemeMapping', 'w:doNotIncludeSubdocsInStats', 'w:doNotAutoCompressPictures', 'w:forceUpgrade', 'w:captions', 'w:readModeInkLockDown', 'w:smartTagType', 'sl:schemaLibrary', 'w:shapeDefaults', 'w:doNotEmbedSmartTags', 'w:decimalSymbol', 'w:listSeparator'];
  const putSetting = (tag, xml) => {
    if (settings.includes('<' + tag)) return;
    const later = ORDER.slice(ORDER.indexOf(tag) + 1);
    const at = later.map((t) => settings.search(new RegExp(`<${t}[ />]`))).filter((i) => i >= 0).sort((x, y) => x - y)[0];
    settings = at === undefined ? settings.replace('</w:settings>', xml + '</w:settings>') : settings.slice(0, at) + xml + settings.slice(at);
  };
  // A coloured page (e.g. dark slides) becomes the document background.
  if (p.page_fill) putSetting('w:displayBackgroundShape', '<w:displayBackgroundShape/>');
  // Typst hyphenates justified text by default.
  if (p.justify) putSetting('w:autoHyphenation', '<w:autoHyphenation/>');
  // Fill in the table of contents (and page fields) when the file is opened.
  putSetting('w:updateFields', '<w:updateFields w:val="true"/>');
  // Lay out like current Word, not in Compatibility Mode.
  // Like Typst: no space above a heading (or anything) that starts a page, and
  // a line ending in a line break isn't stretched in justified text.
  putSetting('w:compat', '<w:compat><w:doNotExpandShiftReturn/><w:suppressSpBfAfterPgBrk/><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat>');
  parts.set('word/settings.xml', Buffer.from(settings));

  return createZip([...parts]);
}
