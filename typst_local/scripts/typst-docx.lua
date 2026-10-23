-- Pandoc filter for Typst Local's Word export (see server/docx.js).
--
-- * Typst's HTML export reserves <h1> for the document title, so `= Heading`
--   arrives as <h2>: shift levels back so it becomes Word's "Heading 1".
-- * The document's own outline arrives as marker paragraphs around its
--   entries (see markTableOfContents in docx.js); wrap them in a real Word
--   table of contents field, so Word can refresh it.
-- * The template already renders its title page, so drop pandoc's title block.

local MARKER = 'TYPSTLOCALTOC::'
local END_MARKER = 'TYPSTLOCALTOCEND'
local toc_levels = os.getenv('TYPST_LOCAL_TOC_LEVELS') or '3'
local toc_break_before = os.getenv('TYPST_LOCAL_TOC_BREAK_BEFORE') == '1'
local toc_break_after = os.getenv('TYPST_LOCAL_TOC_BREAK_AFTER') == '1'

local PAGE_BREAK = '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'

local function escape(s)
  return (s:gsub('&', '&amp;'):gsub('<', '&lt;'):gsub('>', '&gt;'))
end

local function escape_title(title)
  if title == '' then return '' end
  return '<w:p><w:pPr><w:pStyle w:val="TOCHeading"/></w:pPr><w:r><w:t xml:space="preserve">' .. escape(title) .. '</w:t></w:r></w:p>'
end

local SDT_OPEN = '<w:sdt><w:sdtPr><w:docPartObj><w:docPartGallery w:val="Table of Contents"/><w:docPartUnique/></w:docPartObj></w:sdtPr><w:sdtContent>'
local SDT_CLOSE = '</w:sdtContent></w:sdt>'

local function field_begin()
  return '<w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r>'
    .. '<w:r><w:instrText xml:space="preserve"> TOC \\o "1-' .. toc_levels .. '" \\h \\z \\u </w:instrText></w:r>'
    .. '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
end
local FIELD_END = '<w:r><w:fldChar w:fldCharType="end"/></w:r>'

-- The paragraph inside an entry (entries arrive as styled divs).
local function entry_para(block)
  if block.t == 'Div' and block.content[1] then return block.content[1] end
  return block
end

-- The table of contents: Word's TOC field around the document's own entries
-- (so it shows before Word refreshes it), or a placeholder without entries.
local function toc_blocks(title, entries)
  local blocks = pandoc.List()
  if toc_break_before then blocks:insert(pandoc.RawBlock('openxml', PAGE_BREAK)) end
  blocks:insert(pandoc.RawBlock('openxml', SDT_OPEN .. escape_title(title)))
  if #entries == 0 then
    blocks:insert(pandoc.RawBlock('openxml', '<w:p>' .. field_begin()
      .. '<w:r><w:t>Right-click here and choose Update Field to show the table of contents.</w:t></w:r>' .. FIELD_END .. '</w:p>'))
  else
    local first = entry_para(entries[1])
    if first.content then first.content:insert(1, pandoc.RawInline('openxml', field_begin())) end
    local last = entry_para(entries[#entries])
    if last.content then last.content:insert(pandoc.RawInline('openxml', FIELD_END)) end
    blocks:extend(entries)
  end
  blocks:insert(pandoc.RawBlock('openxml', SDT_CLOSE))
  if toc_break_after then blocks:insert(pandoc.RawBlock('openxml', PAGE_BREAK)) end
  return blocks
end

local function block_text(block)
  if block.t == 'Para' or block.t == 'Plain' then return pandoc.utils.stringify(block) end
  return ''
end

-- Replace the marked table of contents (start marker, entries, end marker).
function Pandoc(doc)
  local out = pandoc.List()
  local blocks = doc.blocks
  local i = 1
  while i <= #blocks do
    local text = block_text(blocks[i])
    if text:sub(1, #MARKER) == MARKER then
      local entries = pandoc.List()
      local j = i + 1
      while j <= #blocks and block_text(blocks[j]) ~= END_MARKER do
        entries:insert(blocks[j])
        j = j + 1
      end
      out:extend(toc_blocks(text:sub(#MARKER + 1), entries))
      i = j + 1
    else
      out:insert(blocks[i])
      i = i + 1
    end
  end
  doc.blocks = out
  return doc
end

function Header(el)
  if el.level == 1 then
    return pandoc.Div({ pandoc.Para(el.content) }, { ['custom-style'] = 'Title' })
  end
  el.level = el.level - 1
  return el
end

-- Underlined text (Typst's underline, e.g. on links) arrives as a styled span.
function Span(el)
  local style = el.attributes['style'] or ''
  if style:find('text%-decoration:%s*underline') then
    return pandoc.Underline(el.content)
  end
end

function Meta(meta)
  meta.title = nil
  meta.subtitle = nil
  meta.author = nil
  meta.date = nil
  meta.abstract = nil
  return meta
end

-- Cells carry their background colour and vertical alignment as attributes
-- (data-tl-fill, data-tl-valign); pandoc can't express those, so leave marker
-- runs that server/docx.js turns into real Word cell properties. Tables carry
-- their column widths and padding (data-tl-table), and side-by-side layouts
-- (Typst grids) are marked as such (data-tl-layout), both in the first cell.
local function attr(el, name)
  return el.attributes['data-' .. name] or el.attributes[name]
end

local function prepend(cell, xml)
  local marker = pandoc.RawInline('openxml', xml)
  local first = cell.contents[1]
  if first and (first.t == 'Plain' or first.t == 'Para') then
    first.content:insert(1, marker)
  else
    cell.contents:insert(1, pandoc.Plain({ marker }))
  end
end

local function mark_cell(cell)
  local fill = attr(cell, 'tl-fill')
  local valign = attr(cell, 'tl-valign')
  local align = cell.attributes['align']
  if align == 'center' then
    cell.alignment = pandoc.AlignCenter
  elseif align == 'right' then
    cell.alignment = pandoc.AlignRight
  end
  if fill or valign then
    prepend(cell, '<w:r><w:t>TLCELL' .. (fill and fill:upper() or '') .. '|' .. (valign or '') .. '</w:t></w:r>')
  end
end

local function first_cell(tbl)
  local row = tbl.head.rows[1] or (tbl.bodies[1] and (tbl.bodies[1].head[1] or tbl.bodies[1].body[1]))
  return row and row.cells[1]
end

function Table(tbl)
  local cell = first_cell(tbl)
  local layout = attr(tbl, 'tl-layout')
  local props = attr(tbl, 'tl-table')
  local function rows(list)
    for _, row in ipairs(list) do
      for _, c in ipairs(row.cells) do mark_cell(c) end
    end
  end
  rows(tbl.head.rows)
  for _, body in ipairs(tbl.bodies) do
    rows(body.head)
    rows(body.body)
  end
  rows(tbl.foot.rows)
  if cell and layout then prepend(cell, '<w:r><w:t>TLLAYOUT' .. layout .. '</w:t></w:r>') end
  if cell and props then prepend(cell, '<w:r><w:t>TLTABLE' .. props .. '</w:t></w:r>') end
  return tbl
end
