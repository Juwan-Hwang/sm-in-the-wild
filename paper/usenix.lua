-- pandoc Lua filter: docs/paper.md -> body for the USENIX two-column template.
--
-- * the H1 title and the "Anonymous submission" line become \title / \author;
-- * "## Abstract" becomes the abstract environment;
-- * headings keep the manual numbers the text cross-references (§6.6, Appendix B.3),
--   so they are emitted unnumbered, one level up (## -> \section, ### -> \subsection);
-- * a "**Table N.** ..." paragraph followed by a pipe table becomes one float whose
--   caption is that paragraph; wide tables become table*, narrow ones table;
-- * the "**Figure 1.**" paragraph after the ASCII funnel becomes a figure* with it;
-- * \FloatBarrier + \label{bodyend} is inserted before "References" so the
--   page count of the body includes every body float; labels also mark where the
--   references and the optional appendices start;
-- * long monospace identifiers may break after . / _ so they fit a 3.3-inch column.

local stringify = pandoc.utils.stringify
local breakcode

local function latex(blocks)
  local d = pandoc.Pandoc(blocks)
  if breakcode then d = d:walk({Code = breakcode}) end
  return pandoc.write(d, 'latex', {wrap_text = 'none'})
end

local function inl(inlines)
  return (latex({pandoc.Plain(inlines)}):gsub('\n', ' '))
end

breakcode = function(c)
  if #c.text <= 14 then return nil end
  local s = pandoc.write(pandoc.Pandoc({pandoc.Plain({c})}), 'latex'):gsub('\n', '')
  s = s:gsub('([%./])', '%1\\allowbreak{}'):gsub('(\\_)', '%1\\allowbreak{}')
  return pandoc.RawInline('latex', s)
end

local function starts_with_strong(blk, prefix)
  if blk and blk.t == 'Para' and blk.content[1] and blk.content[1].t == 'Strong' then
    return stringify(blk.content[1]):match('^' .. prefix) ~= nil
  end
  return false
end

local function is_numeric_col(tbl, j)
  local n, num = 0, 0
  for _, b in ipairs(tbl.bodies) do
    for _, r in ipairs(b.body) do
      local c = r.cells[j]
      if c then
        local s = stringify(c.contents)
        if s ~= '' then
          n = n + 1
          if #s <= 14 and s:match('^[%*%s%d%.,%%%(%)/=<>~+%-nNaA]*$') then num = num + 1 end
        end
      end
    end
  end
  return n > 0 and num == n
end

local function table_tex(tbl, caption_blk, placement)
  local ncols = #tbl.colspecs
  local maxlen = {}
  for j = 1, ncols do maxlen[j] = 0 end
  local function scan(r)
    for j, c in ipairs(r.cells) do
      local l = #stringify(c.contents)
      if l > maxlen[j] then maxlen[j] = l end
    end
  end
  for _, r in ipairs(tbl.head.rows) do scan(r) end
  for _, b in ipairs(tbl.bodies) do for _, r in ipairs(b.body) do scan(r) end end
  local total = 0
  for j = 1, ncols do total = total + math.min(maxlen[j], 70) end
  local wide = ncols >= 5 or total > 95
  local spec = {}
  for j = 1, ncols do
    local align = tbl.colspecs[j][1]
    if is_numeric_col(tbl, j) or align == 'AlignRight' then
      table.insert(spec, align == 'AlignLeft' and 'l' or 'r')
    elseif maxlen[j] <= 14 then
      table.insert(spec, 'l')
    else
      table.insert(spec, '>{\\raggedright\\arraybackslash}X')
    end
  end
  local has_x = false
  for _, s in ipairs(spec) do if s:match('X') then has_x = true end end
  if not has_x then
    local best, bj = -1, 1
    for j = 1, ncols do
      if maxlen[j] > best and not is_numeric_col(tbl, j) then best, bj = maxlen[j], j end
    end
    spec[bj] = '>{\\raggedright\\arraybackslash}X'
  end
  local rows = {}
  local function addrow(r)
    local cells = {}
    for _, c in ipairs(r.cells) do
      table.insert(cells, (latex(c.contents):gsub('\n+', ' '):gsub('%s+$', '')))
    end
    for _ = #cells + 1, ncols do table.insert(cells, '') end
    table.insert(rows, table.concat(cells, ' & ') .. ' \\\\')
  end
  for _, r in ipairs(tbl.head.rows) do
    local nonempty = false
    for _, c in ipairs(r.cells) do if stringify(c.contents) ~= '' then nonempty = true end end
    if nonempty then addrow(r) end
  end
  local nhead = #rows
  for _, b in ipairs(tbl.bodies) do for _, r in ipairs(b.body) do addrow(r) end end
  local env = wide and 'table*' or 'table'
  local width = wide and '\\textwidth' or '\\columnwidth'
  local out = {}
  table.insert(out, '\\begin{' .. env .. '}[' .. (placement or (wide and 'tp' or 'tbp')) .. ']\\footnotesize')
  if caption_blk then
    table.insert(out, '\\noindent\\parbox{' .. width .. '}{' .. inl(caption_blk.content) .. '}\\par\\smallskip')
  end
  table.insert(out, '\\noindent\\begin{tabularx}{' .. width .. '}{@{}' .. table.concat(spec) .. '@{}}')
  table.insert(out, '\\toprule')
  for i = 1, nhead do table.insert(out, rows[i]) end
  if nhead > 0 then table.insert(out, '\\midrule') end
  for i = nhead + 1, #rows do table.insert(out, rows[i]) end
  table.insert(out, '\\bottomrule')
  table.insert(out, '\\end{tabularx}')
  table.insert(out, '\\end{' .. env .. '}')
  return pandoc.RawBlock('latex', table.concat(out, '\n'))
end

local function verbatim(code, size)
  return '\\begin{Verbatim}[breaklines,breakanywhere,fontsize=' .. (size or '\\scriptsize') .. ']\n'
    .. code .. '\n\\end{Verbatim}'
end

local function whole(doc)
  local out = pandoc.List()
  local title, author = nil, 'Anonymous submission'
  local blocks = doc.blocks
  local i = 1
  local in_abstract = false
  while i <= #blocks do
    local b = blocks[i]
    local nxt = blocks[i + 1]
    if b.t == 'Header' and b.level == 1 and not title then
      title = inl(b.content)
    elseif b.t == 'Para' and #b.content == 1 and b.content[1].t == 'Emph'
        and stringify(b.content[1]):match('^Anonymous submission') then
      author = inl(b.content[1].content)
    elseif b.t == 'Header' and b.level == 2 and stringify(b.content) == 'Abstract' then
      in_abstract = true
      out:insert(pandoc.RawBlock('latex', '\\begin{abstract}'))
    elseif b.t == 'Header' then
      local name = stringify(b.content)
      if in_abstract then
        out:insert(pandoc.RawBlock('latex', '\\end{abstract}'))
        in_abstract = false
      end
      if b.level == 2 and name == 'References' then
        out:insert(pandoc.RawBlock('latex', '\\FloatBarrier\\label{bodyend}\\label{refsstart}'))
      end
      if b.level == 2 and name:match('^Appendix A') then
        out:insert(pandoc.RawBlock('latex', '\\FloatBarrier\\label{appstart}'))
      end
      if b.level == 2 and (name == 'Ethical Considerations' or name == 'Open Science') then
        out:insert(pandoc.RawBlock('latex', '\\clearpage'))
      end
      local cmd = ({[2] = 'section', [3] = 'subsection', [4] = 'subsubsection'})[b.level] or 'paragraph'
      out:insert(pandoc.RawBlock('latex', '\\' .. cmd .. '*{' .. inl(b.content) .. '}'))
      if b.level == 2 and name == 'Ethical Considerations' then
        out:insert(pandoc.RawBlock('latex', '\\label{ethicsstart}'))
      end
    elseif b.t == 'Div' and b.attributes and b.attributes['data-placement'] then
      -- fenced Div override: ::: {data-placement="H"} around a caption + pipe table
      -- pins that one float (used where [tbp] would lift a table above its own
      -- section heading in column reading order, e.g. Table 19 in Appendix J)
      local pl = b.attributes['data-placement']
      local bs2, j = b.content, 1
      while j <= #bs2 do
        local bb, nx2 = bs2[j], bs2[j + 1]
        if starts_with_strong(bb, 'Table %d+%.') and nx2 and nx2.t == 'Table' then
          out:insert(table_tex(nx2, bb, pl))
          j = j + 1
        else
          out:insert(bb)
        end
        j = j + 1
      end
    elseif starts_with_strong(b, 'Table %d+%.') and nxt and nxt.t == 'Table' then
      out:insert(table_tex(nxt, b))
      i = i + 1
    elseif b.t == 'Table' then
      out:insert(table_tex(b, nil))
    elseif starts_with_strong(b, 'Figure %d+%.') then
      -- a figure caption without a preceding code block embeds the vector figure
      out:insert(pandoc.RawBlock('latex', '\\begin{figure*}[tp]\n\\centering\\includegraphics[width=\\textwidth]{funnel.pdf}' ..
        '\n\\par\\smallskip\\footnotesize\\noindent ' .. inl(b.content) .. '\n\\end{figure*}'))
    elseif b.t == 'CodeBlock' then
      local j = i + 1
      while blocks[j] and blocks[j].t == 'RawBlock' do j = j + 1 end
      if starts_with_strong(blocks[j], 'Figure %d+%.') then
        out:insert(pandoc.RawBlock('latex', '\\begin{figure*}[tp]\n' .. verbatim(b.text, '\\footnotesize') ..
          '\n\\par\\smallskip\\footnotesize\\noindent ' .. inl(blocks[j].content) .. '\n\\end{figure*}'))
        i = j
      else
        out:insert(pandoc.RawBlock('latex', verbatim(b.text)))
      end
    elseif b.t == 'RawBlock' and b.format == 'html' then
      -- HTML comments carry nothing for the PDF
    else
      out:insert(b)
    end
    i = i + 1
  end
  if in_abstract then out:insert(pandoc.RawBlock('latex', '\\end{abstract}')) end
  doc.blocks = out
  doc.meta.title = pandoc.MetaInlines({pandoc.RawInline('latex', title or '')})
  doc.meta.author = pandoc.MetaInlines({pandoc.RawInline('latex', author)})
  return doc
end

return {{Pandoc = function(doc) doc = whole(doc); return doc:walk({Code = breakcode}) end}}
