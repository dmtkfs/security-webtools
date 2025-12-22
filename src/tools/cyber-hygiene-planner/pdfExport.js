import { jsPDF } from 'jspdf'

const PAGE_BG = '#ffffff'
const TEXT = '#0f172a'
const MUTED = '#475569'
const BORDER = '#e2e8f0'
const ACCENT = '#10b981'

const PRI_TEXT = {
  High: '#9f1239',
  Medium: '#92400e',
  Low: '#065f46',
}

const MARGIN_X = 14
const TOP = 18
const FOOTER_H = 12
const BOTTOM_PAD = 10

const TYPE = {
  h1: 16,
  h2: 12.8,
  h3: 11.2,
  actionTitle: 10.3,
  body: 9.5,
  small: 9,
  tiny: 8.5,
}

const LEAD = {
  body: 4.9,
  small: 4.7,
  tiny: 4.4,
}

// utils 
function safeText(v) { return v == null ? '' : String(v) }

function fmtDate(iso) {
  try {
    const d = new Date(iso)
    return d.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return String(iso || '')
  }
}

function mkFilename(report, suffix) {
  const d = new Date().toISOString().slice(0, 10)
  const p = safeText(report?.selectedProfileId || 'profile')
  const v = safeText(report?.selectedVerticalId || 'context')
  return `cyber-hygiene_${p}_${v}_${suffix}_${d}.pdf`
}

function pageW(pdf) { return pdf.internal.pageSize.getWidth() }
function pageH(pdf) { return pdf.internal.pageSize.getHeight() }
function contentW(pdf) { return pageW(pdf) - MARGIN_X * 2 }
function contentBottom(pdf) { return pageH(pdf) - FOOTER_H - BOTTOM_PAD }

// page theme
function setPageTheme(pdf) {
  const w = pageW(pdf)
  const h = pageH(pdf)
  pdf.setFillColor(PAGE_BG)
  pdf.rect(0, 0, w, h, 'F')
  pdf.setTextColor(TEXT)
}

function footer(pdf, pageNo, pageCount) {
  const w = pageW(pdf)
  const h = pageH(pdf)

  pdf.setFont('helvetica', 'normal')
  pdf.setFontSize(TYPE.tiny)
  pdf.setTextColor('#64748b')

  const left = 'Security Webtools - Cyber Hygiene Planner (local-first)'
  const right = `Page ${pageNo}/${pageCount}`

  const y = h - 7
  pdf.text(left, MARGIN_X, y)
  const rw = pdf.getTextWidth(right)
  pdf.text(right, w - MARGIN_X - rw, y)

  pdf.setTextColor(TEXT)
}

// flow helpers
function ensureSpace(pdf, y, need) {
  if (y + need <= contentBottom(pdf)) return y
  pdf.addPage()
  setPageTheme(pdf)
  return TOP
}

function wrapLines(pdf, text, maxW) {
  return pdf.splitTextToSize(safeText(text), maxW)
}

// horizontal lines for major section separation
function sectionDivider(pdf, y) {
  const w = pageW(pdf)
  y = ensureSpace(pdf, y, 10)
  y += 6
  pdf.setDrawColor(BORDER)
  pdf.setLineWidth(0.35)
  pdf.line(MARGIN_X, y, w - MARGIN_X, y)
  return y + 6
}

// text primitives
function para(pdf, y, text, opts = {}) {
  const maxW = opts.maxW ?? contentW(pdf)
  const size = opts.size ?? TYPE.body
  const leading = opts.leading ?? LEAD.body
  const color = opts.color ?? MUTED
  const x = opts.x ?? MARGIN_X

  const lines = wrapLines(pdf, text, maxW)

  pdf.setFont('helvetica', 'normal')
  pdf.setFontSize(size)
  pdf.setTextColor(color)

  for (const line of lines) {
    y = ensureSpace(pdf, y, leading + 1)
    pdf.text(line, x, y)
    y += leading
  }

  pdf.setTextColor(TEXT)
  return y + 2
}

function bulletList(pdf, y, items, opts = {}) {
  if (!Array.isArray(items) || items.length === 0) return y

  const x = opts.x ?? MARGIN_X
  const maxW = opts.maxW ?? (contentW(pdf) - 10)
  const maxItems = opts.maxItems ?? Infinity
  const size = opts.size ?? TYPE.small
  const color = opts.color ?? MUTED
  const lineH = opts.lineH ?? LEAD.small
  const itemGap = opts.itemGap ?? 1.2

  const dotX = x
  const textX = x + 6

  pdf.setFont('helvetica', 'normal')
  pdf.setFontSize(size)
  pdf.setTextColor(color)

  for (const it of items.slice(0, maxItems)) {
    const lines = wrapLines(pdf, it, maxW)

    y = ensureSpace(pdf, y, lineH + 2)
    pdf.text('•', dotX, y)

    let first = true
    for (const line of lines) {
      if (!first) y = ensureSpace(pdf, y, lineH + 2)
      pdf.text(line, textX, y)
      y += lineH
      first = false
    }

    y += itemGap
  }

  pdf.setTextColor(TEXT)
  return y + 2
}

// headers
function heading1(pdf, title, meta) {
  let y = TOP
  const maxW = contentW(pdf)

  pdf.setFont('helvetica', 'bold')
  pdf.setFontSize(TYPE.h1)
  pdf.setTextColor(TEXT)

  const titleLines = wrapLines(pdf, title, maxW)
  for (const line of titleLines) {
    y = ensureSpace(pdf, y, 8)
    pdf.text(line, MARGIN_X, y)
    y += 7
  }

  // underline accent
  y = ensureSpace(pdf, y, 6)
  pdf.setDrawColor(ACCENT)
  pdf.setLineWidth(1.2)
  pdf.line(MARGIN_X, y, MARGIN_X + 34, y)
  pdf.setDrawColor(BORDER)
  pdf.setLineWidth(0.3)
  y += 6

  if (meta) {
    pdf.setFont('helvetica', 'normal')
    pdf.setFontSize(TYPE.small)
    pdf.setTextColor(MUTED)

    const metaLines = wrapLines(pdf, meta, maxW)
    for (const line of metaLines) {
      y = ensureSpace(pdf, y, 6)
      pdf.text(line, MARGIN_X, y)
      y += 5
    }
    pdf.setTextColor(TEXT)
  }

  return y + 8
}

// major section header
function majorSection(pdf, y, title, subtitle, opts = {}) {
      const preGap = opts.preGap ?? 10
      const need = preGap + (subtitle ? 24 : 18)
      y = ensureSpace(pdf, y, need)
      y += preGap

  // title
  pdf.setFont('helvetica', 'bold')
  pdf.setFontSize(TYPE.h2)
  pdf.setTextColor(TEXT)
  pdf.text(safeText(title), MARGIN_X, y)
  y += 4.8

  // underline accent
  y = ensureSpace(pdf, y, 6)
  pdf.setDrawColor(ACCENT)
  pdf.setLineWidth(1.2)
  pdf.line(MARGIN_X, y, MARGIN_X + 26, y)
  pdf.setDrawColor(BORDER)
  pdf.setLineWidth(0.3)
  y += 6

  // subtitle
  if (subtitle) {
    pdf.setFont('helvetica', 'normal')
    pdf.setFontSize(TYPE.small)
    pdf.setTextColor(MUTED)

    const lines = wrapLines(pdf, subtitle, contentW(pdf))
    for (const line of lines) {
      y = ensureSpace(pdf, y, 6)
      pdf.text(line, MARGIN_X, y)
      y += 5
    }
    y += 2
  }

  pdf.setTextColor(TEXT)

  // single divider
  return sectionDivider(pdf, y)
}

// action family header
function familyHeader(pdf, y, title, count) {
  const bandH = 16
  y = ensureSpace(pdf, y, bandH + 8)

  y += 6 

  pdf.setFillColor('#f8fafc')
  pdf.rect(MARGIN_X, y - 10, contentW(pdf), bandH, 'F')

  // left accent bar
  pdf.setFillColor(ACCENT)
  pdf.rect(MARGIN_X, y - 10, 2.2, bandH, 'F')

  // title
  pdf.setFont('helvetica', 'bold')
  pdf.setFontSize(TYPE.h3)
  pdf.setTextColor(TEXT)
  pdf.text(safeText(title), MARGIN_X + 6, y)

  // count
  pdf.setFont('helvetica', 'normal')
  pdf.setFontSize(TYPE.small)
  pdf.setTextColor(MUTED)
  const right = `${count} action${count === 1 ? '' : 's'}`
  const rw = pdf.getTextWidth(right)
  pdf.text(right, MARGIN_X + contentW(pdf) - rw - 2, y)

  pdf.setTextColor(TEXT)

  return y + 14
}

// blocks
function renderOverview(pdf, report, y) {
  y = majorSection(pdf, y, 'Overview', 'Your context + snapshot')

  const profile = report.selectedProfile?.title || report.selectedProfileId || '-'
  const vertical = report.selectedVertical?.title || report.selectedVerticalId || '-'
  y = para(pdf, y, `Profile: ${safeText(profile)}   ·   Context: ${safeText(vertical)}`, {
    color: TEXT,
    size: TYPE.body,
    leading: LEAD.body,
  })

  y = majorSection(pdf, y, 'Guidance', report.guidance?.title ? '' : 'Baseline recommendations')
  if (report.guidance?.title) {
    y = para(pdf, y, report.guidance.title, { color: TEXT, size: TYPE.body, leading: 5.2 })
  }
  if (report.guidance?.body) {
    y = para(pdf, y, report.guidance.body, { color: MUTED, size: TYPE.body, leading: LEAD.body })
  }

  y = majorSection(pdf, y, 'Domain snapshot', 'Score and tier by domain')

  const ds = report.domainSnapshot || {}
  const rows = Object.values(ds)

  if (!rows.length) {
    y = para(pdf, y, 'No domain data.')
  } else {
    const maxW = contentW(pdf)
    for (const d of rows) {
      y = ensureSpace(pdf, y, 10)

      pdf.setFont('helvetica', 'bold')
      pdf.setFontSize(TYPE.small)
      pdf.setTextColor(TEXT)
      const left = safeText(d.title)
      pdf.text(left, MARGIN_X, y)

      pdf.setFont('helvetica', 'normal')
      pdf.setFontSize(TYPE.small)
      pdf.setTextColor(MUTED)
      const right = `${safeText(d.score)}/100 · ${safeText(d.tier)}`
      const rw = pdf.getTextWidth(right)

      if (pdf.getTextWidth(left) + rw + 10 > maxW) {
        y += 5.2
        y = ensureSpace(pdf, y, 6)
        pdf.text(right, MARGIN_X, y)
      } else {
        pdf.text(right, MARGIN_X + maxW - rw, y)
      }

      pdf.setTextColor(TEXT)
      y += 7
    }
  }

  // disclaimer
  y = ensureSpace(pdf, y, 10)
  pdf.setFont('helvetica', 'normal')
  pdf.setFontSize(TYPE.tiny)
  pdf.setTextColor('#64748b')
  pdf.text('Disclaimer: checklist-based planner, not a compliance audit or guarantee of security.', MARGIN_X, y)
  pdf.setTextColor(TEXT)

  return y + 6
}

// major section dividers
function renderOneAction(pdf, y, index, a, { maxSteps = 6, maxRefs = 3 } = {}) {
  const maxW = contentW(pdf)
  const indent = 4
  const x0 = MARGIN_X + indent

  y = ensureSpace(pdf, y, 14)

  // title
  const pri = safeText(a.priority || 'Low')
  const priColor = PRI_TEXT[pri] || PRI_TEXT.Low
  const priTag = `(${pri})`

  pdf.setFont('helvetica', 'bold')
  pdf.setFontSize(TYPE.actionTitle)
  pdf.setTextColor(TEXT)

  const reserve = 30
  const baseTitle = `${index}. ${safeText(a.title)}`
  const titleLines = wrapLines(pdf, baseTitle, Math.max(60, maxW - reserve))

  pdf.text(titleLines[0] || baseTitle, MARGIN_X + indent, y)

  pdf.setFont('helvetica', 'bold')
  pdf.setFontSize(TYPE.small)
  pdf.setTextColor(priColor)
  const priW = pdf.getTextWidth(priTag)
  pdf.text(priTag, MARGIN_X + maxW - priW, y)

  pdf.setTextColor(TEXT)
  pdf.setFont('helvetica', 'bold')
  pdf.setFontSize(TYPE.actionTitle)

  y += 6.0
  for (const line of titleLines.slice(1)) {
    y = ensureSpace(pdf, y, 7)
    pdf.text(line, MARGIN_X + indent, y)
    y += 6.0
  }

  // meta
  const meta = `Effort: ${safeText(a.effort)} · Who: ${safeText(a.execution)}`
  y = para(pdf, y, meta, { size: TYPE.small, color: MUTED, leading: LEAD.small, x: x0, maxW: contentW(pdf) - indent, })

  // why
  if (a.why) {
    y = para(pdf, y, safeText(a.why), { size: TYPE.small, color: MUTED, leading: LEAD.small, x: x0, maxW: contentW(pdf) - indent, })
  }

  // first steps
  y = ensureSpace(pdf, y, 8)
  pdf.setFont('helvetica', 'bold')
  pdf.setFontSize(TYPE.small)
  pdf.setTextColor(TEXT)
  pdf.text('First steps:', MARGIN_X + indent, y)
  y += 5

  y = bulletList(pdf, y, (a.firstSteps || []).slice(0, maxSteps), {
    x: MARGIN_X + indent + 2,
    maxW: maxW - (indent + 8),
    size: TYPE.small,
    color: MUTED,
    lineH: LEAD.small,
    itemGap: 1.2,
  })

  // references
  const refs = (a.references || []).slice(0, maxRefs)
  if (refs.length) {
    y = ensureSpace(pdf, y, 8)
    pdf.setFont('helvetica', 'bold')
    pdf.setFontSize(TYPE.small)
    pdf.setTextColor(TEXT)
    pdf.text('References:', MARGIN_X + indent, y)
    y += 5

    const refLines = refs.map((r) => `${safeText(r.label)}: ${safeText(r.url)}`)
    y = bulletList(pdf, y, refLines, {
      x: MARGIN_X + indent + 2,
      maxW: maxW - (indent + 8),
      size: TYPE.tiny,
      color: '#334155',
      lineH: LEAD.tiny,
      itemGap: 1.1,
    })
  }

  return y + 6
}

function renderQuickWins(pdf, report, y) {
  y = majorSection(pdf, y, 'Quick wins', 'Top actions (prioritized for your context)')

  const items = report.quickWins || []
  if (!items.length) {
    y = para(pdf, y, 'No quick wins were generated by this checklist.')
    return y + 2
  }

  for (let i = 0; i < items.length; i++) {
    y = renderOneAction(pdf, y, i + 1, items[i], { maxSteps: 6, maxRefs: 3 })
  }

  return y + 2
}

function renderPlan(pdf, report, y) {
  y = majorSection(pdf, y, 'Full plan', 'Grouped by domain and prioritized for your context', { preGap: 6 })

  const byDomain = report.actionPlanByDomain || {}
  const domainOrder = Object.keys(byDomain)
  if (!domainOrder.length) {
    y = para(pdf, y, 'No actions were triggered.')
    return y + 6
  }

  for (const domainId of domainOrder) {
    const items = byDomain[domainId] || []
    const domainTitle = report.domainSnapshot?.[domainId]?.title || domainId

    // action family/domain header
    y = familyHeader(pdf, y, domainTitle, items.length)

    if (!items.length) {
      y = para(pdf, y, 'No actions triggered in this domain.', { size: TYPE.small, color: MUTED, leading: LEAD.small })
      y += 6
      continue
    }

    let idx = 1
    for (const a of items) {
      y = renderOneAction(pdf, y, idx, a, { maxSteps: 6, maxRefs: 2 })
      idx++
    }

    y += 4
  }

  // disclaimer
  y = ensureSpace(pdf, y, 10)
  pdf.setFont('helvetica', 'normal')
  pdf.setFontSize(TYPE.tiny)
  pdf.setTextColor('#64748b')
  pdf.text('Disclaimer: checklist-based planner, not a compliance audit or guarantee of security.', MARGIN_X, y)
  pdf.setTextColor(TEXT)

  return y + 6
}

function renderBlock(pdf, report, blockId, y) {
  if (blockId === 'overview') return renderOverview(pdf, report, y)
  if (blockId === 'quickWins') return renderQuickWins(pdf, report, y)
  if (blockId === 'plan') return renderPlan(pdf, report, y)
  return para(pdf, y, `Unknown block: ${blockId}`, { color: MUTED })
}

// public
export function exportReportPDF(report, { blocks = ['overview', 'quickWins', 'plan'] } = {}) {
  if (!report) return false

  const pdf = new jsPDF('p', 'mm', 'a4')
  setPageTheme(pdf)

  const meta = `Generated: ${fmtDate(report.generatedAt)}`
  let y = heading1(pdf, 'Cyber Hygiene Planner - Action Plan', meta)

  for (const blockId of blocks) {
    y = renderBlock(pdf, report, blockId, y)
  }

  const total = pdf.getNumberOfPages()
  for (let p = 1; p <= total; p++) {
    pdf.setPage(p)
    footer(pdf, p, total)
  }

  pdf.save(mkFilename(report, 'full'))
  return true
}

export function exportBlockPDF(report, blockId) {
  if (!report) return false

  const pdf = new jsPDF('p', 'mm', 'a4')
  setPageTheme(pdf)

  const meta = `Generated: ${fmtDate(report.generatedAt)}`
  let y = heading1(pdf, 'Cyber Hygiene Planner - Action Plan', meta)

  renderBlock(pdf, report, blockId, y)

  const total = pdf.getNumberOfPages()
  for (let p = 1; p <= total; p++) {
    pdf.setPage(p)
    footer(pdf, p, total)
  }

  pdf.save(mkFilename(report, safeText(blockId)))
  return true
}
