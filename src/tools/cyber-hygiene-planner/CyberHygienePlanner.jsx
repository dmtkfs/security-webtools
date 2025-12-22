import React, { useEffect, useMemo, useRef, useState } from 'react'
import AboutSection from '../../components/AboutSection.jsx'
import { downloadTextFile } from '../../utils/exportUtils.js'
import {
  PROFILES,
  VERTICALS,
  SECTIONS,
  QUESTIONS,
  ACTIONS,
  PRIORITY_ORDER,
} from './questions.js'

import { exportReportPDF, exportBlockPDF } from './pdfExport.js'

// Evidence formatting (shared)
const QUESTION_BY_ID = Object.fromEntries(QUESTIONS.map((q) => [q.id, q]))

function optionLabel(q, value) {
  if (!q?.options) return String(value ?? '')
  const hit = q.options.find((o) => o.value === value)
  return hit?.label ?? String(value ?? '')
}

function questionLabel(q) {
  return q?.prompt ?? q?.title ?? q?.text ?? q?.id ?? 'Question'
}

function formatEvidence(evidence = []) {
  const out = []
  for (const ev of evidence) {
    const q = QUESTION_BY_ID[ev.questionId]
    const qName = questionLabel(q)

    if (ev.selectedValue != null) {
      out.push(`${qName} → Selected: ${optionLabel(q, ev.selectedValue)}`)
    } else if (ev.missingValue != null) {
      out.push(`${qName} → Missing: ${optionLabel(q, ev.missingValue)}`)
    } else {
      out.push(`${qName}`)
    }
  }
  // de-dupe
  return Array.from(new Set(out))
}

// Small helpers
function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n))
}

function isoNow() {
  return new Date().toISOString()
}

function scoreToTier(score) {
  if (score >= 70) return 'Strong'
  if (score >= 40) return 'Developing'
  return 'Basic'
}

function priorityPill(priority) {
  if (priority === 'High')
    return 'bg-rose-500/10 text-rose-200 border border-rose-500/30'
  if (priority === 'Medium')
    return 'bg-amber-500/10 text-amber-200 border border-amber-500/30'
  return 'bg-emerald-500/10 text-emerald-200 border border-emerald-500/30'
}

function metaPillBase() {
  return 'text-[0.65rem] px-2 py-0.5 rounded-full border'
}

function effortPill(effort) {
  if (effort === 'High')
    return `${metaPillBase()} bg-rose-500/10 text-rose-200 border-rose-500/30`
  if (effort === 'Medium')
    return `${metaPillBase()} bg-amber-500/10 text-amber-200 border-amber-500/30`
  return `${metaPillBase()} bg-emerald-500/10 text-emerald-200 border-emerald-500/30`
}

function executionPill(execution) {
  const base = metaPillBase()

  if (execution === 'Professional') {
    return `${base} bg-amber-500/10 text-amber-200 border-amber-500/30`
  }

  if (execution === 'IT Support') {
    return `${base} bg-sky-500/10 text-sky-200 border-sky-500/30`
  }

  return `${base} bg-slate-900/70 text-slate-200 border-slate-700`
}

// Engine helpers (data-driven)
function getApplicableSections(profileId) {
  return SECTIONS.filter((s) => s.appliesTo.includes(profileId))
}

function isQuestionVisible(q, profileId, answers) {
  if (!q.appliesTo.includes(profileId)) return false
  if (!q.dependsOn) return true

  const dep = q.dependsOn
  const ans = answers?.[dep.questionId]
  if (ans == null) return false

  if (Array.isArray(ans)) return ans.some((v) => dep.anyOf.includes(v))
  return dep.anyOf.includes(ans)
}

function getVisibleQuestionsForSection(profileId, sectionId, answers) {
  return QUESTIONS.filter(
    (q) => q.sectionId === sectionId && isQuestionVisible(q, profileId, answers),
  )
}

function isAnswered(q, answers) {
  const a = answers[q.id]
  if (q.type === 'radio') return typeof a === 'string' && a.length > 0
  if (q.type === 'checkbox') return Array.isArray(a)
  return false
}

function computeDomainScores(profileId, answers) {
  const sections = getApplicableSections(profileId)

  const bySection = {}
  for (const s of sections) {
    const visibleQs = getVisibleQuestionsForSection(profileId, s.id, answers)

    let earned = 0
    let possible = 0

    for (const q of visibleQs) {
      if (q.type === 'radio') {
        const maxPts = Math.max(...q.options.map((o) => o.points ?? 0))
        possible += maxPts

        const selected = answers[q.id]
        const opt = q.options.find((o) => o.value === selected)
        earned += opt?.points ?? 0
      }

      if (q.type === 'checkbox') {
        const sumPts = q.options.reduce((acc, o) => acc + (o.points ?? 0), 0)
        possible += sumPts

        const selectedArr = Array.isArray(answers[q.id]) ? answers[q.id] : []
        for (const opt of q.options) {
          if (selectedArr.includes(opt.value)) earned += opt.points ?? 0
        }
      }
    }

    const score = possible > 0 ? Math.round((earned / possible) * 100) : 0
    bySection[s.id] = {
      sectionId: s.id,
      title: s.title,
      score: clamp(score, 0, 100),
      tier: scoreToTier(score),
    }
  }

  return bySection
}

function buildActionPlan(profileId, verticalId, answers) {
  const sections = getApplicableSections(profileId)
  const actionById = Object.fromEntries(ACTIONS.map((a) => [a.id, a]))

  const triggered = new Map()

  for (const s of sections) {
    const visibleQs = getVisibleQuestionsForSection(profileId, s.id, answers)

    for (const q of visibleQs) {
      if (q.type === 'radio') {
        const selected = answers[q.id]
        const opt = q.options.find((o) => o.value === selected)
        const triggersOnSelect = opt?.triggersOnSelect ?? []
        const riskBoost = opt?.riskBoost ?? 0

        for (const actionId of triggersOnSelect) {
          if (!actionById[actionId]) continue
          const prev = triggered.get(actionId) || { boost: 0, evidence: [] }
          triggered.set(actionId, {
            boost: prev.boost + riskBoost,
            evidence: [
              ...prev.evidence,
              { questionId: q.id, selectedValue: selected },
            ],
          })
        }
      }

      if (q.type === 'checkbox') {
        const selectedArr = Array.isArray(answers[q.id]) ? answers[q.id] : []

        for (const opt of q.options) {
          for (const actionId of opt.triggersOnSelect ?? []) {
            if (!actionById[actionId]) continue
            const prev = triggered.get(actionId) || { boost: 0, evidence: [] }
            triggered.set(actionId, {
              boost: prev.boost + (opt.riskBoost ?? 0),
              evidence: [
                ...prev.evidence,
                { questionId: q.id, selectedValue: opt.value },
              ],
            })
          }

          if (!selectedArr.includes(opt.value)) {
            for (const actionId of opt.triggersOnMissing ?? []) {
              if (!actionById[actionId]) continue
              const prev = triggered.get(actionId) || { boost: 0, evidence: [] }
              triggered.set(actionId, {
                boost: prev.boost + (opt.missingRiskBoost ?? 0),
                evidence: [
                  ...prev.evidence,
                  { questionId: q.id, missingValue: opt.value },
                ],
              })
            }
          }
        }
      }
    }
  }

  const actions = Array.from(triggered.entries())
    .map(([id, meta]) => {
      const a = actionById[id]
      const base = PRIORITY_ORDER[a.basePriority] ?? 1
      const verticalBoost =
        (a.verticalBoosts?.[verticalId] ?? 0) + (a.verticalBoosts?.general ?? 0)

      const sortScore = base * 1000 + (meta.boost ?? 0) * 50 + verticalBoost

      const evidence = meta.evidence ?? []
      const evidenceText = formatEvidence(evidence)

      return {
        id: a.id,
        domain: a.domain,
        title: a.title,
        why: a.why,
        firstSteps: a.firstSteps,
        priority: a.basePriority,
        effort: a.effort ?? 'Low',
        execution: a.execution ?? 'Self',
        references: a.references ?? [],
        evidence,
        evidenceText,
        verticalBoost,
        sortScore,
      }
    })
    .sort((x, y) => y.sortScore - x.sortScore || x.id.localeCompare(y.id))

  const sectionOrder = getApplicableSections(profileId).map((s) => s.id)
  const byDomain = {}
  for (const sId of sectionOrder) byDomain[sId] = []

  for (const a of actions) {
    if (!byDomain[a.domain]) byDomain[a.domain] = []
    byDomain[a.domain].push(a)
  }

  return { all: actions, byDomain }
}

// Guidance text
function overallScore(domainSnapshot) {
  const vals = Object.values(domainSnapshot || {})
  if (vals.length === 0) return 0
  const sum = vals.reduce((acc, d) => acc + (d.score ?? 0), 0)
  return Math.round(sum / vals.length)
}

function guidanceForScore(score) {
  if (score <= 15) {
    return {
      tone: 'bg-rose-500/10 border-rose-500/30 text-rose-100',
      title: 'Start with the top actions - these will reduce the biggest risks fast.',
      body:
        'Your answers suggest most baseline controls are missing or inconsistent. Don’t focus on the number - focus on the plan. Do the High priority items first, then re-run the wizard to track progress.',
    }
  }
  if (score <= 40) {
    return {
      tone: 'bg-amber-500/10 border-amber-500/30 text-amber-100',
      title: 'Good progress - tighten the fundamentals and remove weak links.',
      body:
        'You have some protections in place, but gaps remain. Prioritize High actions, then pick 1-2 Medium items per domain to stabilize the baseline.',
    }
  }
  if (score <= 70) {
    return {
      tone: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-100',
      title: 'Solid baseline - focus on consistency and “boring reliability”.',
      body:
        'You’re in a good place. The plan below is about reducing drift: consistent MFA, clean sharing, backup testing, and alerting. Re-validate occasionally.',
    }
  }
  return {
    tone: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-100',
    title: 'Strong baseline - keep it verified and documented.',
    body:
      'Your answers indicate strong controls. Use the plan as a verification checklist and keep it documented so security doesn’t regress over time.',
  }
}

// Export formatting
function toCSV(actions) {
  const escape = (v) => {
    const s = String(v ?? '')
    if (s.includes('"') || s.includes(',') || s.includes('\n')) {
      return `"${s.replaceAll('"', '""')}"`
    }
    return s
  }

  const header = [
    'actionId',
    'domain',
    'priority',
    'effort',
    'execution',
    'title',
    'why',
    'evidence',
    'firstSteps',
  ].join(',')

  const lines = (actions || []).map((a) =>
    [
      escape(a.id),
      escape(a.domain),
      escape(a.priority),
      escape(a.effort),
      escape(a.execution),
      escape(a.title),
      escape(a.why),
      escape((a.evidenceText || []).join(' | ')),
      escape((a.firstSteps || []).join(' | ')),
    ].join(','),
  )
  return [header, ...lines].join('\n')
}

function toCSVOverview(report) {
  const escape = (v) => {
    const s = String(v ?? '')
    if (s.includes('"') || s.includes(',') || s.includes('\n')) {
      return `"${s.replaceAll('"', '""')}"`
    }
    return s
  }

  const overall = overallScore(report?.domainSnapshot || {})
  const header = [
    'generatedAt',
    'profileId',
    'verticalId',
    'overallScore',
    'sectionId',
    'title',
    'score',
    'tier',
  ].join(',')

  const rows = Object.values(report?.domainSnapshot || {}).map((d) =>
    [
      escape(report?.generatedAt),
      escape(report?.selectedProfileId),
      escape(report?.selectedVerticalId),
      escape(overall),
      escape(d.sectionId),
      escape(d.title),
      escape(d.score),
      escape(d.tier),
    ].join(','),
  )

  return [header, ...rows].join('\n')
}

// Markdown helpers
function mdEvidenceBlock(a, indent = '') {
  if (!a?.evidenceText?.length) return ''
  const lines = [
    `${indent}**Evidence (from answers)**`,
    ...a.evidenceText.map((ev) => `${indent}- ${ev}`),
  ]
  return lines.join('\n')
}

function mdRefsBlock(a, indent = '') {
  const refs = a?.references || []
  if (!refs.length) return ''
  return [
    '',
    `${indent}References:`,
    ...refs.map((r) => `${indent}- ${r.label}: ${r.url}`),
  ].join('\n')
}

function toMarkdown(report) {
  const {
    selectedProfile,
    selectedVertical,
    generatedAt,
    domainSnapshot,
    quickWins,
    actionPlanByDomain,
  } = report

  const profileLabel = selectedProfile?.title ?? selectedProfile?.id ?? 'unknown'
  const verticalLabel = selectedVertical?.title ?? selectedVertical?.id ?? 'unknown'

  const domainLines = Object.values(domainSnapshot || {})
    .map((d) => `- **${d.title}:** ${d.score}/100 (${d.tier})`)
    .join('\n')

  const quickLines = (quickWins || [])
    .map((a, idx) => {
      const steps = (a.firstSteps || []).map((s) => `  - ${s}`).join('\n')
      const evidence = a.evidenceText?.length
        ? `\n\n${mdEvidenceBlock(a)}`
        : ''
      const refs = mdRefsBlock(a, '  ')
      return `**${idx + 1}. ${a.title}** (${a.priority})\n\n${a.why}\n\n${steps}${evidence}${refs ? `\n\n${refs}` : ''}`
    })
    .join('\n\n')

  const domains = Object.keys(actionPlanByDomain || {})
  const planBlocks = domains
    .map((domainId) => {
      const items = actionPlanByDomain[domainId] || []
      if (items.length === 0) return null
      const title = domainSnapshot?.[domainId]?.title ?? domainId

      const bullets = items
        .map((a) => {
          const steps = (a.firstSteps || []).map((s) => `    - ${s}`).join('\n')
          const meta = `  Meta: ${a.priority} priority · Effort: ${a.effort} · Requires: ${a.execution}`
          const evidence = a.evidenceText?.length
            ? `\n\n  ${mdEvidenceBlock(a, '  ')}`
            : ''
          const refs = mdRefsBlock(a, '  ')
          return `- **${a.title}** - _${a.priority}_\n\n  ${a.why}\n\n${meta}\n\n  First steps:\n${steps}${evidence}${refs ? `\n\n${refs}` : ''}`
        })
        .join('\n\n')

      return `## ${title}\n\n${bullets}`
    })
    .filter(Boolean)
    .join('\n\n')

  return `# Cyber Hygiene Planner - Action Plan

- **Profile:** ${profileLabel}
- **Vertical:** ${verticalLabel}
- **Generated:** ${generatedAt}

## Domain snapshot

${domainLines}

## Quick wins

${quickLines || '_No quick wins were generated (you may already be in good shape for this checklist)._'} 

## Prioritized action plan

${planBlocks || '_No actions were triggered by your answers._'}

---

_Disclaimer: This is a checklist-based planner, not a compliance audit or guarantee of security._
`
}

function toMarkdownBlock(report, blockId) {
  if (blockId === 'overview') {
    const overall = overallScore(report.domainSnapshot || {})
    const domainLines = Object.values(report.domainSnapshot || {})
      .map((d) => `- **${d.title}:** ${d.score}/100 (${d.tier})`)
      .join('\n')

    return `## Overview

- Overall: **${overall}/100** (${scoreToTier(overall)})

### Domain snapshot
${domainLines || '_No domain data._'}
`
  }

  if (blockId === 'quickWins') {
    const quick = report.quickWins || []
    const lines = quick.length
      ? quick
          .map((a, i) => {
            const steps = (a.firstSteps || []).map((s) => `  - ${s}`).join('\n')
            const evidence = a.evidenceText?.length
              ? `\n\n${mdEvidenceBlock(a)}`
              : ''
            const refs = mdRefsBlock(a, '  ')
            return `**${i + 1}. ${a.title}** (${a.priority})\n\n${a.why}\n\n${steps}${evidence}${refs ? `\n\n${refs}` : ''}`
          })
          .join('\n\n')
      : '_No quick wins were generated._'

    return `## Quick wins\n\n${lines}\n`
  }

  if (blockId === 'plan') {
    const domains = Object.keys(report.actionPlanByDomain || {})
    const blocks = domains
      .map((domainId) => {
        const items = report.actionPlanByDomain[domainId] || []
        if (!items.length) return null
        const title = report.domainSnapshot?.[domainId]?.title ?? domainId

        const bullets = items
          .map((a) => {
            const steps = (a.firstSteps || []).map((s) => `    - ${s}`).join('\n')
            const meta = `  Meta: ${a.priority} priority · Effort: ${a.effort} · Required: ${a.execution}`
            const evidence = a.evidenceText?.length
              ? `\n\n  ${mdEvidenceBlock(a, '  ')}`
              : ''
            const refs = mdRefsBlock(a, '  ')
            return `- **${a.title}** - _${a.priority}_\n\n  ${a.why}\n\n${meta}\n\n  First steps:\n${steps}${evidence}${refs ? `\n\n${refs}` : ''}`
          })
          .join('\n\n')

        return `### ${title}\n\n${bullets}`
      })
      .filter(Boolean)
      .join('\n\n')

    return `## Full plan\n\n${blocks || '_No actions were triggered._'}\n`
  }

  return `## ${blockId}\n\n_Unknown block._\n`
}

function buildClipboardText(report) {
  return toMarkdown(report)
}

function getBlockPayload(report, blockId) {
  const base = {
    selectedProfileId: report.selectedProfileId,
    selectedProfileTitle: report.selectedProfile?.title,
    selectedVerticalId: report.selectedVerticalId,
    selectedVerticalTitle: report.selectedVertical?.title,
    generatedAt: report.generatedAt,
  }

  if (blockId === 'overview') {
    return {
      ...base,
      blockId,
      domainSnapshot: report.domainSnapshot,
      overall: overallScore(report.domainSnapshot || {}),
    }
  }

  if (blockId === 'quickWins') {
    return {
      ...base,
      blockId,
      quickWins: (report.quickWins || []).map((a) => ({
        id: a.id,
        domain: a.domain,
        title: a.title,
        why: a.why,
        firstSteps: a.firstSteps,
        priority: a.priority,
        effort: a.effort,
        execution: a.execution,
        references: a.references,
        evidence: a.evidence,
        evidenceText: a.evidenceText,
      })),
    }
  }

  if (blockId === 'plan') {
    return {
      ...base,
      blockId,
      actionPlan: {
        byDomain: report.actionPlanByDomain,
        all: (report.actionPlanAll || []).map((a) => ({
          id: a.id,
          domain: a.domain,
          title: a.title,
          why: a.why,
          firstSteps: a.firstSteps,
          priority: a.priority,
          effort: a.effort,
          execution: a.execution,
          verticalBoost: a.verticalBoost,
          references: a.references,
          evidence: a.evidence,
          evidenceText: a.evidenceText,
        })),
      },
    }
  }

  return { ...base, blockId }
}

function getBlockCSV(report, blockId) {
  if (!report) return ''
  if (blockId === 'plan') return toCSV(report.actionPlanAll || [])
  if (blockId === 'quickWins') return toCSV(report.quickWins || [])
  if (blockId === 'overview') return toCSVOverview(report)
  return ''
}

async function copyBlockToClipboard(report, blockId) {
  try {
    const md = toMarkdownBlock(report, blockId)
    await navigator.clipboard.writeText(md)
    return true
  } catch {
    return false
  }
}

function exportBlockJSON(report, blockId) {
  if (!report) return
  const payload = getBlockPayload(report, blockId)
  downloadTextFile(
    `cyber-hygiene_${report.selectedProfileId}_${report.selectedVerticalId}_${blockId}_${new Date()
      .toISOString()
      .slice(0, 10)}.json`,
    JSON.stringify(payload, null, 2),
  )
}

function exportBlockCSV(report, blockId) {
  if (!report) return
  const csv = getBlockCSV(report, blockId)
  if (!csv) return
  downloadTextFile(
    `cyber-hygiene_${report.selectedProfileId}_${report.selectedVerticalId}_${blockId}_${new Date()
      .toISOString()
      .slice(0, 10)}.csv`,
    csv,
  )
}

// Small UI helper
function EvidencePill({ action, isOpen, onToggle }) {
  if (!action?.evidenceText?.length) return null
  return (
    <button
      type="button"
      onClick={onToggle}
      className="text-[0.65rem] px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-200 hover:border-emerald-400/60 transition"
      title="See which answers triggered this recommendation"
    >
      {isOpen ? 'Evidence ▾' : `Evidence (${action.evidenceText.length})`}
    </button>
  )
}

function EvidencePanel({ action }) {
  if (!action?.evidenceText?.length) return null
  return (
    <div className="mt-2 rounded-xl bg-slate-900/40 border border-slate-800 p-2">
      <div className="text-[0.65rem] text-slate-400 mb-1">
        Triggered by your answers:
      </div>
      <ul className="list-disc pl-5 text-xs text-slate-300 space-y-1">
        {action.evidenceText.map((line, idx) => (
          <li key={idx}>{line}</li>
        ))}
      </ul>
    </div>
  )
}

function ResultsBlock({
  title,
  defaultOpen = true,
  blockId,
  report,
  onCopyFeedback,
  onPdfFeedback,
  children,
}) {
  const canExport = !!report

  const csvContent = report ? getBlockCSV(report, blockId) : ''
  const canCSV = canExport && csvContent.length > 0

  const disabledBtn =
    'bg-slate-900/60 border-slate-800 text-slate-500 cursor-not-allowed'
  const enabledBtn =
    'bg-slate-950/60 border-slate-800 hover:border-emerald-400/60 text-slate-200'

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/50">
      <details open={defaultOpen} className="group">
        <summary className="list-none cursor-pointer px-4 py-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-slate-100">{title}</span>
              <span
                className="text-slate-500 transition-transform group-open:rotate-180 select-none"
                aria-hidden="true"
                title="Expand/collapse"
              >
                ▾
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={(e) => {
                  e.preventDefault()
                  e.stopPropagation()
                  if (!report) return
                  downloadTextFile(
                    `cyber-hygiene_${report.selectedProfileId}_${report.selectedVerticalId}_${blockId}_${new Date()
                      .toISOString()
                      .slice(0, 10)}.md`,
                    [
                      `# Cyber Hygiene Planner - ${blockId}`,
                      `- Profile: ${report.selectedProfile?.title || report.selectedProfileId}`,
                      `- Context: ${report.selectedVertical?.title || report.selectedVerticalId}`,
                      `- Generated: ${report.generatedAt}`,
                      '',
                      toMarkdownBlock(report, blockId),
                      '',
                      '_Disclaimer: This is a checklist-based planner, not a compliance audit or guarantee of security._',
                      '',
                    ].join('\n'),
                  )
                }}
                disabled={!canExport}
                className={[
                  'text-[0.65rem] rounded-full px-2 py-1 border transition',
                  canExport ? enabledBtn : disabledBtn,
                ].join(' ')}
                title="Download this section as Markdown"
              >
                Download .md
              </button>

              <button
                type="button"
                onClick={(e) => {
                  e.preventDefault()
                  e.stopPropagation()
                  if (!report) return
                  exportBlockJSON(report, blockId)
                }}
                disabled={!canExport}
                className={[
                  'text-[0.65rem] rounded-full px-2 py-1 border transition',
                  canExport ? enabledBtn : disabledBtn,
                ].join(' ')}
                title="Download this section as JSON"
              >
                Download .json
              </button>

              <button
                type="button"
                onClick={(e) => {
                  e.preventDefault()
                  e.stopPropagation()
                  if (!canCSV) return
                  exportBlockCSV(report, blockId)
                }}
                disabled={!canCSV}
                className={[
                  'text-[0.65rem] rounded-full px-2 py-1 border transition',
                  canCSV ? enabledBtn : disabledBtn,
                ].join(' ')}
                title="Download this section as CSV"
              >
                Download .csv
              </button>

              <button
                type="button"
                onClick={(e) => {
                  e.preventDefault()
                  e.stopPropagation()
                  if (!report) return
                  const ok = exportBlockPDF(report, blockId)
                  onPdfFeedback?.(blockId, ok)
                }}
                disabled={!canExport}
                className={[
                  'text-[0.65rem] rounded-full px-2 py-1 border transition',
                  canExport ? enabledBtn : disabledBtn,
                ].join(' ')}
                title="Download this section as PDF"
              >
                Download .pdf
              </button>

              <button
                type="button"
                onClick={async (e) => {
                  e.preventDefault()
                  e.stopPropagation()
                  if (!report) return
                  const ok = await copyBlockToClipboard(report, blockId)
                  onCopyFeedback?.(blockId, ok)
                }}
                disabled={!canExport}
                className={[
                  'text-[0.65rem] rounded-full px-2 py-1 border transition',
                  canExport ? enabledBtn : disabledBtn,
                ].join(' ')}
                title="Copy this section to clipboard"
              >
                Copy
              </button>
            </div>
          </div>
        </summary>

        <div className="px-4 pb-4">{children}</div>
      </details>
    </div>
  )
}

function CyberHygienePlanner({ onBack }) {
  const [selectedProfileId, setSelectedProfileId] = useState(null)
  const [selectedVerticalId, setSelectedVerticalId] = useState(null)

  // 0 = profile, 1 = vertical (if needed), sections, last = results
  const [stepIndex, setStepIndex] = useState(0)

  const [answers, setAnswers] = useState({})
  const [copied, setCopied] = useState(false)

  // per-block copy feedback
  const [blockCopiedId, setBlockCopiedId] = useState(null)
  const [blockCopyOk, setBlockCopyOk] = useState(true)

  // PDF export feedback
  const [pdfStatus, setPdfStatus] = useState('idle')

  // Evidence disclosure state per action id
  const [openEvidence, setOpenEvidence] = useState(() => new Set())

  function toggleEvidence(actionId) {
    setOpenEvidence((prev) => {
      const next = new Set(prev)
      if (next.has(actionId)) next.delete(actionId)
      else next.add(actionId)
      return next
    })
  }

  const stepTopRef = useRef(null)

  const selectedProfile = useMemo(() => {
    if (!selectedProfileId) return null
    return PROFILES.find((p) => p.id === selectedProfileId) || null
  }, [selectedProfileId])

  const needsVertical = useMemo(() => {
    if (selectedProfile?.requiresVertical != null)
      return !!selectedProfile.requiresVertical
    const id = selectedProfile?.id || ''
    return !id.includes('personal')
  }, [selectedProfile])

  const selectedVertical = useMemo(() => {
    if (!selectedVerticalId) return null
    return VERTICALS.find((v) => v.id === selectedVerticalId) || null
  }, [selectedVerticalId])

  const sections = useMemo(() => {
    if (!selectedProfileId) return []
    return getApplicableSections(selectedProfileId)
  }, [selectedProfileId])

  const currentStep = useMemo(() => {
    if (!selectedProfileId) return { kind: 'profile' }
    if (needsVertical && !selectedVerticalId) return { kind: 'vertical' }

    const sectionCount = sections.length

    if (stepIndex <= 0) return { kind: 'profile' }
    const verticalIndex = needsVertical ? 1 : -1
    if (needsVertical && stepIndex === verticalIndex) return { kind: 'vertical' }

    const firstSectionIndex = needsVertical ? 2 : 1
    const lastSectionIndex = firstSectionIndex + sectionCount - 1
    const resultsIndex = lastSectionIndex + 1

    if (stepIndex >= firstSectionIndex && stepIndex <= lastSectionIndex) {
      const section = sections[stepIndex - firstSectionIndex]
      return { kind: 'section', section }
    }
    if (stepIndex >= resultsIndex) return { kind: 'results' }
    return { kind: 'section', section: sections[0] }
  }, [selectedProfileId, needsVertical, selectedVerticalId, stepIndex, sections])

  const domainSnapshot = useMemo(() => {
    if (!selectedProfileId) return null
    return computeDomainScores(selectedProfileId, answers)
  }, [selectedProfileId, answers])

  const effectiveVerticalId = useMemo(
    () => (needsVertical ? selectedVerticalId : 'general'),
    [needsVertical, selectedVerticalId],
  )

  const effectiveVertical = useMemo(
    () => (needsVertical ? selectedVertical : { id: 'general', title: 'General' }),
    [needsVertical, selectedVertical],
  )

  const actionPlan = useMemo(() => {
    if (!selectedProfileId) return null
    if (needsVertical && !selectedVerticalId) return null
    return buildActionPlan(selectedProfileId, effectiveVerticalId, answers)
  }, [selectedProfileId, needsVertical, selectedVerticalId, effectiveVerticalId, answers])

  const quickWins = useMemo(() => {
    const all = actionPlan?.all ?? []
    return all.slice(0, 3)
  }, [actionPlan])

  const overall = useMemo(() => overallScore(domainSnapshot || {}), [domainSnapshot])
  const guidance = useMemo(() => guidanceForScore(overall), [overall])

  const report = useMemo(() => {
    if (!selectedProfileId) return null
    if (needsVertical && !selectedVerticalId) return null
    return {
      selectedProfile,
      selectedProfileId,
      selectedVertical: effectiveVertical,
      selectedVerticalId: effectiveVerticalId,
      generatedAt: isoNow(),
      domainSnapshot: domainSnapshot || {},
      quickWins: quickWins || [],
      actionPlanByDomain: actionPlan?.byDomain || {},
      actionPlanAll: actionPlan?.all || [],
      answers: { ...answers },
      guidance,
    }
  }, [
    selectedProfileId,
    selectedProfile,
    needsVertical,
    selectedVerticalId,
    effectiveVerticalId,
    effectiveVertical,
    domainSnapshot,
    quickWins,
    actionPlan,
    answers,
    guidance,
  ])

  const stepNumbers = useMemo(() => {
    if (!selectedProfileId) return { current: 1, total: 1 }

    const base = needsVertical ? 2 : 1
    const total = base + sections.length + 1
    const current = clamp(stepIndex + 1, 1, total)

    return { current, total }
  }, [selectedProfileId, needsVertical, stepIndex, sections.length])

  const progressPct = useMemo(() => {
    if (!selectedProfileId) return 0
    const maxIndex = needsVertical
      ? selectedVerticalId
        ? 2 + sections.length
        : 1
      : 1 + sections.length
    const pct = Math.round((clamp(stepIndex, 0, maxIndex) / maxIndex) * 100)
    return clamp(pct, 0, 100)
  }, [selectedProfileId, needsVertical, selectedVerticalId, stepIndex, sections.length])

  const canGoNext = useMemo(() => {
    if (!selectedProfileId) return false
    if (needsVertical && !selectedVerticalId) return false
    if (currentStep.kind !== 'section') return true

    const visibleQs = getVisibleQuestionsForSection(
      selectedProfileId,
      currentStep.section.id,
      answers,
    )
    return visibleQs.every((q) => isAnswered(q, answers))
  }, [selectedProfileId, needsVertical, selectedVerticalId, currentStep, answers])

  const resetAll = () => {
    setSelectedProfileId(null)
    setSelectedVerticalId(null)
    setStepIndex(0)
    setAnswers({})
    setCopied(false)
    setBlockCopiedId(null)
    setPdfStatus('idle')
    setOpenEvidence(new Set())
  }

  const goBack = () => {
    if (stepIndex === 0) return

    const firstSectionIndex = needsVertical ? 2 : 1
    const verticalIndex = needsVertical ? 1 : -1

    if (stepIndex === firstSectionIndex) {
      if (needsVertical) {
        setStepIndex(verticalIndex)
      } else {
        setSelectedProfileId(null)
        setSelectedVerticalId(null)
        setAnswers({})
        setStepIndex(0)
      }
      setCopied(false)
      setBlockCopiedId(null)
      setPdfStatus('idle')
      setOpenEvidence(new Set())
      return
    }

    if (needsVertical && stepIndex === verticalIndex) {
      setSelectedProfileId(null)
      setSelectedVerticalId(null)
      setAnswers({})
      setStepIndex(0)
      setCopied(false)
      setBlockCopiedId(null)
      setPdfStatus('idle')
      setOpenEvidence(new Set())
      return
    }

    setStepIndex((i) => Math.max(0, i - 1))
    setCopied(false)
    setBlockCopiedId(null)
    setPdfStatus('idle')
  }

  const goNext = () => {
    if (!selectedProfileId) return
    if (needsVertical && !selectedVerticalId) return

    const lastIndex = (needsVertical ? 2 : 1) + sections.length
    setStepIndex((i) => Math.min(lastIndex, i + 1))
    setCopied(false)
    setBlockCopiedId(null)
    setPdfStatus('idle')
  }

  const handleSelectProfile = (profileId) => {
    setSelectedProfileId(profileId)
    setSelectedVerticalId(null)
    setAnswers({})
    setCopied(false)
    setBlockCopiedId(null)
    setPdfStatus('idle')
    setOpenEvidence(new Set())
    setStepIndex(1)
  }

  const handleSelectVertical = (verticalId) => {
    setSelectedVerticalId(verticalId)
    setStepIndex(2)
    setCopied(false)
    setBlockCopiedId(null)
    setPdfStatus('idle')
    setOpenEvidence(new Set())
  }

  const setRadio = (questionId, value) => {
    setAnswers((prev) => ({ ...prev, [questionId]: value }))
  }

  const toggleCheckbox = (questionId, value) => {
    setAnswers((prev) => {
      const cur = Array.isArray(prev[questionId]) ? prev[questionId] : []
      if (cur.includes(value)) {
        return { ...prev, [questionId]: cur.filter((v) => v !== value) }
      }
      return { ...prev, [questionId]: [...cur, value] }
    })
  }

  const exportMarkdown = () => {
    if (!report) return
    downloadTextFile(
      `cyber-hygiene-plan_${report.selectedProfileId}_${report.selectedVerticalId}_${new Date()
        .toISOString()
        .slice(0, 10)}.md`,
      toMarkdown(report),
    )
  }

  const exportJSON = () => {
    if (!report) return
    const payload = {
      selectedProfileId: report.selectedProfileId,
      selectedProfileTitle: report.selectedProfile?.title,
      selectedVerticalId: report.selectedVerticalId,
      selectedVerticalTitle: report.selectedVertical?.title,
      generatedAt: report.generatedAt,
      domainSnapshot: report.domainSnapshot,
      actionPlan: {
        byDomain: report.actionPlanByDomain,
        all: (report.actionPlanAll || []).map((a) => ({
          id: a.id,
          domain: a.domain,
          title: a.title,
          why: a.why,
          firstSteps: a.firstSteps,
          priority: a.priority,
          effort: a.effort,
          execution: a.execution,
          verticalBoost: a.verticalBoost,
          references: a.references,
          evidence: a.evidence,
          evidenceText: a.evidenceText,
        })),
      },
      answers: report.answers,
    }
    downloadTextFile(
      `cyber-hygiene-plan_${report.selectedProfileId}_${report.selectedVerticalId}_${new Date()
        .toISOString()
        .slice(0, 10)}.json`,
      JSON.stringify(payload, null, 2),
    )
  }

  const exportCSV = () => {
    if (!report) return
    downloadTextFile(
      `cyber-hygiene-actions_${report.selectedProfileId}_${report.selectedVerticalId}_${new Date()
        .toISOString()
        .slice(0, 10)}.csv`,
      toCSV(report.actionPlanAll || []),
    )
  }

  const exportPDF = () => {
    if (!report) return
    try {
      setPdfStatus('working')
      const ok = exportReportPDF(report, { blocks: ['overview', 'quickWins', 'plan'] })
      setPdfStatus(ok ? 'ok' : 'fail')
    } catch (e) {
      console.error(e)
      setPdfStatus('fail')
    } finally {
      window.setTimeout(() => setPdfStatus('idle'), 1500)
    }
  }

  const copyToClipboard = async () => {
    if (!report) return
    try {
      await navigator.clipboard.writeText(buildClipboardText(report))
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  const headerRightMeta = useMemo(() => {
    const parts = []
    if (selectedProfile?.title) parts.push(`Profile: ${selectedProfile.title}`)
    parts.push(
      `Context: ${needsVertical ? selectedVertical?.title || 'General' : 'General'}`,
    )
    return parts.join(' · ')
  }, [selectedProfile, needsVertical, selectedVertical])

  const handleBlockCopyFeedback = (blockId, ok) => {
    setBlockCopiedId(blockId)
    setBlockCopyOk(!!ok)
    window.setTimeout(() => setBlockCopiedId(null), 1200)
  }

  const handleBlockPdfFeedback = (blockId, ok) => {
    setPdfStatus(ok ? 'ok' : 'fail')
    window.setTimeout(() => setPdfStatus('idle'), 1500)
  }

  useEffect(() => {
    if (currentStep.kind !== 'section') return
    stepTopRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    window.setTimeout(() => {
      const root = stepTopRef.current?.parentElement
      const firstControl = root?.querySelector('input, button, select, textarea')
      firstControl?.focus?.()
    }, 50)
  }, [currentStep.kind, currentStep.section?.id])

  return (
    <div className="space-y-6">
      {/* Back / Reset */}
      <div className="flex items-center justify-between gap-3">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 bg-slate-900/80 border border-slate-800 hover:border-emerald-400/60 hover:text-emerald-200 transition text-xs"
          title="Back to Tool Hub"
        >
          <span className="text-emerald-300">←</span>
          Back to Hub
        </button>

        <button
          type="button"
          onClick={resetAll}
          className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 bg-slate-900/80 border border-slate-800 hover:border-rose-400/60 hover:text-rose-200 transition text-xs"
          title="Reset wizard"
        >
          Reset
        </button>
      </div>

      {/* Header */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
          <div>
            <h2 className="text-lg sm:text-xl font-semibold text-slate-50">
              Cyber Hygiene Planner
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 mt-1">
              Profile-based, checklist-style wizard that generates a prioritized security roadmap.
            </p>
            <p className="text-xs sm:text-sm text-slate-300 mt-1">
              Everything runs locally in your browser.
            </p>
            <div className="mt-2 text-[0.65rem] sm:text-xs text-slate-400 italic">
              Disclaimer: This is a checklist-based planner, not a compliance audit or guarantee of security.
            </div>
          </div>

          {/* Step counter + progress */}
          <div className="min-w-60">
            <div className="flex items-center justify-between text-[0.65rem] sm:text-xs text-slate-400">
              <span>
                Step{' '}
                <span className="text-slate-200 font-semibold">
                  {stepNumbers.current}
                </span>{' '}
                of{' '}
                <span className="text-slate-200 font-semibold">
                  {stepNumbers.total}
                </span>
              </span>

              <span className="text-slate-500">
                {selectedProfileId ? `${progressPct}%` : '0%'}
              </span>
            </div>

            <div className="mt-2 h-2 rounded-full bg-slate-950/70 border border-slate-800 overflow-hidden">
              <div
                className="h-full bg-emerald-500/40"
                style={{ width: `${selectedProfileId ? progressPct : 0}%` }}
              />
            </div>

            {headerRightMeta && (
              <div className="mt-2 text-[0.65rem] sm:text-xs text-slate-500">
                {headerRightMeta}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Step: Profile */}
      {currentStep.kind === 'profile' && (
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:p-5">
          <h3 className="text-sm font-semibold text-slate-100 mb-1">
            Step 1: Choose your profile
          </h3>
          <p className="text-xs sm:text-sm text-slate-300 mb-4">
            Pick the option that best matches how you use your accounts and devices.
            This avoids wrong advice caused by “close enough” choices.
          </p>

          <div className="grid gap-3 sm:grid-cols-2">
            {PROFILES.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => handleSelectProfile(p.id)}
                className="text-left rounded-2xl border border-slate-800 bg-slate-950/50 p-4 hover:border-emerald-400/60 hover:shadow-lg hover:shadow-emerald-500/10 transition"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-base font-semibold text-slate-50">
                      {p.title}
                    </div>
                    <div className="text-xs text-slate-300 mt-1">
                      {p.description}
                    </div>
                  </div>
                  <span className="text-[0.65rem] px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-200 border border-emerald-500/30">
                    Select
                  </span>
                </div>
              </button>
            ))}
          </div>
        </section>
      )}

      {/* Step: Vertical */}
      {currentStep.kind === 'vertical' && (
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:p-5">
          <h3 className="text-sm font-semibold text-slate-100 mb-1">
            Step 2: Choose your context (industry)
          </h3>
          <p className="text-xs sm:text-sm text-slate-300 mb-4">
            This doesn’t change your answers, but influences which actions are prioritized first.
            Pick the closest match.
          </p>

          <div className="grid gap-3 sm:grid-cols-2">
            {VERTICALS.map((v) => (
              <button
                key={v.id}
                type="button"
                onClick={() => handleSelectVertical(v.id)}
                className={[
                  'text-left rounded-2xl border bg-slate-950/50 p-4 transition',
                  selectedVerticalId === v.id
                    ? 'border-emerald-500/50 bg-emerald-500/10'
                    : 'border-slate-800 hover:border-emerald-400/60 hover:shadow-lg hover:shadow-emerald-500/10',
                ].join(' ')}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-base font-semibold text-slate-50">
                      {v.title}
                    </div>
                    <div className="text-xs text-slate-300 mt-1">
                      {v.description}
                    </div>
                  </div>
                  <span className="text-[0.65rem] px-2 py-0.5 rounded-full bg-slate-900/70 text-slate-200 border border-slate-700">
                    Select
                  </span>
                </div>
              </button>
            ))}
          </div>

          <div className="mt-5 flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={goBack}
              className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 bg-slate-900/80 border border-slate-800 hover:border-slate-600 transition text-xs"
            >
              ← Back
            </button>
          </div>
        </section>
      )}

      {/* Step: Section */}
      {currentStep.kind === 'section' && (
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:p-5">
          <div ref={stepTopRef} tabIndex={-1} />
          <div className="flex items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                {currentStep.section.title}
              </h3>
              <p className="text-xs sm:text-sm text-slate-300 mt-1">
                {currentStep.section.description}
              </p>
            </div>

            <span className="text-[0.65rem] px-2 py-0.5 rounded-full bg-slate-950/60 border border-slate-800 text-slate-300">
              Step
            </span>
          </div>

          <div className="mt-4 space-y-4">
            {getVisibleQuestionsForSection(
              selectedProfileId,
              currentStep.section.id,
              answers,
            ).map((q) => (
              <div
                key={q.id}
                className="rounded-2xl border border-slate-800 bg-slate-950/50 p-4"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-slate-100">
                      {q.prompt}
                    </div>
                    {q.helpText && (
                      <div className="mt-1 text-xs text-slate-400">
                        {q.helpText}
                      </div>
                    )}
                  </div>
                </div>

                {q.type === 'radio' && (
                  <div className="mt-3 grid gap-2">
                    {q.options.map((opt) => {
                      const checked = answers[q.id] === opt.value
                      return (
                        <label
                          key={opt.value}
                          className={[
                            'flex items-start gap-3 rounded-xl border px-3 py-2 cursor-pointer transition',
                            checked
                              ? 'border-emerald-500/50 bg-emerald-500/10'
                              : 'border-slate-800 bg-slate-950/40 hover:border-emerald-400/40',
                          ].join(' ')}
                        >
                          <input
                            type="radio"
                            name={q.id}
                            value={opt.value}
                            checked={checked}
                            onChange={() => setRadio(q.id, opt.value)}
                            className="mt-1"
                          />
                          <div className="text-xs sm:text-sm text-slate-200">
                            {opt.label}
                          </div>
                        </label>
                      )
                    })}
                  </div>
                )}

                {q.type === 'checkbox' && (
                  <div className="mt-3 grid gap-2">
                    {q.options.map((opt) => {
                      const selectedArr = Array.isArray(answers[q.id])
                        ? answers[q.id]
                        : []
                      const checked = selectedArr.includes(opt.value)
                      return (
                        <label
                          key={opt.value}
                          className={[
                            'flex items-start gap-3 rounded-xl border px-3 py-2 cursor-pointer transition',
                            checked
                              ? 'border-emerald-500/50 bg-emerald-500/10'
                              : 'border-slate-800 bg-slate-950/40 hover:border-emerald-400/40',
                          ].join(' ')}
                        >
                          <input
                            type="checkbox"
                            value={opt.value}
                            checked={checked}
                            onChange={() => toggleCheckbox(q.id, opt.value)}
                            className="mt-1"
                          />
                          <div className="text-xs sm:text-sm text-slate-200">
                            {opt.label}
                          </div>
                        </label>
                      )
                    })}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Nav */}
          <div className="mt-5 flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={goBack}
              className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 bg-slate-900/80 border border-slate-800 hover:border-slate-600 transition text-xs"
            >
              ← Back
            </button>

            <div className="flex items-center gap-2">
              {!canGoNext && (
                <span className="text-[0.65rem] text-amber-200 bg-amber-500/10 border border-amber-500/30 rounded-full px-2 py-0.5">
                  Answer all questions to continue
                </span>
              )}
              <button
                type="button"
                onClick={goNext}
                disabled={!canGoNext}
                className={[
                  'inline-flex items-center gap-2 rounded-full px-3 py-1.5 border transition text-xs',
                  canGoNext
                    ? 'bg-emerald-500/10 border-emerald-500/30 hover:border-emerald-400/60 text-emerald-200'
                    : 'bg-slate-900/80 border-slate-800 text-slate-500 cursor-not-allowed',
                ].join(' ')}
              >
                Next →
              </button>
            </div>
          </div>
        </section>
      )}

      {/* Step: Results */}
      {currentStep.kind === 'results' && report && (
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">Results</h3>
              <p className="text-xs sm:text-sm text-slate-300 mt-1">
                Your plan is the important part. The score is only a rough signal.
              </p>
              <div className="mt-2 text-[0.65rem] text-slate-500">
                Generated:{' '}
                <span className="text-slate-300">{report.generatedAt}</span>
              </div>
              <div className="mt-1 text-[0.65rem] text-slate-500">
                Profile:{' '}
                <span className="text-slate-300">{report.selectedProfile?.title}</span>{' '}
                · Context:{' '}
                <span className="text-slate-300">{report.selectedVertical?.title}</span>
              </div>

              {pdfStatus !== 'idle' && (
                <div className="mt-2 text-[0.65rem] text-slate-400">
                  {pdfStatus === 'working' && 'Building PDF…'}
                  {pdfStatus === 'ok' && 'PDF saved ✓'}
                  {pdfStatus === 'fail' && 'PDF failed (check console)'}
                </div>
              )}
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={exportMarkdown}
                className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 bg-slate-950/60 border border-slate-800 hover:border-emerald-400/60 transition text-xs"
              >
                Download .md
              </button>
              <button
                type="button"
                onClick={exportJSON}
                className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 bg-slate-950/60 border border-slate-800 hover:border-emerald-400/60 transition text-xs"
              >
                Download .json
              </button>
              <button
                type="button"
                onClick={exportCSV}
                className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 bg-slate-950/60 border border-slate-800 hover:border-emerald-400/60 transition text-xs"
              >
                Download .csv
              </button>

              <button
                type="button"
                onClick={exportPDF}
                disabled={pdfStatus === 'working'}
                className={[
                  'inline-flex items-center gap-2 rounded-full px-3 py-1.5 border transition text-xs',
                  pdfStatus === 'working'
                    ? 'bg-slate-900/60 border-slate-800 text-slate-500 cursor-not-allowed'
                    : 'bg-slate-950/60 border border-slate-800 hover:border-emerald-400/60',
                ].join(' ')}
                title="Download a real PDF report (no screenshots)"
              >
                {pdfStatus === 'working'
                  ? 'PDF…'
                  : pdfStatus === 'ok'
                    ? 'PDF ✓'
                    : pdfStatus === 'fail'
                      ? 'PDF failed'
                      : 'Download .pdf'}
              </button>

              <button
                type="button"
                onClick={copyToClipboard}
                className={[
                  'inline-flex items-center gap-2 rounded-full px-3 py-1.5 border transition text-xs',
                  copied
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                    : 'bg-slate-950/60 border-slate-800 hover:border-emerald-400/60',
                ].join(' ')}
              >
                {copied ? 'Copied ✓' : 'Copy to clipboard'}
              </button>
            </div>
          </div>

          {/* Guidance banner */}
          <div className={`rounded-2xl border p-4 ${guidance.tone}`}>
            <div className="text-sm font-semibold">{guidance.title}</div>
            <div className="mt-1 text-xs text-slate-200/90">{guidance.body}</div>
          </div>

          {/* per-block copy feedback */}
          {blockCopiedId && (
            <div className="text-[0.65rem] sm:text-xs text-slate-400">
              {blockCopyOk ? 'Copied' : 'Copy failed'}:{' '}
              <span className="text-slate-200">{blockCopiedId}</span>
            </div>
          )}

          {/* Results blocks */}
          <div className="space-y-4">
            <ResultsBlock
              title="Overview"
              blockId="overview"
              report={report}
              defaultOpen={false}
              onCopyFeedback={handleBlockCopyFeedback}
              onPdfFeedback={handleBlockPdfFeedback}
            >
              <div className="space-y-4">
                <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-xs text-slate-400">
                        Overall maturity (rough)
                      </div>
                      <div className="text-sm font-semibold text-slate-100">
                        {overall}/100 · {scoreToTier(overall)}
                      </div>
                    </div>
                    <span className="text-[0.65rem] px-2 py-0.5 rounded-full bg-slate-900/80 border border-slate-800 text-slate-300">
                      Focus: actions first
                    </span>
                  </div>
                  <div className="mt-2 h-2 rounded-full bg-slate-950/70 border border-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-emerald-500/40"
                      style={{ width: `${overall}%` }}
                    />
                  </div>
                  <div className="mt-2 text-[0.65rem] text-slate-500">
                    Tip: re-run after you complete a few items to update the plan.
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4">
                  <div className="text-sm font-semibold text-slate-100">
                    Domain snapshot
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    These are directional indicators, not a pass/fail grade.
                  </div>

                  <div className="mt-4 grid gap-3 sm:grid-cols-2">
                    {Object.values(report.domainSnapshot).map((d) => (
                      <div
                        key={d.sectionId}
                        className="rounded-2xl border border-slate-800 bg-slate-950/40 p-3"
                      >
                        <div className="flex items-center justify-between gap-3">
                          <div className="text-xs font-semibold text-slate-200">
                            {d.title}
                          </div>
                          <span className="text-[0.65rem] px-2 py-0.5 rounded-full bg-slate-900/80 border border-slate-800 text-slate-300">
                            {d.tier}
                          </span>
                        </div>
                        <div className="mt-2 text-xs text-slate-300">
                          Score:{' '}
                          <span className="text-slate-100 font-semibold">
                            {d.score}/100
                          </span>
                        </div>
                        <div className="mt-2 h-2 rounded-full bg-slate-950/70 border border-slate-800 overflow-hidden">
                          <div
                            className="h-full bg-emerald-500/40"
                            style={{ width: `${d.score}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </ResultsBlock>

            <ResultsBlock
              title="Quick wins"
              blockId="quickWins"
              report={report}
              defaultOpen={true}
              onCopyFeedback={handleBlockCopyFeedback}
              onPdfFeedback={handleBlockPdfFeedback}
            >
              <div className="text-xs text-slate-400">
                Top 3 actions (prioritized for your context).
              </div>

              <div className="mt-3 space-y-3">
                {(report.quickWins || []).length === 0 ? (
                  <div className="text-xs text-slate-400">
                    No quick wins were generated by this checklist.
                  </div>
                ) : (
                  report.quickWins.map((a) => (
                    <div
                      key={a.id}
                      className="rounded-2xl border border-slate-800 bg-slate-950/40 p-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="text-sm font-semibold text-slate-100">
                          {a.title}
                        </div>
                        <span
                          className={`text-[0.65rem] px-2 py-0.5 rounded-full ${priorityPill(
                            a.priority,
                          )}`}
                        >
                          {a.priority}
                        </span>
                      </div>

                      <div className="mt-2 flex flex-wrap gap-2">
                        <span className={effortPill(a.effort)} title="Estimated effort">
                          Effort: {a.effort}
                        </span>
                        <span className={executionPill(a.execution)} title="Who should do this">
                          Requires: {a.execution}
                        </span>

                        <EvidencePill
                          action={a}
                          isOpen={openEvidence.has(a.id)}
                          onToggle={() => toggleEvidence(a.id)}
                        />
                      </div>

                      <div className="mt-2 text-xs text-slate-300">{a.why}</div>

                      {openEvidence.has(a.id) && <EvidencePanel action={a} />}

                      <ul className="mt-2 list-disc pl-5 text-xs text-slate-300 space-y-1">
                        {(a.firstSteps || []).map((s, idx) => (
                          <li key={idx}>{s}</li>
                        ))}
                      </ul>

                      {(a.references || []).length > 0 && (
                        <>
                          <div className="mt-3 text-xs text-slate-400">
                            References:
                          </div>
                          <ul className="mt-1 list-disc pl-5 text-xs text-slate-300 space-y-1">
                            {a.references.map((r, idx) => (
                              <li key={idx}>
                                <a
                                  href={r.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="underline text-slate-300 hover:text-slate-100"
                                >
                                  {r.label}
                                </a>
                              </li>
                            ))}
                          </ul>
                        </>
                      )}
                    </div>
                  ))
                )}
              </div>
            </ResultsBlock>

            <ResultsBlock
              title="Full plan"
              blockId="plan"
              report={report}
              defaultOpen={false}
              onCopyFeedback={handleBlockCopyFeedback}
              onPdfFeedback={handleBlockPdfFeedback}
            >
              <div className="text-xs text-slate-400">
                Grouped by domain. Deduplicated. Prioritized for your context.
              </div>

              <div className="mt-4 space-y-5">
                {getApplicableSections(selectedProfileId).map((s) => {
                  const items = report.actionPlanByDomain?.[s.id] || []
                  return (
                    <div key={s.id} className="space-y-2">
                      <div className="flex items-center justify-between gap-3">
                        <div className="text-xs font-semibold text-slate-200">
                          {s.title}
                        </div>
                        <span className="text-[0.65rem] px-2 py-0.5 rounded-full bg-slate-900/80 border border-slate-800 text-slate-400">
                          {items.length} action{items.length === 1 ? '' : 's'}
                        </span>
                      </div>

                      {items.length === 0 ? (
                        <div className="text-xs text-slate-500">
                          No actions triggered in this domain.
                        </div>
                      ) : (
                        <div className="grid gap-3">
                          {items.map((a) => (
                            <div
                              key={a.id}
                              className="rounded-2xl border border-slate-800 bg-slate-950/40 p-3"
                            >
                              <div className="flex items-start justify-between gap-3">
                                <div className="text-sm font-semibold text-slate-100">
                                  {a.title}
                                </div>
                                <span
                                  className={`text-[0.65rem] px-2 py-0.5 rounded-full ${priorityPill(
                                    a.priority,
                                  )}`}
                                >
                                  {a.priority}
                                </span>
                              </div>

                              <div className="mt-2 flex flex-wrap gap-2">
                                <span className={effortPill(a.effort)} title="Estimated effort">
                                  Effort: {a.effort}
                                </span>
                                <span className={executionPill(a.execution)} title="Who should do this">
                                  Requires: {a.execution}
                                </span>

                                <EvidencePill
                                  action={a}
                                  isOpen={openEvidence.has(a.id)}
                                  onToggle={() => toggleEvidence(a.id)}
                                />
                              </div>

                              <div className="mt-2 text-xs text-slate-300">
                                {a.why}
                              </div>

                              {openEvidence.has(a.id) && <EvidencePanel action={a} />}

                              <div className="mt-3 text-xs text-slate-400">
                                Practical first steps:
                              </div>
                              <ul className="mt-1 list-disc pl-5 text-xs text-slate-300 space-y-1">
                                {(a.firstSteps || []).map((step, idx) => (
                                  <li key={idx}>{step}</li>
                                ))}
                              </ul>

                              {(a.references || []).length > 0 && (
                                <>
                                  <div className="mt-3 text-xs text-slate-400">
                                    References:
                                  </div>
                                  <ul className="mt-1 list-disc pl-5 text-xs text-slate-300 space-y-1">
                                    {a.references.map((r, idx) => (
                                      <li key={idx}>
                                        <a
                                          href={r.url}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="underline text-slate-300 hover:text-slate-100"
                                        >
                                          {r.label}
                                        </a>
                                      </li>
                                    ))}
                                  </ul>
                                </>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>

              <div className="mt-5 rounded-xl bg-slate-950/60 border border-slate-800 p-3">
                <div className="text-[0.65rem] sm:text-xs text-slate-400">
                  Disclaimer: This is a checklist-based planner, not a compliance audit or guarantee of security.
                </div>
              </div>
            </ResultsBlock>
          </div>

          {/* Nav */}
          <div className="flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={goBack}
              className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 bg-slate-900/80 border border-slate-800 hover:border-slate-600 transition text-xs"
            >
              ← Back
            </button>

            <button
              type="button"
              onClick={resetAll}
              className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 bg-rose-500/10 border border-rose-500/30 hover:border-rose-400/60 text-rose-200 transition text-xs"
            >
              Reset wizard
            </button>
          </div>
        </section>
      )}

      <AboutSection />
    </div>
  )
}

export default CyberHygienePlanner
