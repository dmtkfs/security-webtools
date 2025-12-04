// src/utils/exportUtils.js

// Helper: download a text blob as a file (client-side only)
export function downloadTextFile(filename, text) {
  try {
    const blob = new Blob(
      [typeof text === 'string' ? text : String(text ?? '')],
      { type: 'text/plain;charset=utf-8' },
    )
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename || 'download.txt'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  } catch (err) {
    console.error('Failed to download text file:', err)
  }
}

// ---------------------------------------------------------------------------
// findingsToMarkdown
//  - If called with { dockerfileText, findings }: Docker image report
//  - If called with { findings, context } only: generic cloud report
// ---------------------------------------------------------------------------

export function findingsToMarkdown(opts = {}) {
  const { dockerfileText, findings, context } = opts
  const list = Array.isArray(findings) ? findings : []

  // -------------------------------------------------------------------------
  // 1) Docker image security report (old behavior, kept intact but safer)
  // -------------------------------------------------------------------------
  if (typeof dockerfileText === 'string') {
    const lines = dockerfileText.split(/\r?\n/)
    const summaryLines = list.map((f, idx) => {
      const lineInfo = f.lineNumber ? ` (line ${f.lineNumber})` : ''
      const sev = (f.severity || '').toString().toUpperCase() || 'INFO'
      const title = f.title || 'Untitled finding'
      return `${idx + 1}. **[${sev}] ${title}**${lineInfo}`
    })

    const details = list
      .map((f, idx) => {
        const sev = (f.severity || '').toString().toUpperCase() || 'INFO'
        const title = f.title || 'Untitled finding'
        const lineInfo = f.lineNumber ? `Line: ${f.lineNumber}\n` : ''
        const snippet = f.lineContent
          ? `\n\`\`\`dockerfile\n${f.lineContent}\n\`\`\`\n`
          : ''
        const desc = f.description || ''
        const rec = f.recommendation || ''

        return [
          `### ${idx + 1}. ${title} [${sev}]`,
          lineInfo,
          desc,
          snippet,
          rec ? `**Remediation:** ${rec}` : '',
        ]
          .filter(Boolean)
          .join('\n')
      })
      .join('\n\n---\n\n')

    return [
      '# Docker Image Security Analysis Report',
      '',
      `Generated at: ${new Date().toISOString()}`,
      '',
      '## Summary',
      '',
      list.length
        ? summaryLines.join('\n')
        : '_No findings produced by the current rule set._',
      '',
      '## Detailed Findings',
      '',
      list.length ? details : '_No detailed findings._',
      '',
      '## Dockerfile (analyzed)',
      '',
      '```dockerfile',
      lines.join('\n'),
      '```',
      '',
      '> This report was generated locally in the browser by Security Webtools.',
      '',
    ].join('\n')
  }

  // -------------------------------------------------------------------------
  // 2) Generic cloud misconfig report (used by CloudMisconfigScanner)
  // -------------------------------------------------------------------------

  const lines = []

  lines.push('# Cloud Misconfiguration Report')
  lines.push('')
  lines.push(`Generated at: ${new Date().toISOString()}`)
  if (context) {
    lines.push('')
    lines.push(`> ${context}`)
  }
  lines.push('')
  lines.push('---')
  lines.push('')

  if (list.length === 0) {
    lines.push('_No findings in this view._')
    return lines.join('\n')
  }

  // Group by resourceType for nicer structure
  const byResourceType = new Map()
  list.forEach((f) => {
    const type = f.resourceType || 'other'
    if (!byResourceType.has(type)) byResourceType.set(type, [])
    byResourceType.get(type).push(f)
  })

  for (const [resourceType, grouped] of byResourceType.entries()) {
    const friendlyType =
      resourceType === 'security-group'
        ? 'Security groups / firewall rules'
        : resourceType === 's3-bucket'
          ? 'Storage buckets'
          : resourceType === 'iam-policy'
            ? 'IAM / role policies'
            : resourceType

    lines.push(`## ${friendlyType}`)
    lines.push('')

    grouped.forEach((f) => {
      const title = f.title || f.ruleId || f.id || 'Unlabelled finding'
      const severity = (f.severity || 'info').toString().toUpperCase()
      const category = f.category || 'uncategorized'

      lines.push(`### ${title}`)
      lines.push('')
      lines.push(`- **Severity:** ${severity}`)
      lines.push(`- **Category:** ${category}`)

      if (f.ruleId) {
        lines.push(`- **Rule ID:** \`${f.ruleId}\``)
      }

      const resBits = []
      if (f.resourceType) resBits.push(`type: \`${f.resourceType}\``)
      if (f.resourceId) resBits.push(`id: \`${f.resourceId}\``)
      if (resBits.length > 0) {
        lines.push(`- **Resource:** ${resBits.join(', ')}`)
      }

      if (f.location && f.location.path) {
        lines.push(`- **Location in config:** \`${f.location.path}\``)
      }

      if (f.description) {
        lines.push('')
        lines.push('**Description**')
        lines.push('')
        lines.push(f.description)
      }

      if (f.recommendation) {
        lines.push('')
        lines.push('**Remediation guidance**')
        lines.push('')
        lines.push(f.recommendation)
      }

      lines.push('')
      lines.push('---')
      lines.push('')
    })
  }

  return lines.join('\n')
}
