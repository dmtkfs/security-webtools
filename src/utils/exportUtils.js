// Helper: download a text blob as a file (client-side only)
export function downloadTextFile(filename, text) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// Serialize findings to a Markdown report
export function findingsToMarkdown({ dockerfileText, findings }) {
  const lines = dockerfileText.split(/\r?\n/)

  const summaryLines = findings.map((f, idx) => {
    const lineInfo = f.lineNumber ? ` (line ${f.lineNumber})` : ''
    return `${idx + 1}. **[${f.severity.toUpperCase()}] ${f.title}**${lineInfo}`
  })

  const details = findings
    .map((f, idx) => {
      const lineInfo = f.lineNumber ? `Line: ${f.lineNumber}\n` : ''
      const snippet = f.lineContent
        ? `\n\`\`\`dockerfile\n${f.lineContent}\n\`\`\`\n`
        : ''
      return [
        `### ${idx + 1}. ${f.title} [${f.severity.toUpperCase()}]`,
        lineInfo,
        `${f.description}`,
        snippet,
        `**Remediation:** ${f.recommendation}`,
      ].join('\n')
    })
    .join('\n\n---\n\n')

  return [
    '# Docker Image Security Analysis Report',
    '',
    `Generated at: ${new Date().toISOString()}`,
    '',
    '## Summary',
    '',
    findings.length
      ? summaryLines.join('\n')
      : '_No findings produced by the current rule set._',
    '',
    '## Detailed Findings',
    '',
    findings.length ? details : '_No detailed findings._',
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
