import React, { useRef, useState, useEffect } from 'react'
import AboutSection from '../../components/AboutSection.jsx'
import { getTemp, setTemp } from '../../utils/storage.js'
import { downloadTextFile, findingsToMarkdown } from '../../utils/exportUtils.js'
import {
  analyzeMultiCloudConfig,
  exampleMultiCloudConfig,
  PLATFORM_LABELS,
} from './multiCloudEngine.js'
import SchemaHelpPanel from './SchemaHelpPanel.jsx'

// Helper: safely parse JSON and try to infer approximate line/column from the
// built-in "position X" error message that most JS engines provide.
function safeParseJsonWithLocation(text) {
  try {
    const value = JSON.parse(text)
    return { ok: true, value }
  } catch (err) {
    const message =
      err && typeof err.message === 'string'
        ? err.message
        : 'Invalid JSON.'

    let line = null
    let column = null

    const match = message.match(/position\s+(\d+)/i)
    if (match) {
      const pos = Number(match[1])
      if (!Number.isNaN(pos)) {
        let currentLine = 1
        let currentCol = 1

        for (let i = 0; i < pos && i < text.length; i += 1) {
          const ch = text[i]
          if (ch === '\n') {
            currentLine += 1
            currentCol = 1
          } else {
            currentCol += 1
          }
        }

        line = currentLine
        column = currentCol
      }
    }

    return {
      ok: false,
      value: null,
      message:
        'The configuration is not valid JSON. Please fix the syntax and try again.',
      rawMessage: message,
      line,
      column,
    }
  }
}

function CloudMisconfigScanner({ onBack }) {
  const [configText, setConfigText] = useState(() =>
    getTemp('sw_cloud_config_text', ''),
  )
  const [findings, setFindings] = useState(() =>
    getTemp('sw_cloud_findings', []),
  )
  const [hasAnalyzed, setHasAnalyzed] = useState(() =>
    getTemp('sw_cloud_hasAnalyzed', false),
  )

  // Sync to temp storage (TTL-limited)
  useEffect(() => {
    setTemp('sw_cloud_config_text', configText)
  }, [configText])

  useEffect(() => {
    setTemp('sw_cloud_findings', findings)
  }, [findings])

  useEffect(() => {
    setTemp('sw_cloud_hasAnalyzed', hasAnalyzed)
  }, [hasAnalyzed])

  useEffect(() => {
    setTemp('sw_cloud_detectedPlatform', detectedPlatform)
  }, [detectedPlatform])


  // Ephemeral UI state
  const [error, setError] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [exportMessage, setExportMessage] = useState(null)
  const [inputSource, setInputSource] = useState('manual')
  const [uploadedFileName, setUploadedFileName] = useState(null)
  const [showOnlyImportant, setShowOnlyImportant] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [detectedPlatform, setDetectedPlatform] = useState(() =>
    getTemp('sw_cloud_detectedPlatform', null),
  )

  const fileInputRef = useRef(null)

  // ---------------------------------------------------------------------------
  // Input handlers
  // ---------------------------------------------------------------------------

  const handleLoadSample = () => {
    const text = JSON.stringify(exampleMultiCloudConfig, null, 2)
    setConfigText(text)
    setFindings([])
    setHasAnalyzed(false)
    setError(null)
    setExportMessage(null)
    setInputSource('sample')
    setUploadedFileName(null)
    setShowOnlyImportant(false)
    setSearchQuery('')
    setDetectedPlatform(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleFileChange = (event) => {
    const file = event.target.files?.[0]
    if (!file) return

    const lowerName = file.name.toLowerCase()

    const disallowedExts = [
      '.php',
      '.js',
      '.jsx',
      '.ts',
      '.tsx',
      '.exe',
      '.dll',
      '.so',
      '.sh',
      '.bat',
      '.cmd',
      '.ps1',
      '.jar',
      '.py',
    ]

    if (disallowedExts.some((ext) => lowerName.endsWith(ext))) {
      setError('This file type is not allowed. Please upload a JSON export only.')
      setExportMessage(null)
      setInputSource('manual')
      setUploadedFileName(null)
      setSearchQuery('')
      setDetectedPlatform(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
      return
    }

    const MAX_FILE_SIZE_BYTES = 512 * 1024
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setError('File is too large. Please upload a JSON file under 512 KB.')
      setExportMessage(null)
      setInputSource('manual')
      setUploadedFileName(null)
      setSearchQuery('')
      setDetectedPlatform(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
      return
    }

    const reader = new FileReader()
    reader.onload = (e) => {
      const contents = e.target.result
      if (typeof contents !== 'string') return

      if (!contents.trim().startsWith('{')) {
        setError('This file does not look like a JSON configuration object.')
        setExportMessage(null)
        setInputSource('manual')
        setUploadedFileName(null)
        setSearchQuery('')
        setDetectedPlatform(null)
        if (fileInputRef.current) fileInputRef.current.value = ''
        return
      }

      setConfigText(contents)
      setHasAnalyzed(false)
      setFindings([])
      setError(null)
      setExportMessage(null)
      setInputSource('file')
      setUploadedFileName(file.name)
      setShowOnlyImportant(false)
      setSearchQuery('')
      setDetectedPlatform(null)
    }
    reader.onerror = () => {
      setError('Failed to read file. Please try again.')
      setInputSource('manual')
      setUploadedFileName(null)
      setSearchQuery('')
      setDetectedPlatform(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
    reader.readAsText(file)
  }

  const handleReset = () => {
    setConfigText('')
    setFindings([])
    setHasAnalyzed(false)
    setError(null)
    setExportMessage(null)
    setInputSource('manual')
    setUploadedFileName(null)
    setShowOnlyImportant(false)
    setSearchQuery('')
    setDetectedPlatform(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleAnalyze = () => {
    setError(null)
    setExportMessage(null)
    setHasAnalyzed(true)

    if (!configText.trim()) {
      setFindings([])
      setError('Please paste JSON configuration or upload a file before analyzing.')
      return
    }

    const MAX_TEXT_LENGTH = 300_000
    if (configText.length > MAX_TEXT_LENGTH) {
      setFindings([])
      setError('Input is too large. Please analyze a JSON file under ~300 KB of text.')
      return
    }

    const parsedResult = safeParseJsonWithLocation(configText)
    if (!parsedResult.ok) {
      setFindings([])
      if (parsedResult.line != null && parsedResult.column != null) {
        setError(
          `${parsedResult.message} Approximate error location: line ${parsedResult.line}, column ${parsedResult.column}.`,
        )
      } else {
        setError(parsedResult.message)
      }
      return
    }

    const parsed = parsedResult.value

    try {
      setIsAnalyzing(true)
      const { platform, findings: results } = analyzeMultiCloudConfig(parsed)
      setDetectedPlatform(platform)
      setFindings(results)
      setShowOnlyImportant(false)
      setSearchQuery('')
    } catch (err) {
      console.error(err)
      setError('An unexpected error occurred while analyzing the configuration.')
    } finally {
      setIsAnalyzing(false)
    }
  }

      // ---------------------------------------------------------------------------
      // Derived state: filters, summary, etc.
      // ---------------------------------------------------------------------------

      const severityFilteredFindings = showOnlyImportant
        ? findings.filter(
            (f) => f.severity === 'high' || f.severity === 'warning',
          )
        : findings

      const searchLower = searchQuery.trim().toLowerCase()
      const filteredFindings = searchLower
        ? severityFilteredFindings.filter((f) => {
            const haystack = [
              f.title || '',
              f.description || '',
              f.resourceId || '',
              f.resourceType || '',
              f.ruleId || '',
            ]
              .join(' ')
              .toLowerCase()
            return haystack.includes(searchLower)
          })
        : severityFilteredFindings

      const severityCounts = filteredFindings.reduce(
        (acc, f) => {
          acc[f.severity] = (acc[f.severity] || 0) + 1
          return acc
        },
        { high: 0, warning: 0, info: 0 },
      )

      const totalShown = filteredFindings.length
      const percent = (count) => (totalShown > 0 ? (count / totalShown) * 100 : 0)

      const resourceSets = {
        'security-group': new Set(),
        's3-bucket': new Set(),
        'iam-policy': new Set(),
      }

      const CATEGORY_LABELS = {
        network: 'Network / firewall',
        storage: 'Storage / buckets',
        iam: 'IAM / roles & policies',
      }

      const categoryCounts = filteredFindings.reduce(
        (acc, f) => {
          if (f.category && acc[f.category] !== undefined) {
            acc[f.category] += 1
          }
          return acc
        },
        { network: 0, storage: 0, iam: 0 },
      )

      filteredFindings.forEach((f) => {
        if (f.resourceType && f.resourceId && resourceSets[f.resourceType]) {
          resourceSets[f.resourceType].add(f.resourceId)
        }
      })

      const summarySecurityGroups = resourceSets['security-group'].size
      const summaryS3Buckets = resourceSets['s3-bucket'].size
      const summaryIamPolicies = resourceSets['iam-policy'].size

      const exportFindings = filteredFindings

      const canExport = hasAnalyzed && exportFindings.length > 0
      const canReset =
        configText.trim().length > 0 || findings.length > 0 || uploadedFileName


    // ---------------------------------------------------------------------------
    // Export handlers
    // ---------------------------------------------------------------------------
    
    const handleDownloadJson = () => {
        if (!canExport) return
        const platform = detectedPlatform || 'unknown'
        const payload = {
            generatedAt: new Date().toISOString(),
            platform,
            filters: {
            showOnlyImportant,
            searchQuery: searchQuery.trim() || null,
            },
            findings: exportFindings,
        }
        downloadTextFile(
            `cloud-misconfig-findings-${platform}.json`,
            JSON.stringify(payload, null, 2),
        )
        setExportMessage('Exported findings as JSON.')
        }

        const handleDownloadMarkdown = () => {
        if (!canExport) return
        const platformLabel =
            PLATFORM_LABELS[detectedPlatform] || 'Unknown platform'
        const markdown = findingsToMarkdown({
            findings: exportFindings,
            context: `Cloud Misconfiguration Scanner (${platformLabel})`,
        })
        downloadTextFile('cloud-misconfig-report.md', markdown)
        setExportMessage('Exported findings as Markdown.')
        }

        const handleCopyMarkdown = async () => {
        if (!canExport || typeof navigator === 'undefined' || !navigator.clipboard) {
            return
        }
        try {
            const platformLabel =
            PLATFORM_LABELS[detectedPlatform] || 'Unknown platform'
            const markdown = findingsToMarkdown({
            findings: exportFindings,
            context: `Cloud Misconfiguration Scanner (${platformLabel})`,
            })
            await navigator.clipboard.writeText(markdown)
            setExportMessage('Markdown report copied to clipboard.')
        } catch (err) {
            console.error(err)
            setError(
            'Could not copy report to clipboard. Your browser may block clipboard access.',
            )
        }
    }


    // ---------------------------------------------------------------------------
    // UI helpers
    // ---------------------------------------------------------------------------

    const renderSeverityBadge = (severity) => {
    const base =
        'inline-flex items-center rounded-full px-2 py-0.5 text-[0.65rem] font-medium border'
    if (severity === 'high') {
        return (
        <span
            className={`${base} bg-rose-500/10 text-rose-300 border-rose-500/40`}
        >
            High
        </span>
        )
    }
    if (severity === 'warning') {
        return (
        <span
            className={`${base} bg-amber-500/10 text-amber-300 border-amber-500/40`}
        >
            Warning
        </span>
        )
    }
    return (
        <span
        className={`${base} bg-sky-500/10 text-sky-300 border-sky-500/40`}
        >
        Info
        </span>
    )
    }

  const renderResourceBadge = (finding) => {
    if (!finding.resourceType || !finding.resourceId) return null

    let label = ''
    let classes =
      'inline-flex items-center rounded-full px-2 py-0.5 text-[0.65rem] border '

    if (finding.resourceType === 'security-group') {
      label = 'Security group'
      classes += 'bg-indigo-500/10 text-indigo-200 border-indigo-500/40'
    } else if (finding.resourceType === 's3-bucket') {
      label = 'Object storage bucket'
      classes += 'bg-teal-500/10 text-teal-200 border-teal-500/40'
    } else if (finding.resourceType === 'iam-policy') {
      label = 'IAM / role policy'
      classes += 'bg-fuchsia-500/10 text-fuchsia-200 border-fuchsia-500/40'
    } else {
      label = finding.resourceType
      classes += 'bg-slate-700/40 text-slate-200 border-slate-600'
    }

    return (
      <span className={classes}>
        {label}:{' '}
        <span
          className="font-mono ml-1 text-[0.63rem] leading-none translate-y-[0.5px]"
        >
          {finding.resourceId}
        </span>
      </span>
    )
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-8">
      {/* Header / nav */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onBack}
          className="text-xs px-2.5 py-1 rounded-full border border-slate-700 text-slate-300 hover:border-slate-500 hover:text-slate-100 transition"
        >
          ← Back to Hub
        </button>
        <div>
          <h2 className="text-lg sm:text-xl font-semibold">
            Cloud Misconfiguration Scanner
          </h2>
          <p className="text-xs sm:text-sm text-slate-300">
            Upload a static JSON configuration for security groups / firewall rules,
            storage buckets and IAM or role policies, and detect common
            misconfigurations - all in your browser.
          </p>
            {hasAnalyzed && detectedPlatform && detectedPlatform !== 'unknown' && (
              <p className="mt-1 text-[0.65rem] text-emerald-300">
                Detected platform:{' '}
                <span className="inline-flex items-center px-2 py-0.5 rounded-full border border-emerald-400 bg-emerald-500/10 text-emerald-100">
                  {PLATFORM_LABELS[detectedPlatform] || 'Unknown'}
                </span>
              </p>
            )}
            {hasAnalyzed && detectedPlatform === 'unknown' && (
            <p className="mt-1 text-[0.65rem] text-slate-400">
                Couldn&apos;t confidently match this config to AWS, Azure or GCP. That&apos;s ok,
                rules still run as long as the top-level keys match the schema.
            </p>
            )}
        </div>
      </div>

      {/* Grid */}
      <section className="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        {/* Input side */}
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-3">
            <label className="text-xs font-medium text-slate-200">
              Cloud configuration (JSON)
            </label>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleLoadSample}
                className="text-[0.65rem] px-2 py-0.5 rounded-full border border-emerald-400 text-emerald-100 hover:bg-emerald-500/10"
              >
                Load sample
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,application/json"
                onChange={handleFileChange}
                className="block text-xs text-slate-300 file:text-xs file:font-medium file:px-2.5 file:py-1 file:rounded-full file:border-0 file:bg-slate-700 file:text-slate-100 hover:file:bg-slate-600"
              />
            </div>
          </div>

          <textarea
            className="w-full min-h-[220px] text-xs sm:text-sm font-mono bg-slate-950/80 border border-slate-800 rounded-2xl p-3 outline-none resize-y focus:border-emerald-400/80 focus:ring-1 focus:ring-emerald-400/60"
            placeholder="// Paste cloud JSON configuration here or load the sample."
            value={configText}
            onChange={(e) => {
              const value = e.target.value
              setConfigText(value)
              setHasAnalyzed(false)
              setFindings([])
              setError(null)
              setExportMessage(null)
              setInputSource('manual')
              setUploadedFileName(null)
              setShowOnlyImportant(false)
              setSearchQuery('')
              setDetectedPlatform(null)
              if (fileInputRef.current) fileInputRef.current.value = ''
            }}
          />

          <p className="text-[0.65rem] text-slate-500">
            Source:{' '}
            {inputSource === 'file' && uploadedFileName
              ? (
                <>
                  Uploaded file:{' '}
                  <span className="text-slate-300">{uploadedFileName}</span>
                </>
                )
              : inputSource === 'sample'
                ? 'Built-in sample configuration'
                : 'Manual input'}
          </p>

          <div className="flex items-center justify-between gap-3">
            <p className="text-[0.65rem] text-slate-400">
              Tip: Use sanitized exports. Do not include real secrets or full account IDs if
              you plan to share the JSON.
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleReset}
                disabled={!canReset}
                className="inline-flex items-center justify-center px-5 py-2 rounded-full text-[0.8rem] font-medium border border-slate-600 text-slate-300 hover:text-white hover:border-slate-400 hover:ring-2 hover:ring-slate-500/30 active:bg-slate-800/40 transition disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Reset
              </button>
              <button
                type="button"
                onClick={handleAnalyze}
                disabled={isAnalyzing}
                className="inline-flex items-center justify-center px-5 py-2 rounded-full text-[0.8rem] font-semibold border border-emerald-400 text-slate-300 hover:bg-emerald-500/10 hover:ring-2 hover:ring-emerald-400/40 active:bg-emerald-500/20"
              >
                {isAnalyzing ? 'Analyzing…' : 'Analyze'}
              </button>
            </div>
          </div>

          {error && (
            <div className="text-xs text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-xl px-3 py-2">
              {error}
            </div>
          )}
          {exportMessage && !error && (
            <div className="text-[0.7rem] text-emerald-200 bg-emerald-500/10 border border-emerald-500/30 rounded-xl px-3 py-1.5">
              {exportMessage}
            </div>
          )}

          <SchemaHelpPanel />
        </div>

        {/* Results side */}
        <div className="space-y-3">
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-slate-100">
                Findings
              </h3>

              <div className="flex flex-wrap items-center gap-1.5">
                {hasAnalyzed && findings.length > 0 && (
                  <span className="text-[0.65rem] text-slate-400 mr-1">
                    {totalShown} of {findings.length} finding
                    {findings.length !== 1 ? 's' : ''} shown
                  </span>
                )}

                <button
                  type="button"
                  onClick={() => setShowOnlyImportant((prev) => !prev)}
                  className={
                    showOnlyImportant
                      ? 'text-[0.65rem] px-2 py-0.5 rounded-full border border-amber-400 text-amber-100 bg-amber-500/15'
                      : 'text-[0.65rem] px-2 py-0.5 rounded-full border border-emerald-400 text-emerald-100 bg-emerald-500/10'
                  }
                >
                  {showOnlyImportant ? 'High & Warning' : 'Show All'}
                </button>

                <button
                  type="button"
                  onClick={handleDownloadJson}
                  disabled={!canExport}
                  className="text-[0.65rem] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 hover:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  JSON
                </button>
                <button
                  type="button"
                  onClick={handleDownloadMarkdown}
                  disabled={!canExport}
                  className="text-[0.65rem] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 hover:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  .md
                </button>
                <button
                  type="button"
                  onClick={handleCopyMarkdown}
                  disabled={!canExport}
                  className="text-[0.65rem] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 hover:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Copy
                </button>
              </div>
            </div>

            {/* Search box */}
            <div>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by title, description, resource or rule id…"
                className="w-full text-[0.7rem] bg-slate-950/80 border border-slate-800 rounded-full px-3 py-1.5 outline-none focus:border-emerald-400/80 focus:ring-1 focus:ring-emerald-400/60"
              />
            </div>

            {hasAnalyzed && totalShown > 0 && (
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-[0.65rem]">
                  <span className="inline-flex items-center gap-1">
                    <span className="inline-block h-2 w-2 rounded-full bg-rose-500" />
                    High: {severityCounts.high}
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="inline-block h-2 w-2 rounded-full bg-amber-400" />
                    Warning: {severityCounts.warning}
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="inline-block h-2 w-2 rounded-full bg-sky-400" />
                    Info: {severityCounts.info}
                  </span>
                </div>

                <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                  <div className="flex h-full">
                    {severityCounts.high > 0 && (
                      <div
                        className="bg-rose-500"
                        style={{ width: `${percent(severityCounts.high)}%` }}
                      />
                    )}
                    {severityCounts.warning > 0 && (
                      <div
                        className="bg-amber-400"
                        style={{ width: `${percent(severityCounts.warning)}%` }}
                      />
                    )}
                    {severityCounts.info > 0 && (
                      <div
                        className="bg-sky-400"
                        style={{ width: `${percent(severityCounts.info)}%` }}
                      />
                    )}
                  </div>
                </div>
              </div>
            )}

            {hasAnalyzed && totalShown > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-[0.65rem] mt-1">
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-900/80 border border-slate-700">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400" />
                {CATEGORY_LABELS.network}: {categoryCounts.network}
                </span>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-900/80 border border-slate-700">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-sky-400" />
                {CATEGORY_LABELS.storage}: {categoryCounts.storage}
                </span>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-900/80 border border-slate-700">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-fuchsia-400" />
                {CATEGORY_LABELS.iam}: {categoryCounts.iam}
                </span>
            </div>
            )}
          </div>

          {/* Findings card */}
          <div className="border border-slate-800 rounded-2xl bg-slate-950/70 p-3 min-h-[200px] max-h-[380px] flex flex-col">
            {!hasAnalyzed && (
              <p className="text-xs text-slate-400">
                Run an analysis to see misconfigurations in your cloud security groups /
                firewall rules, storage buckets, and IAM / role policies.
              </p>
            )}

            {hasAnalyzed && findings.length === 0 && !error && (
              <div className="text-xs text-emerald-200 bg-emerald-500/10 border border-emerald-500/30 rounded-xl px-3 py-2">
                No high or warning-level issues detected based on the current rule set.
                You should still review the configuration against your organization&apos;s
                policies.
              </div>
            )}

            {hasAnalyzed &&
              findings.length > 0 &&
              totalShown === 0 &&
              (showOnlyImportant || searchQuery.trim()) &&
              !error && (
                <div className="text-xs text-slate-200 bg-slate-800/60 border border-slate-700 rounded-xl px-3 py-2">
                  No findings match the current filters/search. Clear the{' '}
                  <span className="font-semibold">High &amp; Warning only</span> filter or
                  empty the search box to see all results.
                </div>
              )}

            {hasAnalyzed && totalShown > 0 && (
              <ul className="space-y-2 overflow-auto pr-1 mt-1 flex-1">
                {filteredFindings.map((finding) => (
                  <li
                    key={finding.id}
                    className="rounded-xl border border-slate-800 bg-slate-900/80 p-3"
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center gap-2">
                          <h4 className="text-xs font-semibold text-slate-100">
                            {finding.title}
                          </h4>
                          {renderSeverityBadge(finding.severity)}
                        </div>
                        <p className="text-[0.7rem] text-slate-300">
                          {finding.description}
                        </p>
                        {renderResourceBadge(finding)}
                      </div>
                      {finding.location?.path && (
                        <span className="text-[0.65rem] text-sky-400">
                          {finding.location.path}
                        </span>
                      )}
                    </div>

                    <p className="text-[0.7rem] text-slate-300 mt-1">
                      <span className="font-semibold text-slate-200">
                        Remediation:
                      </span>{' '}
                      {finding.recommendation}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Summary card under findings */}
          <section className="border border-slate-800 rounded-2xl bg-slate-950/70 p-3">
            <h3 className="text-sm font-semibold text-slate-100 mb-1">
              Summary for current view
            </h3>

            {!hasAnalyzed && (
              <p className="text-[0.7rem] text-slate-400">
                Run an analysis to see a quick breakdown of affected resource types.
              </p>
            )}

            {hasAnalyzed && totalShown === 0 && !error && (
              <p className="text-[0.7rem] text-slate-400">
                No findings to summarize for the current filters/search.
              </p>
            )}

            {hasAnalyzed && totalShown > 0 && (
              <div className="space-y-1 text-[0.7rem] text-slate-300">
                <p>
                  This summary is based on findings currently shown (respecting the severity
                  filter and search box).
                </p>
                <ul className="list-disc list-inside space-y-0.5">
                  <li>
                    Security groups / firewall rules with issues:{' '}
                    <span className="font-semibold text-slate-100">
                      {summarySecurityGroups}
                    </span>
                  </li>
                  <li>
                    Storage buckets with issues:{' '}
                    <span className="font-semibold text-slate-100">
                      {summaryS3Buckets}
                    </span>
                  </li>
                  <li>
                    IAM / role policies with issues:{' '}
                    <span className="font-semibold text-slate-100">
                      {summaryIamPolicies}
                    </span>
                  </li>
                </ul>
              </div>
            )}
          </section>
        </div>
      </section>

      {/* Quick cloud hardening tips (AWS-biased for now) */}
      <section className="mt-2 border border-slate-800 rounded-2xl bg-slate-950/70 p-3">
        <h3 className="text-sm font-semibold text-slate-100 mb-1">
          Quick cloud hardening tips
        </h3>
        <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5">
          <li>Avoid 0.0.0.0/0 on administrative ports like 22 and 3389.</li>
          <li>Limit management access to jump hosts, VPNs or private networks.</li>
          <li>
            Use storage &quot;block public access&quot; features and bucket/container policies to prevent
            public data exposure.
          </li>
          <li>
            Prefer short-lived credentials and roles over long-lived access keys or static secrets.
          </li>
          <li>
            Limit IAM / role policies to the minimum required actions and resources instead of using
            wildcards.
          </li>
          <li>Enable encryption and versioning for buckets that store sensitive data.</li>
        </ul>
      </section>

      {/* About / privacy */}
      <section className="mt-4 pt-4 border-t border-slate-800">
        <AboutSection />
      </section>
    </div>
  )
}

export default CloudMisconfigScanner
