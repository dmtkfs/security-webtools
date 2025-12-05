import React, { useRef, useState, useEffect } from 'react'
import { analyzeDockerfile } from './dockerRules.js'
import AboutSection from '../../components/AboutSection.jsx'
import { getTemp, setTemp } from '../../utils/storage.js'
import { downloadTextFile, findingsToMarkdown } from '../../utils/exportUtils.js'

function DockerAnalyzer({ onBack }) {
  // Persisted state (temp storage with TTL)
  const [dockerfileText, setDockerfileText] = useState(() =>
    getTemp('sw_docker_text', ''),
  )
  const [findings, setFindings] = useState(() =>
    getTemp('sw_docker_findings', []),
  )
  const [hasAnalyzed, setHasAnalyzed] = useState(() =>
    getTemp('sw_docker_hasAnalyzed', false),
  )

  // Sync to temp storage
  useEffect(() => {
    setTemp('sw_docker_text', dockerfileText)
  }, [dockerfileText])

  useEffect(() => {
    setTemp('sw_docker_findings', findings)
  }, [findings])

  useEffect(() => {
    setTemp('sw_docker_hasAnalyzed', hasAnalyzed)
  }, [hasAnalyzed])

  // Ephemeral UI state
  const [error, setError] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [exportMessage, setExportMessage] = useState(null)

  // Track source + filename
  const [inputSource, setInputSource] = useState('manual') // 'manual' | 'file'
  const [uploadedFileName, setUploadedFileName] = useState(null)
  const fileInputRef = useRef(null)
  const textareaRef = useRef(null)

  // Filter toggle: show only High + Warning
  const [showOnlyImportant, setShowOnlyImportant] = useState(false)

  const handleFileChange = (event) => {
    const file = event.target.files?.[0]
    if (!file) return

    const lowerName = file.name.toLowerCase()

    // Block obviously wrong / potentially dangerous file types
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
      setError('This file type is not allowed. Please upload a plain-text Dockerfile.')
      setExportMessage(null)
      setInputSource('manual')
      setUploadedFileName(null)
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
      return
    }

    // Basic size limit to avoid huge files blowing up memory / localStorage
    const MAX_FILE_SIZE_BYTES = 512 * 1024 // 512 KB
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setError('File is too large. Please upload a Dockerfile under 512 KB.')
      setExportMessage(null)
      setInputSource('manual')
      setUploadedFileName(null)
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
      return
    }

    const reader = new FileReader()
    reader.onload = (e) => {
      const contents = e.target.result
      if (typeof contents !== 'string') return

      // Basic content check: must contain FROM
      const looksLikeDockerfile = /(^|\n)\s*FROM\s+/i.test(contents)
      if (!looksLikeDockerfile) {
        setError('This file does not look like a Dockerfile (no FROM instruction found).')
        setExportMessage(null)
        setInputSource('manual')
        setUploadedFileName(null)
        if (fileInputRef.current) {
          fileInputRef.current.value = ''
        }
        return
      }

      setDockerfileText(contents)
      setHasAnalyzed(false)
      setFindings([])
      setError(null)
      setExportMessage(null)
      setInputSource('file')
      setUploadedFileName(file.name)
      setShowOnlyImportant(false)
    }
    reader.onerror = () => {
      setError('Failed to read file. Please try again.')
      setInputSource('manual')
      setUploadedFileName(null)
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
    }
    reader.readAsText(file)
  }

    const handleAnalyze = () => {
      setError(null)
      setExportMessage(null)

      if (!dockerfileText.trim()) {
        setFindings([])
        setHasAnalyzed(false)
        setError('Please paste a Dockerfile or upload a file before analyzing.')
        return
      }

      const MAX_TEXT_LENGTH = 200_000 // ~200 KB of text
      if (dockerfileText.length > MAX_TEXT_LENGTH) {
        setFindings([])
        setHasAnalyzed(false)
        setError('Input is too large. Please analyze a Dockerfile under ~200 KB of text.')
        return
      }

      try {
        setIsAnalyzing(true)
        const results = analyzeDockerfile(dockerfileText)
        setFindings(results)
        setHasAnalyzed(true)        // ← only here, on success
      } catch (err) {
        console.error(err)
        setError('An unexpected error occurred while analyzing the Dockerfile.')
        setHasAnalyzed(false)
      } finally {
        setIsAnalyzing(false)
      }
    }

    const handleJumpToLine = (lineNumber) => {
    if (!textareaRef.current || !dockerfileText) return
    if (!lineNumber || lineNumber < 1) return

    const lines = dockerfileText.split(/\r?\n/)
    const clampedLine = Math.min(lineNumber, lines.length)

    // Compute character offset to start of that line
    let offset = 0
    for (let i = 0; i < clampedLine - 1; i += 1) {
      offset += lines[i].length + 1 // +1 for newline
    }

    const lineText = lines[clampedLine - 1] ?? ''
    const start = offset
    const end = offset + lineText.length

    const el = textareaRef.current
    el.focus()
    el.setSelectionRange(start, end)

    // Optional: small scroll tweak to bring line into middle of view
    const lineHeight = 18 // rough px, good enough
    el.scrollTop = Math.max(0, (clampedLine - 3) * lineHeight)
  }


  const handleReset = () => {
    setDockerfileText('')
    setFindings([])
    setHasAnalyzed(false)
    setError(null)
    setExportMessage(null)
    setInputSource('manual')
    setUploadedFileName(null)
    setShowOnlyImportant(false)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const canExport = hasAnalyzed && findings.length > 0

  const canReset =
    dockerfileText.trim().length > 0 ||
    findings.length > 0 ||
    uploadedFileName

  // Apply filter for UI display
  const filteredFindings = showOnlyImportant
    ? findings.filter(
        (f) => f.severity === 'high' || f.severity === 'warning',
      )
    : findings

  // Severity summary based on what is currently shown
  const severityCounts = filteredFindings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1
      return acc
    },
    { high: 0, warning: 0, info: 0 },
  )

  const totalShown = filteredFindings.length
  const percent = (count) =>
    totalShown > 0 ? (count / totalShown) * 100 : 0

  const handleDownloadJson = () => {
    if (!canExport) return
    const payload = {
      generatedAt: new Date().toISOString(),
      findings,
    }
    const json = JSON.stringify(payload, null, 2)
    downloadTextFile('docker-security-findings.json', json)
    setExportMessage('Exported findings as JSON.')
  }

  const handleDownloadMarkdown = () => {
    if (!canExport) return
    const markdown = findingsToMarkdown({ dockerfileText, findings })
    downloadTextFile('docker-security-report.md', markdown)
    setExportMessage('Exported findings as Markdown.')
  }

  const handleCopyMarkdown = async () => {
    if (!canExport || typeof navigator === 'undefined' || !navigator.clipboard) {
      return
    }
    try {
      const markdown = findingsToMarkdown({ dockerfileText, findings })
      await navigator.clipboard.writeText(markdown)
      setExportMessage('Markdown report copied to clipboard.')
    } catch (err) {
      console.error(err)
      setError('Could not copy report to clipboard. Your browser may block clipboard access.')
    }
  }

  const renderSeverityBadge = (severity) => {
    const baseClasses =
      'inline-flex items-center rounded-full px-2 py-0.5 text-[0.65rem] font-medium border'

    if (severity === 'high') {
      return (
        <span className={`${baseClasses} bg-rose-500/10 text-rose-300 border-rose-500/40`}>
          High
        </span>
      )
    }

    if (severity === 'warning') {
      return (
        <span className={`${baseClasses} bg-amber-500/10 text-amber-300 border-amber-500/40`}>
          Warning
        </span>
      )
    }

    return (
      <span className={`${baseClasses} bg-sky-500/10 text-sky-300 border-sky-500/40`}>
        Info
      </span>
    )
  }

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
            Docker Image Security Analyzer
          </h2>
          <p className="text-xs sm:text-sm text-slate-300">
            Analyze a Dockerfile for security and hardening issues. Everything runs locally on your device.
          </p>
        </div>
      </div>

      {/* Input + results grid */}
      <section className="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        {/* Input side */}
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-3">
            <label className="text-xs font-medium text-slate-200">
              Dockerfile content
            </label>
            <input
              ref={fileInputRef}
              type="file"
              accept=".dockerfile,.Dockerfile,.txt,text/plain"
              onChange={handleFileChange}
              className="block text-xs text-slate-300 file:text-xs file:font-medium file:px-2.5 file:py-1 file:rounded-full file:border-0 file:bg-slate-700 file:text-slate-100 hover:file:bg-slate-600"
            />
          </div>

          <textarea
            ref={textareaRef}
            className="w-full min-h-[220px] text-xs sm:text-sm font-mono bg-slate-950/80 border border-slate-800 rounded-2xl p-3 outline-none resize-y focus:border-emerald-400/80 focus:ring-1 focus:ring-emerald-400/60"
            placeholder={`Example:
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y openssh-server
EXPOSE 22
CMD ["bash"]`}
            value={dockerfileText}
            onChange={(e) => {
              const value = e.target.value
              setDockerfileText(value)
              setHasAnalyzed(false)
              setFindings([])
              setError(null)
              setExportMessage(null)

              // User is now editing manually; clear uploaded file state
              setInputSource('manual')
              setUploadedFileName(null)
              setShowOnlyImportant(false)
              if (fileInputRef.current) {
                fileInputRef.current.value = ''
              }
            }}
          />

          <p className="text-[0.65rem] text-slate-500">
            Source:{' '}
            {inputSource === 'file' && uploadedFileName
              ? <>Uploaded file: <span className="text-slate-300">{uploadedFileName}</span></>
              : 'Manual input'}
          </p>

          <div className="flex items-center justify-between gap-3">
            <p className="text-[0.65rem] text-slate-400">
              Tip: You can paste Dockerfiles directly from your editor or upload a file from disk.
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleReset}
                disabled={!canReset}
                className="
                inline-flex items-center justify-center
                px-5 py-2 rounded-full 
                text-[0.8rem] font-medium
                border border-slate-600 text-slate-300
                hover:text-white hover:border-slate-400 
                hover:ring-2 hover:ring-slate-500/30
                active:bg-slate-800/40
                transition
                disabled:opacity-40 disabled:cursor-not-allowed
              "
              >
                Reset
              </button>
                  <button
                  type="button"
                  onClick={handleAnalyze}
                  disabled={isAnalyzing}
                  className="
                    inline-flex items-center justify-center
                    px-5 py-2 rounded-full 
                    text-[0.8rem] font-semibold
                    border border-emerald-400 text-slate-300
                    hover:bg-emerald-500/10
                    hover:ring-2 hover:ring-emerald-400/40
                    active:bg-emerald-500/20
                  "
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
        </div>

        {/* Results side */}
        <div className="space-y-3">
          {/* Findings header + severity summary */}
          <div className="space-y-1">
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

            {hasAnalyzed && totalShown > 0 && (
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-[0.65rem]">
                  <span className="inline-flex items-center gap-1">
                    <span className="inline-block h-2 w-2 rounded-full bg-rose-500"></span>
                    High: {severityCounts.high}
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="inline-block h-2 w-2 rounded-full bg-amber-400"></span>
                    Warning: {severityCounts.warning}
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="inline-block h-2 w-2 rounded-full bg-sky-400"></span>
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
          </div>

          {/* Findings card */}
          <div className="border border-slate-800 rounded-2xl bg-slate-950/70 p-3 min-h-[200px] max-h-[380px] flex flex-col">
            {!hasAnalyzed && (
              <p className="text-xs text-slate-400">
                Run an analysis to see security and hardening findings for this Dockerfile.
              </p>
            )}

            {hasAnalyzed && findings.length === 0 && !error && dockerfileText.trim() && (
              <div className="text-xs text-emerald-200 bg-emerald-500/10 border border-emerald-500/30 rounded-xl px-3 py-2">
                No high or warning-level issues detected based on the current rule set.
                You should still review your Dockerfile against your organization&apos;s policies.
              </div>
            )}

            {hasAnalyzed &&
              findings.length > 0 &&
              totalShown === 0 &&
              showOnlyImportant &&
              !error && (
                <div className="text-xs text-slate-200 bg-slate-800/60 border border-slate-700 rounded-xl px-3 py-2">
                  Only informational findings exist for this Dockerfile.
                  Disable the <span className="font-semibold">High &amp; Warning only</span> filter
                  to see them.
                </div>
              )}

            {hasAnalyzed && totalShown > 0 && (
              <ul className="space-y-2 overflow-auto pr-1 mt-1 flex-1">
                {filteredFindings.map((finding) => (
                  <li
                    key={finding.id}
                    className="rounded-xl border border-slate-800 bg-slate-900/80 p-3"
                  >
                    <div className="flex items-baseline justify-between gap-2 mb-1">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <h4 className="text-xs font-semibold text-slate-100">
                            {finding.title}
                          </h4>
                          {renderSeverityBadge(finding.severity)}
                        </div>
                        <p className="text-[0.7rem] text-slate-300 mt-0.5">
                          {finding.description}
                        </p>
                      </div>
                      {finding.lineNumber && (
                        <button
                          type="button"
                          onClick={() => handleJumpToLine(finding.lineNumber)}
                          className="text-[0.65rem] text-sky-400 hover:underline hover:text-sky-300"
                        >
                          Line {finding.lineNumber}
                        </button>
                      )}
                    </div>

                    {finding.lineContent && (
                      <pre className="text-[0.65rem] bg-slate-950/80 border border-slate-800 rounded-lg px-2 py-1 mt-1 overflow-x-auto">
                        <code>{finding.lineContent}</code>
                      </pre>
                    )}

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
        </div>
      </section>

      {/* Quick Docker hardening tips */}
      <section className="mt-2 border border-slate-800 rounded-2xl bg-slate-950/70 p-3">
        <h3 className="text-sm font-semibold text-slate-100 mb-1">
          Quick Docker hardening tips
        </h3>
        <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5">
          <li>
            Prefer multi-stage builds to keep the final image small and free of build tools.
          </li>
          <li>
            Pin package and base image versions for reproducible builds (for example,{' '}
            <code className="font-mono">ubuntu:22.04</code>).
          </li>
          <li>
            Avoid installing compilers and heavy dev tools in the final runtime image.
          </li>
          <li>
            Use a non-root user whenever possible instead of running as{' '}
            <code className="font-mono">root</code>.
          </li>
          <li>
            Consider minimal or distroless images for production workloads.
          </li>
        </ul>
      </section>

      {/* About / privacy section with clear separation */}
      <section className="mt-4 pt-4 border-t border-slate-800">
        <AboutSection />
      </section>
    </div>
  )
}

export default DockerAnalyzer
