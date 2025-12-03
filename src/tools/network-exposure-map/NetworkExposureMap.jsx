// src/tools/network-exposure-map/NetworkExposureMap.jsx

import React, { useState, useMemo, useRef } from 'react'
import {
  parseScanFile,
  SAMPLE_SCAN_XML,
  SAMPLE_SCAN_JSON,
  HIGH_RISK_PORTS,
  HIGH_RISK_SERVICES,
  isHighRiskPortOrService,
  PORT_RISK_HINTS,
} from './scanParsers.js'
import AboutSection from '../../components/AboutSection.jsx'
import { downloadTextFile } from '../../utils/exportUtils.js'
import { useLocalStorage } from '../../hooks/useLocalStorage.js'

function riskBadgeClasses(level) {
  switch (level) {
    case 'high':
      return 'bg-rose-500/10 text-rose-300 border border-rose-500/40'
    case 'medium':
      return 'bg-amber-500/10 text-amber-300 border border-amber-500/40'
    default:
      return 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/40'
  }
}

function subnetKey(ip) {
  const parts = (ip || '').split('.')
  if (parts.length !== 4) return 'unknown'
  const [a, b, c] = parts
  return `${a}.${b}.${c}.0/24`
}

function labelForRisk(level) {
  switch (level) {
    case 'high':
      return 'High Risk'
    case 'medium':
      return 'Medium Risk'
    case 'low':
      return 'Low Risk'
    default:
      return 'Unknown Risk'
  }
}

function prettifyStatus(status) {
  if (!status || typeof status !== 'string') return 'Unknown'
  return status.charAt(0).toUpperCase() + status.slice(1)
}

// ----- Export helpers (local to this tool) -----

function hostsToJsonReport(hosts) {
  const payload = {
    generatedAt: new Date().toISOString(),
    hostCount: hosts.length,
    hosts: hosts.map((h) => ({
      ip: h.ip,
      hostname: h.hostname,
      status: h.status,
      riskLevel: h.riskLevel,
      riskReasons: h.riskReasons,
      ports: h.ports,
    })),
  }
  return JSON.stringify(payload, null, 2)
}

function hostsToMarkdownReport(hosts) {
  const lines = []

  lines.push('# Local Network Exposure Report')
  lines.push('')
  lines.push(
    `Generated at: ${new Date().toISOString()}  \nHosts in view: ${hosts.length}`,
  )
  lines.push('')
  lines.push('---')
  lines.push('')

  hosts.forEach((host) => {
    lines.push(`## ${host.ip}${host.hostname ? ` (${host.hostname})` : ''}`)
    lines.push('')
    lines.push(`- **Status:** ${prettifyStatus(host.status)}`)
    lines.push(`- **Risk level:** ${labelForRisk(host.riskLevel)}`)
    if (host.riskReasons && host.riskReasons.length > 0) {
      lines.push('- **Risk notes:**')
      host.riskReasons.forEach((reason) => {
        lines.push(`  - ${reason}`)
      })
    } else {
      lines.push('- **Risk notes:** _None_')
    }
    lines.push('')
    lines.push('### Open ports')
    if (!host.ports || host.ports.length === 0) {
      lines.push('')
      lines.push('_No open ports detected in this scan._')
    } else {
      lines.push('')
      lines.push('| Port | Protocol | Service | High-risk |')
      lines.push('|------|----------|---------|-----------|')
      host.ports.forEach((p) => {
        const high = isHighRiskPortOrService(p) ? 'Yes' : 'No'
        lines.push(
          `| ${p.port} | ${p.protocol} | ${p.service || ''} | ${high} |`,
        )
      })
    }
    lines.push('')
    lines.push('---')
    lines.push('')
  })

  return lines.join('\n')
}

function hostsToCsvReport(hosts) {
  const rows = []

  rows.push(
    [
      'ip',
      'hostname',
      'status',
      'riskLevel',
      'port',
      'protocol',
      'service',
      'isHighRisk',
    ].join(','),
  )

  hosts.forEach((h) => {
    if (!h.ports || h.ports.length === 0) {
      rows.push(
        [
          h.ip,
          h.hostname || '',
          h.status || '',
          h.riskLevel || '',
          '',
          '',
          '',
          '',
        ].join(','),
      )
    } else {
      h.ports.forEach((p) => {
        const isHigh = isHighRiskPortOrService(p) ? 'yes' : 'no'
        rows.push(
          [
            h.ip,
            h.hostname || '',
            h.status || '',
            h.riskLevel || '',
            p.port,
            p.protocol || '',
            p.service || '',
            isHigh,
          ].join(','),
        )
      })
    }
  })

  return rows.join('\n')
}

function NetworkExposureMap({ onBack }) {
  const [hosts, setHosts] = useLocalStorage('sw_netmap_hosts', [])
  const [error, setError] = useState(null)
  const [lastSource, setLastSource] = useState(null)
  const [manualInput, setManualInput] = useLocalStorage(
    'sw_netmap_manual',
    '',
  )
  const [showOnlyElevated, setShowOnlyElevated] = useLocalStorage(
    'sw_netmap_showElevated',
    false,
  )
  const [exportMessage, setExportMessage] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [onlyUpHosts, setOnlyUpHosts] = useLocalStorage(
    'sw_netmap_onlyUp',
    false,
  )
  const [viewMode, setViewMode] = useLocalStorage(
    'sw_netmap_viewMode',
    'hosts',
  )

  // Host detail side panel
  const [selectedHost, setSelectedHost] = useState(null)

  // Custom high-risk markers (UI-only, persisted locally)
  const [userHighRiskPorts, setUserHighRiskPorts] = useLocalStorage(
    'sw_netmap_custom_ports',
    [],
  )
  const [userHighRiskServices, setUserHighRiskServices] = useLocalStorage(
    'sw_netmap_custom_services',
    [],
  )
  const [newHighPort, setNewHighPort] = useState('')
  const [newHighService, setNewHighService] = useState('')

  const fileInputRef = useRef(null)

  // Helper: custom high-risk logic (adds on top of built-in)
  const isCustomHighRisk = (port) => {
    if (!port) return false
    const portNum = Number(port.port)
    const svc = (port.service || '').toString().toLowerCase()

    const fromPorts =
      Number.isFinite(portNum) && userHighRiskPorts.includes(portNum)
    const fromSvc =
      svc &&
      userHighRiskServices.some((marker) =>
        svc.includes(marker.toLowerCase()),
      )

    return fromPorts || fromSvc
  }

  // Derived list based on filters
  const visibleHosts = useMemo(() => {
    let filtered = hosts

    if (showOnlyElevated) {
      filtered = filtered.filter(
        (h) => h.riskLevel === 'high' || h.riskLevel === 'medium',
      )
    }

    if (onlyUpHosts) {
      filtered = filtered.filter((h) => h.status === 'up')
    }

    const q = searchQuery.trim().toLowerCase()
    if (q) {
      filtered = filtered.filter((h) => {
        const ip = (h.ip || '').toLowerCase()
        const name = (h.hostname || '').toLowerCase()
        return ip.includes(q) || name.includes(q)
      })
    }

    return filtered
  }, [hosts, showOnlyElevated, onlyUpHosts, searchQuery])

  const stats = useMemo(() => {
    const total = visibleHosts.length
    const up = visibleHosts.filter((h) => h.status === 'up').length
    const high = visibleHosts.filter((h) => h.riskLevel === 'high').length
    const medium = visibleHosts.filter((h) => h.riskLevel === 'medium').length
    const low = visibleHosts.filter((h) => h.riskLevel === 'low').length

    const denom = total || 1
    const dist = {
      lowPct: (low / denom) * 100,
      mediumPct: (medium / denom) * 100,
      highPct: (high / denom) * 100,
    }

    let openPortsTotal = 0
    const serviceCounts = {}

    visibleHosts.forEach((h) => {
      if (Array.isArray(h.ports)) {
        h.ports.forEach((p) => {
          openPortsTotal += 1
          const key = (
            p.service ||
            `${p.port}/${p.protocol || 'tcp'}`
          )
            .toString()
            .toLowerCase()
          serviceCounts[key] = (serviceCounts[key] || 0) + 1
        })
      }
    })

    return { total, up, high, medium, low, dist, openPortsTotal, serviceCounts }
  }, [visibleHosts])

  const topServices = useMemo(() => {
    const entries = Object.entries(stats.serviceCounts || {})
    if (entries.length === 0) return []
    return entries
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
  }, [stats.serviceCounts])

  const subnetBuckets = useMemo(() => {
    const buckets = {}
    visibleHosts.forEach((h) => {
      const key = subnetKey(h.ip)
      if (!buckets[key]) buckets[key] = []
      buckets[key].push(h)
    })
    return buckets
  }, [visibleHosts])

  const handleFileChange = (event) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = () => {
      try {
        const content = String(reader.result || '')
        const parsedHosts = parseScanFile(content)
        setHosts(parsedHosts)
        setError(null)
        setLastSource(file.name)
        setExportMessage(null)
      } catch (err) {
        console.error(err)
        setError(err.message || 'Failed to parse scan file')
        setHosts([])
        setLastSource(file.name)
        setExportMessage(null)
      }
    }
    reader.onerror = () => {
      setError('Failed to read file')
      setHosts([])
      setLastSource(file.name)
      setExportMessage(null)
    }

    reader.readAsText(file)
  }

  const loadFromSample = (type) => {
    try {
      const parsedHosts = parseScanFile(
        type === 'xml' ? SAMPLE_SCAN_XML : SAMPLE_SCAN_JSON,
      )
      setHosts(parsedHosts)
      setError(null)
      setLastSource(type === 'xml' ? 'Sample XML scan' : 'Sample JSON scan')
      setExportMessage(null)
    } catch (err) {
      console.error(err)
      setError('Failed to parse built-in sample scan')
      setHosts([])
      setLastSource(
        type === 'xml' ? 'Sample XML scan (error)' : 'Sample JSON scan (error)',
      )
      setExportMessage(null)
    }
  }

  const handleAnalyzeText = () => {
    const trimmed = manualInput.trim()
    if (!trimmed) {
      setError('Paste XML or JSON scan output first.')
      setHosts([])
      setLastSource('Manual input')
      setExportMessage(null)
      return
    }

    try {
      const parsedHosts = parseScanFile(trimmed)
      setHosts(parsedHosts)
      setError(null)
      setLastSource('Manual input')
      setExportMessage(null)
    } catch (err) {
      console.error(err)
      setError(err.message || 'Failed to parse manual input')
      setHosts([])
      setLastSource('Manual input')
      setExportMessage(null)
    }
  }

  const handleReset = () => {
    setHosts([])
    setError(null)
    setLastSource(null)
    setManualInput('')
    setShowOnlyElevated(false)
    setSearchQuery('')
    setOnlyUpHosts(false)
    setExportMessage(null)
    setSelectedHost(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const totalHosts = hosts.length
  const canExport = visibleHosts.length > 0

  const handleDownloadJson = () => {
    if (!canExport) return
    const json = hostsToJsonReport(visibleHosts)
    downloadTextFile('network-exposure-report.json', json)
    setExportMessage('Exported current view as JSON.')
  }

  const handleDownloadMarkdown = () => {
    if (!canExport) return
    const markdown = hostsToMarkdownReport(visibleHosts)
    downloadTextFile('network-exposure-report.md', markdown)
    setExportMessage('Exported current view as Markdown.')
  }

  const handleDownloadCsv = () => {
    if (!canExport) return
    const csv = hostsToCsvReport(visibleHosts)
    downloadTextFile('network-exposure-report.csv', csv)
    setExportMessage('Exported current view as CSV.')
  }

  const handleCopyMarkdown = async () => {
    if (!canExport || typeof navigator === 'undefined' || !navigator.clipboard)
      return
    try {
      const markdown = hostsToMarkdownReport(visibleHosts)
      await navigator.clipboard.writeText(markdown)
      setExportMessage('Markdown report copied to clipboard.')
    } catch (err) {
      console.error(err)
      setError(
        'Could not copy report to clipboard. Your browser may block clipboard access.',
      )
    }
  }

  const handleCopyHostMarkdown = async (host) => {
    if (!host || typeof navigator === 'undefined' || !navigator.clipboard) {
      return
    }
    try {
      const markdown = hostsToMarkdownReport([host])
      await navigator.clipboard.writeText(markdown)
      setExportMessage('Markdown report for this host copied to clipboard.')
    } catch (err) {
      console.error(err)
      setError(
        'Could not copy host report to clipboard. Your browser may block clipboard access.',
      )
    }
  }

  const handleAddHighPort = () => {
    const n = Number.parseInt(newHighPort, 10)
    if (!Number.isFinite(n) || n <= 0 || n > 65535) return
    if (!userHighRiskPorts.includes(n)) {
      setUserHighRiskPorts([...userHighRiskPorts, n])
    }
    setNewHighPort('')
  }

  const handleAddHighService = () => {
    const raw = newHighService.trim()
    if (!raw) return
    const normalized = raw.toLowerCase()
    if (
      !userHighRiskServices.some(
        (s) => s.toLowerCase() === normalized,
      )
    ) {
      setUserHighRiskServices([...userHighRiskServices, raw])
    }
    setNewHighService('')
  }

  const handleRemoveHighPort = (port) => {
    setUserHighRiskPorts(userHighRiskPorts.filter((p) => p !== port))
  }

  const handleRemoveHighService = (svc) => {
    setUserHighRiskServices(
      userHighRiskServices.filter((s) => s !== svc),
    )
  }

  return (
    <div className="space-y-6">
      {/* Header + back button */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <button
            type="button"
            onClick={onBack}
            className="text-xs inline-flex items-center gap-1 px-2 py-1 rounded-full border border-slate-700 text-slate-300 hover:border-emerald-400/60 hover:text-emerald-200 mb-2"
          >
            <span className="text-sm">←</span>
            Back to Hub
          </button>

          <h2 className="text-lg sm:text-xl font-semibold">
            Local Network Exposure Map
          </h2>
          <p className="text-xs sm:text-sm text-slate-300">
            Import existing scan results (Nmap XML or generic JSON) to visualize
            hosts, open ports, and exposure risk. All processed entirely in your
            browser with no backend or external APIs.
          </p>
        </div>
      </div>

      {/* Upload + controls + host view */}
      <section className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        {/* Left column: input */}
        <div className="space-y-3">
          <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-900/70 p-4 space-y-3">
            <div>
              <h3 className="text-sm font-semibold mb-1">
                Import scan result (XML or JSON)
              </h3>
              <p className="text-xs text-slate-300 mb-3">
                Supported formats:
                <br />
                - Nmap XML output (
                <code className="text-[0.7rem]">-oX</code>)
                <br />
                - Generic JSON (
                <code className="text-[0.7rem]">
                  {'{ hosts: [{ ip, hostname, status, ports[] }] }'}
                </code>
                )
              </p>

              <label className="block">
                <span className="sr-only">Upload scan file</span>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".xml,.json,.txt"
                  onChange={handleFileChange}
                  className="block w-full text-xs text-slate-200
                             file:mr-3 file:py-1.5 file:px-3 file:rounded-full
                             file:border-0 file:text-xs file:font-semibold
                             file:bg-emerald-500/90 file:text-slate-950
                             hover:file:bg-emerald-400/90 cursor-pointer"
                />
              </label>

              {lastSource && (
                <p className="mt-2 text-[0.7rem] text-slate-500">
                  Last loaded:{' '}
                  <span className="text-slate-300">{lastSource}</span>
                </p>
              )}
            </div>

            <div className="border-t border-slate-800 pt-3 space-y-2">
              <h4 className="text-xs font-semibold text-slate-200">
                Or paste scan output
              </h4>
              <textarea
                value={manualInput}
                onChange={(e) => setManualInput(e.target.value)}
                placeholder="Paste Nmap XML (-oX) or compatible JSON scan output here..."
                className="w-full min-h-[130px] rounded-xl bg-slate-950/60 border border-slate-800 px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-400/60"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={handleReset}
                  className="inline-flex items-center justify-center
                             px-4 py-1.5 rounded-full 
                             text-[0.75rem] font-medium
                             border border-slate-600 text-slate-300
                             hover:text-white hover:border-slate-400 
                             hover:ring-2 hover:ring-slate-500/30
                             active:bg-slate-800/40
                             transition"
                >
                  Reset
                </button>
                <button
                  type="button"
                  onClick={handleAnalyzeText}
                  className="text-xs px-3 py-1.5 rounded-full border border-emerald-500/70 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20"
                >
                  Analyze text
                </button>
              </div>
              {exportMessage && !error && (
                <div className="mt-2 text-[0.7rem] text-emerald-200 bg-emerald-500/10 border border-emerald-500/30 rounded-xl px-3 py-1.5">
                  {exportMessage}
                </div>
              )}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
            <h3 className="text-sm font-semibold">Quick demo</h3>
            <p className="text-xs text-slate-300">
              No scan file handy? Load one of the built-in samples to try the
              visualizer.
            </p>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => loadFromSample('xml')}
                className="text-xs px-3 py-1.5 rounded-full border border-slate-700 bg-slate-800/80 hover:border-emerald-400/70 hover:text-emerald-200"
              >
                Load sample XML
              </button>
              <button
                type="button"
                onClick={() => loadFromSample('json')}
                className="text-xs px-3 py-1.5 rounded-full border border-slate-700 bg-slate-800/80 hover:border-emerald-400/70 hover:text-emerald-200"
              >
                Load sample JSON
              </button>
            </div>

            <p className="text-[0.7rem] text-slate-400">
              All parsing is performed locally in your browser. Files and pasted
              text are never sent to any server.
            </p>
          </div>
        </div>

        {/* Right column: hosts view */}
        <div className="space-y-3">
          {error && (
            <div className="rounded-xl border border-rose-500/40 bg-rose-950/40 p-3 text-xs text-rose-100">
              <span className="font-semibold">Parse error: </span>
              {error}
            </div>
          )}

          {hosts.length === 0 && !error && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 text-xs text-slate-300">
              No hosts loaded yet. Upload a scan file, paste scan output, or use
              one of the sample scans to see the exposure map.
            </div>
          )}

          {hosts.length > 0 && (
            <>
              {/* Row 1: stats line */}
              <div className="text-xs text-slate-300">
                {stats.total > 0 ? (
                  <>
                    <span className="font-semibold text-slate-100">
                      {stats.total} host{stats.total === 1 ? '' : 's'}
                    </span>{' '}
                    in view (of {totalHosts}) · {stats.up} up ·{' '}
                    <span className="text-rose-300">
                      {stats.high} high-risk host
                      {stats.high === 1 ? '' : 's'}
                    </span>{' '}
                    · {stats.openPortsTotal} open port
                    {stats.openPortsTotal === 1 ? '' : 's'} total
                  </>
                ) : totalHosts > 0 ? (
                  <span className="text-[0.75rem] text-slate-400">
                    No hosts match the current filters.
                  </span>
                ) : (
                  <span className="text-[0.75rem] text-slate-400">
                    No hosts loaded yet.
                  </span>
                )}
              </div>

              {/* Row 2: search + only-up + view mode */}
              <div className="mt-1 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter by IP or hostname"
                    className="text-[0.65rem] px-2 py-0.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 placeholder:text-slate-500"
                  />

                  <label className="flex items-center gap-1 text-[0.65rem] text-slate-400">
                    <input
                      type="checkbox"
                      checked={onlyUpHosts}
                      onChange={(e) => setOnlyUpHosts(e.target.checked)}
                      className="h-3 w-3 rounded border-slate-600 bg-slate-900"
                    />
                    Only up
                  </label>

                  <span className="text-[0.65rem] text-slate-400">
                    {visibleHosts.length} of {totalHosts} host
                    {totalHosts === 1 ? '' : 's'} shown
                  </span>
                </div>

                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => setViewMode('hosts')}
                    className={
                      viewMode === 'hosts'
                        ? 'text-[0.65rem] px-2 py-0.5 rounded-full border border-emerald-400 text-emerald-100 bg-emerald-500/15'
                        : 'text-[0.65rem] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 bg-slate-900/60 hover:border-slate-500'
                    }
                  >
                    Hosts
                  </button>
                  <button
                    type="button"
                    onClick={() => setViewMode('subnets')}
                    className={
                      viewMode === 'subnets'
                        ? 'text-[0.65rem] px-2 py-0.5 rounded-full border border-emerald-400 text-emerald-100 bg-emerald-500/15'
                        : 'text-[0.65rem] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 bg-slate-900/60 hover:border-slate-500'
                    }
                  >
                    Subnets
                  </button>
                </div>
              </div>

              {/* Row 3: severity bar + filter + exports */}
              {stats.total > 0 && (
                <div className="mt-1 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between text-[0.7rem] text-slate-300">
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden flex">
                      {stats.dist.lowPct > 0 && (
                        <div
                          className="h-full bg-emerald-400"
                          style={{ width: `${stats.dist.lowPct}%` }}
                        />
                      )}
                      {stats.dist.mediumPct > 0 && (
                        <div
                          className="h-full bg-amber-400"
                          style={{ width: `${stats.dist.mediumPct}%` }}
                        />
                      )}
                      {stats.dist.highPct > 0 && (
                        <div
                          className="h-full bg-rose-500"
                          style={{ width: `${stats.dist.highPct}%` }}
                        />
                      )}
                    </div>
                    <div className="flex items-center gap-2 text-[0.65rem] text-slate-400">
                      <span className="inline-flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-emerald-400" />
                        Low
                      </span>
                      <span className="inline-flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-amber-400" />
                        Med
                      </span>
                      <span className="inline-flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-rose-500" />
                        High
                      </span>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        setShowOnlyElevated((prev) => !prev)
                      }
                      className={
                        showOnlyElevated
                          ? 'text-[0.65rem] px-2 py-0.5 rounded-full border border-amber-400 text-amber-100 bg-amber-500/15'
                          : 'text-[0.65rem] px-2 py-0.5 rounded-full border border-emerald-400 text-emerald-100 bg-emerald-500/10'
                      }
                    >
                      {showOnlyElevated ? 'High & Medium' : 'Show All'}
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
                      onClick={handleDownloadCsv}
                      disabled={!canExport}
                      className="text-[0.65rem] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 hover:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      CSV
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
              )}

              {viewMode === 'subnets' && stats.total > 0 && (
                <p className="text-[0.7rem] text-slate-400 mt-1">
                  Hosts are grouped by <code className="font-mono">/24</code>{' '}
                  subnet. Each circle represents a host (labelled with its last
                  IP octet). Color indicates the host&apos;s risk level.
                </p>
              )}

              {/* Host cards */}
              {viewMode === 'hosts' && (
                <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {visibleHosts.map((host) => (
                    <div
                      key={host.id}
                      className="rounded-2xl border border-slate-800 bg-slate-900/80 p-3 flex flex-col gap-2"
                    >
                      <div className="flex items-start justify-between mb-1">
                        <div>
                          <div className="text-sm font-semibold text-slate-100">
                            {host.ip}
                          </div>
                          {host.hostname && (
                            <div className="text-[0.7rem] text-slate-400">
                              {host.hostname}
                            </div>
                          )}
                          <div className="text-[0.65rem] text-slate-400">
                            Status: {prettifyStatus(host.status)}
                          </div>
                        </div>

                        <span
                          className={[
                            'text-[0.65rem] px-2 py-0.5 rounded-full',
                            riskBadgeClasses(host.riskLevel),
                          ].join(' ')}
                        >
                          {labelForRisk(host.riskLevel)}
                        </span>
                      </div>

                      {host.riskReasons && host.riskReasons.length > 0 && (
                        <ul className="list-disc list-inside text-[0.65rem] text-slate-300 space-y-0.5">
                          {host.riskReasons.map((reason, idx) => (
                            <li key={`${host.id}-reason-${idx}`}>{reason}</li>
                          ))}
                        </ul>
                      )}

                      <div className="mt-1">
                        <div className="text-[0.7rem] font-semibold text-slate-200">
                          Open ports ({host.ports?.length || 0})
                        </div>
                        {(!host.ports || host.ports.length === 0) && (
                          <p className="text-[0.65rem] text-slate-400">
                            No open ports detected in this scan.
                          </p>
                        )}
                        {host.ports && host.ports.length > 0 && (
                          <ul className="mt-0.5 space-y-0.5 text-[0.65rem] text-slate-200">
                            {host.ports.map((p) => {
                              const baseHigh = isHighRiskPortOrService(p)
                              const customHigh = isCustomHighRisk(p)
                              const isHigh = baseHigh || customHigh
                              const portKey = `${host.id}-${p.port}-${p.protocol}`

                              const serviceKey =
                                p.service && p.service.toLowerCase()
                              const hint =
                                PORT_RISK_HINTS[p.port] ||
                                (serviceKey && PORT_RISK_HINTS[serviceKey])

                              const baseTextClasses = isHigh
                                ? 'font-mono text-rose-200'
                                : 'font-mono text-slate-200'

                              const hasHint = isHigh && !!hint

                              const serviceTextClasses = hasHint
                                ? 'text-[0.65rem] text-rose-300 italic underline decoration-dotted cursor-help'
                                : isHigh
                                ? 'text-[0.65rem] text-rose-300 italic'
                                : 'text-[0.65rem] text-slate-400'

                              return (
                                <li
                                  key={portKey}
                                  className={`relative flex items-center gap-2 px-1 py-0.5 rounded-lg ${
                                    hasHint
                                      ? 'group hover:bg-rose-500/5'
                                      : ''
                                  }`}
                                >
                                  <span className={baseTextClasses}>
                                    {p.port}/{p.protocol}
                                  </span>
                                  {p.service && (
                                    <span className={serviceTextClasses}>
                                      ({p.service})
                                    </span>
                                  )}

                                  {hasHint && (
                                    <div className="pointer-events-none absolute left-0 top-full z-30 mt-1 hidden w-64 rounded-xl border border-rose-500/40 bg-slate-950/95 p-2 text-[0.65rem] text-slate-100 shadow-lg group-hover:block">
                                      {hint.title && (
                                        <div className="font-semibold mb-0.5">
                                          {hint.title}
                                        </div>
                                      )}
                                      {hint.summary && (
                                        <div className="text-[0.65rem] text-rose-100">
                                          {hint.summary}
                                        </div>
                                      )}
                                      {hint.remediation && (
                                        <div className="mt-1 text-[0.65rem] text-rose-200">
                                          <span className="font-semibold">
                                            Remediation:
                                          </span>{' '}
                                          {hint.remediation}
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </li>
                              )
                            })}
                          </ul>
                        )}
                      </div>

                      <button
                        type="button"
                        onClick={() => setSelectedHost(host)}
                        className="mt-1 self-start text-[0.65rem] text-emerald-300 hover:text-emerald-200 hover:underline"
                      >
                        View host details
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Subnet topology-ish view */}
              {viewMode === 'subnets' && (
                <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {Object.entries(subnetBuckets).map(([subnet, subnetHosts]) => {
                    const highCount = subnetHosts.filter(
                      (h) => h.riskLevel === 'high',
                    ).length
                    const upCount = subnetHosts.filter(
                      (h) => h.status === 'up',
                    ).length

                    return (
                      <div
                        key={subnet}
                        className="rounded-2xl border border-slate-800 bg-slate-900/80 p-3"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div>
                            <div className="text-xs font-semibold text-slate-100">
                              {subnet}
                            </div>
                            <div className="text-[0.65rem] text-slate-400">
                              {subnetHosts.length} host
                              {subnetHosts.length !== 1 ? 's' : ''} · {upCount}{' '}
                              up ·{' '}
                              <span className="text-rose-300">
                                {highCount} high-risk
                              </span>
                            </div>
                          </div>
                        </div>

                        <div className="flex flex-wrap gap-1 mt-1">
                          {subnetHosts.map((h) => {
                            const risk = h.riskLevel
                            const baseClasses =
                              'w-7 h-7 rounded-full border flex items-center justify-center'
                            const riskClasses =
                              risk === 'high'
                                ? 'bg-rose-500/70 border-rose-300'
                                : risk === 'medium'
                                ? 'bg-amber-400/80 border-amber-300'
                                : 'bg-emerald-400/80 border-emerald-300'

                            return (
                              <button
                                key={h.id}
                                type="button"
                                onClick={() => setSelectedHost(h)}
                                className={`${baseClasses} ${riskClasses}`}
                                title={`${h.ip}${
                                  h.hostname ? ` (${h.hostname})` : ''
                                }`}
                              >
                                <span
                                  className="text-[0.7rem] font-semibold text-white"
                                  style={{
                                    textShadow:
                                      '0 0 3px rgba(0,0,0,0.9)',
                                  }}
                                >
                                  {h.ip.split('.').slice(-1)[0]}
                                </span>
                              </button>
                            )
                          })}
                        </div>

                        <ul className="mt-2 space-y-0.5 text-[0.65rem] text-slate-300">
                          {subnetHosts.map((h) => (
                            <li key={`${subnet}-${h.id}`}>
                              • {h.ip}
                              {h.hostname ? ` (${h.hostname})` : ''} -{' '}
                              {labelForRisk(h.riskLevel)}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )
                  })}
                </div>
              )}

              {/* Per-service stats */}
              {stats.openPortsTotal > 0 && topServices.length > 0 && (
                <div className="mt-3 rounded-2xl border border-slate-800 bg-slate-900/70 p-3 text-[0.7rem] text-slate-300">
                  <div className="text-xs font-semibold text-slate-100 mb-1">
                    Top exposed services in current view
                  </div>
                  <ul className="space-y-0.5">
                    {topServices.map(([svc, count]) => (
                      <li
                        key={svc}
                        className="flex items-center justify-between"
                      >
                        <span className="font-mono">
                          {svc}
                        </span>
                        <span className="text-slate-400">
                          {count} host{count === 1 ? '' : 's'}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {visibleHosts.length === 0 && (
                <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-3 text-xs text-slate-300">
                  No hosts match the current filter. Try disabling the{' '}
                  <span className="font-semibold">High &amp; Medium</span>{' '}
                  filter or clearing the search box to see all hosts.
                </div>
              )}
            </>
          )}
        </div>
      </section>

      {/* Full-width hardening tips + custom risk profile */}
      <section className="mt-2 border border-slate-800 rounded-2xl bg-slate-950/70 p-3 space-y-2">
        <h3 className="text-sm font-semibold text-slate-100 mb-1">
          Quick exposure hardening tips
        </h3>
        <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5">
          <li>
            Treat <span className="font-semibold">High Risk</span> hosts as
            priority: confirm they are meant to be reachable and restrict access
            to trusted networks or VPNs.
          </li>
          <li>
            Remote admin and database services (RDP, SMB, SQL, VNC, etc.)
            should not be exposed directly to the internet.
          </li>
          <li>
            Use network segmentation and firewall rules to separate management
            interfaces from user traffic.
          </li>
          <li>
            Regularly rescan from different vantage points (internal and
            external) to catch new exposure.
          </li>
        </ul>
        <p className="text-[0.65rem] text-slate-400 mt-2">
          This tool treats certain ports and services as high-risk when open,
          plus any custom markers you add below:
        </p>
        <p className="text-[0.65rem] font-mono text-slate-300">
          Built-in ports: {HIGH_RISK_PORTS.join(', ')}
        </p>
        <p className="text-[0.65rem] font-mono text-slate-300">
          Built-in services: {HIGH_RISK_SERVICES.join(', ')}
        </p>

        {/* Custom risk profile controls */}
        <div className="mt-3 border-t border-slate-800 pt-2 space-y-2">
          <p className="text-[0.65rem] text-slate-400">
            Add extra ports or service name fragments to also treat as
            high-risk in this visualizer (stored only in your browser).
          </p>

          <div className="flex flex-wrap gap-2 items-center">
            <input
              type="number"
              min="1"
              max="65535"
              value={newHighPort}
              onChange={(e) => setNewHighPort(e.target.value)}
              placeholder="Add port (e.g. 8443)"
              className="w-32 text-[0.65rem] px-2 py-1 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-500"
            />
            <button
              type="button"
              onClick={handleAddHighPort}
              className="text-[0.65rem] px-2 py-1 rounded-full border border-emerald-400 text-emerald-100 bg-emerald-500/10 hover:bg-emerald-500/20"
            >
              Add port
            </button>

            <input
              type="text"
              value={newHighService}
              onChange={(e) => setNewHighService(e.target.value)}
              placeholder="Add service name fragment"
              className="flex-1 min-w-40 text-[0.65rem] px-2 py-1 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder:text-slate-500"
            />
            <button
              type="button"
              onClick={handleAddHighService}
              className="text-[0.65rem] px-2 py-1 rounded-full border border-emerald-400 text-emerald-100 bg-emerald-500/10 hover:bg-emerald-500/20"
            >
              Add service
            </button>
          </div>

          {(userHighRiskPorts.length > 0 ||
            userHighRiskServices.length > 0) && (
            <div className="text-[0.65rem] text-slate-300 space-y-1">
              {userHighRiskPorts.length > 0 && (
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-slate-400">Custom ports:</span>
                  {userHighRiskPorts.map((p) => (
                    <button
                      key={p}
                      type="button"
                      onClick={() => handleRemoveHighPort(p)}
                      className="px-2 py-0.5 rounded-full bg-slate-800 border border-slate-600 text-[0.65rem] hover:border-rose-400 hover:text-rose-200"
                    >
                      {p}
                      <span className="ml-1 text-[0.6rem]">×</span>
                    </button>
                  ))}
                </div>
              )}
              {userHighRiskServices.length > 0 && (
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-slate-400">Custom services:</span>
                  {userHighRiskServices.map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => handleRemoveHighService(s)}
                      className="px-2 py-0.5 rounded-full bg-slate-800 border border-slate-600 text-[0.65rem] hover:border-rose-400 hover:text-rose-200"
                    >
                      {s}
                      <span className="ml-1 text-[0.6rem]">×</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </section>

      {/* Shared About & Privacy section */}
      <section className="mt-4 pt-4 border-t border-slate-800">
        <AboutSection />
      </section>

      {/* Host detail side panel */}
      {selectedHost && (
        <div
          className="fixed inset-0 z-40 flex items-start justify-end bg-black/40"
          onClick={(e) => {
            if (e.target === e.currentTarget) setSelectedHost(null)
          }}
        >
          <div className="h-full w-full max-w-md bg-slate-950 border-l border-slate-800 p-4 overflow-y-auto">
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="text-sm font-semibold text-slate-100">
                  {selectedHost.ip}
                </div>
                {selectedHost.hostname && (
                  <div className="text-xs text-slate-400">
                    {selectedHost.hostname}
                  </div>
                )}
                <div className="text-[0.7rem] text-slate-400">
                  Status: {prettifyStatus(selectedHost.status)}
                </div>
              </div>
              <div className="flex flex-col items-end gap-2">
                <span
                  className={[
                    'text-[0.65rem] px-2 py-0.5 rounded-full',
                    riskBadgeClasses(selectedHost.riskLevel),
                  ].join(' ')}
                >
                  {labelForRisk(selectedHost.riskLevel)}
                </span>
                <button
                  type="button"
                  onClick={() => setSelectedHost(null)}
                  className="text-[0.7rem] text-slate-400 hover:text-slate-100"
                >
                  Close ✕
                </button>
              </div>
            </div>

            {selectedHost.riskReasons &&
              selectedHost.riskReasons.length > 0 && (
                <div className="mb-3">
                  <h4 className="text-xs font-semibold text-slate-200 mb-1">
                    Risk notes
                  </h4>
                  <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5">
                    {selectedHost.riskReasons.map((reason, idx) => (
                      <li key={`${selectedHost.id}-detail-reason-${idx}`}>
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

            <div className="mb-3">
              <h4 className="text-xs font-semibold text-slate-200 mb-1">
                Open ports ({selectedHost.ports?.length || 0})
              </h4>
              {(!selectedHost.ports ||
                selectedHost.ports.length === 0) && (
                <p className="text-[0.7rem] text-slate-400">
                  No open ports detected in this scan.
                </p>
              )}
              {selectedHost.ports && selectedHost.ports.length > 0 && (
                <ul className="mt-0.5 space-y-0.5 text-[0.7rem] text-slate-200">
                  {selectedHost.ports.map((p) => {
                    const baseHigh = isHighRiskPortOrService(p)
                    const customHigh = isCustomHighRisk(p)
                    const isHigh = baseHigh || customHigh
                    const portKey = `${selectedHost.id}-detail-${p.port}-${p.protocol}`

                    const serviceKey =
                      p.service && p.service.toLowerCase()
                    const hint =
                      PORT_RISK_HINTS[p.port] ||
                      (serviceKey && PORT_RISK_HINTS[serviceKey])

                    const baseTextClasses = isHigh
                      ? 'font-mono text-rose-200'
                      : 'font-mono text-slate-200'

                    const hasHint = isHigh && !!hint

                    const serviceTextClasses = hasHint
                      ? 'text-[0.65rem] text-rose-300 italic underline decoration-dotted cursor-help'
                      : isHigh
                      ? 'text-[0.65rem] text-rose-300 italic'
                      : 'text-[0.65rem] text-slate-400'

                    return (
                      <li
                        key={portKey}
                        className={`relative flex items-center gap-2 px-1 py-0.5 rounded-lg ${
                          hasHint ? 'group hover:bg-rose-500/5' : ''
                        }`}
                      >
                        <span className={baseTextClasses}>
                          {p.port}/{p.protocol}
                        </span>
                        {p.service && (
                          <span className={serviceTextClasses}>
                            ({p.service})
                          </span>
                        )}

                        {hasHint && (
                          <div className="pointer-events-none absolute left-0 top-full z-30 mt-1 hidden w-64 rounded-xl border border-rose-500/40 bg-slate-950/95 p-2 text-[0.65rem] text-slate-100 shadow-lg group-hover:block">
                            {hint.title && (
                              <div className="font-semibold mb-0.5">
                                {hint.title}
                              </div>
                            )}
                            {hint.summary && (
                              <div className="text-[0.65rem] text-rose-100">
                                {hint.summary}
                              </div>
                            )}
                            {hint.remediation && (
                              <div className="mt-1 text-[0.65rem] text-rose-200">
                                <span className="font-semibold">
                                  Remediation:
                                </span>{' '}
                                {hint.remediation}
                              </div>
                            )}
                          </div>
                        )}
                      </li>
                    )
                  })}
                </ul>
              )}
            </div>

            <button
              type="button"
              onClick={() => handleCopyHostMarkdown(selectedHost)}
              className="text-[0.7rem] px-3 py-1.5 rounded-full border border-slate-600 text-slate-200 hover:border-emerald-400 hover:text-emerald-200"
            >
              Copy host report as Markdown
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default NetworkExposureMap
