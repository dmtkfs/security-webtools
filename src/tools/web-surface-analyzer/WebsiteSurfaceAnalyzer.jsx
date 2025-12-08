import React, { useState } from 'react';
import AboutSection from '../../components/AboutSection.jsx';
import { analyzeHeaders } from './headerRules.js';
import { analyzeHtmlForStack } from './stackFingerprint.js';
import { analyzeHtmlSecurity } from './htmlSecurityAudit.js';
import { downloadTextFile } from '../../utils/exportUtils.js';

function WebsiteSurfaceAnalyzer({ onBack }) {
  const [activeTab, setActiveTab] = useState('headers'); // 'headers' | 'stack' | 'html-security'

  // Mode 1: headers
  const [rawHeaders, setRawHeaders] = useState('');
  const [headerResult, setHeaderResult] = useState(null);
  const [headerError, setHeaderError] = useState('');
  const [isAnalyzingHeaders, setIsAnalyzingHeaders] = useState(false);
  const [headerCopied, setHeaderCopied] = useState(false);

  // Mode 2: stack
  const [rawHtml, setRawHtml] = useState('');
  const [stackResult, setStackResult] = useState(null);
  const [stackError, setStackError] = useState('');
  const [isAnalyzingStack, setIsAnalyzingStack] = useState(false);
  const [stackCopied, setStackCopied] = useState(false);

  // Mode 3: HTML security review
  const [rawHtmlSecurity, setRawHtmlSecurity] = useState('');
  const [htmlSecurityResult, setHtmlSecurityResult] = useState(null);
  const [htmlSecurityError, setHtmlSecurityError] = useState('');
  const [isAnalyzingHtmlSecurity, setIsAnalyzingHtmlSecurity] = useState(false);
  const [htmlSecurityCopied, setHtmlSecurityCopied] = useState(false);

  // Filters
  const [headerFilter, setHeaderFilter] = useState('all'); // 'all' | 'ok' | 'weak' | 'missing'
  const [htmlSeverityFilter, setHtmlSeverityFilter] = useState('all'); // 'all' | 'high' | 'medium' | 'low'
  const [stackCategoryFilter, setStackCategoryFilter] = useState('all'); // 'all' or category name

  // Deduplicate exposure factors
  const uniqueExposureFactors = stackResult
    ? Array.from(new Set(stackResult.exposureFactors || []))
    : [];

  // Slice out rendering-related findings
  const renderingFindings = stackResult
    ? (stackResult.techFindings || []).filter(
        (f) => f.category === 'Rendering'
      )
    : [];

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setHeaderCopied(false);
    setStackCopied(false);
    setHtmlSecurityCopied(false);
  };

  // -----------------------
  // Mode 1 handlers
  // -----------------------

  const handleAnalyzeHeaders = () => {
    const trimmed = rawHeaders.trim();
    if (!trimmed) {
      setHeaderError('Paste HTTP response headers first.');
      setHeaderResult(null);
      return;
    }

    try {
      setIsAnalyzingHeaders(true);
      const result = analyzeHeaders(trimmed);
      setHeaderResult(result);
      setHeaderError('');
      setHeaderCopied(false);
    } catch (err) {
      console.error('Header analysis error', err);
      setHeaderError('Something went wrong while analyzing headers.');
      setHeaderResult(null);
    } finally {
      setIsAnalyzingHeaders(false);
    }
  };

  const handleClearHeaders = () => {
    setRawHeaders('');
    setHeaderResult(null);
    setHeaderError('');
    setHeaderCopied(false);
    setHeaderFilter('all');
  };

  const handleExportHeadersMarkdown = () => {
    if (!headerResult) return;
    const md = buildHeadersMarkdown(rawHeaders, headerResult);
    downloadTextFile('website-headers-report.md', md);
  };

  const handleCopyHeadersSummary = async () => {
    if (!headerResult) return;
    const text = buildHeadersTextSummary(headerResult);

    try {
      if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        setHeaderCopied(true);
        setTimeout(() => setHeaderCopied(false), 2000);
      }
    } catch (err) {
      console.error('Clipboard copy failed', err);
    }
  };

  // -----------------------
  // Mode 2 handlers (stack fingerprint)
  // -----------------------

  const handleAnalyzeStack = () => {
    const trimmed = rawHtml.trim();
    if (!trimmed) {
      setStackError('Paste HTML source first.');
      setStackResult(null);
      return;
    }

    try {
      setIsAnalyzingStack(true);
      const result = analyzeHtmlForStack(trimmed);
      setStackResult(result);
      setStackError('');
      setStackCopied(false);
    } catch (err) {
      console.error('Stack analysis error', err);
      setStackError('Something went wrong while analyzing the HTML.');
      setStackResult(null);
    } finally {
      setIsAnalyzingStack(false);
    }
  };

  const handleClearStack = () => {
    setRawHtml('');
    setStackResult(null);
    setStackError('');
    setStackCopied(false);
    setStackCategoryFilter('all');
  };

  const handleExportStackMarkdown = () => {
    if (!stackResult) return;
    const md = buildStackMarkdown(rawHtml, stackResult);
    downloadTextFile('website-techstack-report.md', md);
  };

  const handleCopyStackSummary = async () => {
    if (!stackResult) return;
    const text = buildStackTextSummary(stackResult);

    try {
      if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        setStackCopied(true);
        setTimeout(() => setStackCopied(false), 2000);
      }
    } catch (err) {
      console.error('Clipboard copy failed', err);
    }
  };

  // -----------------------
  // Mode 3 handlers (HTML security review)
  // -----------------------

  const handleAnalyzeHtmlSecurityClick = () => {
    const trimmed = rawHtmlSecurity.trim();
    if (!trimmed) {
      setHtmlSecurityError('Paste HTML source first.');
      setHtmlSecurityResult(null);
      return;
    }

    try {
      setIsAnalyzingHtmlSecurity(true);
      const result = analyzeHtmlSecurity(trimmed);
      setHtmlSecurityResult(result);
      setHtmlSecurityError('');
      setHtmlSecurityCopied(false);
    } catch (err) {
      console.error('HTML security analysis error', err);
      setHtmlSecurityError('Something went wrong while analyzing the HTML.');
      setHtmlSecurityResult(null);
    } finally {
      setIsAnalyzingHtmlSecurity(false);
    }
  };

  const handleClearHtmlSecurity = () => {
    setRawHtmlSecurity('');
    setHtmlSecurityResult(null);
    setHtmlSecurityError('');
    setHtmlSecurityCopied(false);
    setHtmlSeverityFilter('all');
  };

  const handleExportHtmlSecurityMarkdown = () => {
    if (!htmlSecurityResult) return;
    const md = buildHtmlSecurityMarkdown(rawHtmlSecurity, htmlSecurityResult);
    downloadTextFile('website-html-security-report.md', md);
  };

  const handleCopyHtmlSecuritySummary = async () => {
    if (!htmlSecurityResult) return;
    const text = buildHtmlSecurityTextSummary(htmlSecurityResult);

    try {
      if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        setHtmlSecurityCopied(true);
        setTimeout(() => setHtmlSecurityCopied(false), 2000);
      }
    } catch (err) {
      console.error('Clipboard copy failed', err);
    }
  };

  // -----------------------
  // Render helpers
  // -----------------------

  const renderScoreBadge = (score, label) => {
    let color =
      'border-rose-500/60 bg-rose-500/10 text-rose-200';

    if (label === 'Hardened') {
      color = 'border-emerald-500/60 bg-emerald-500/10 text-emerald-200';
    } else if (label === 'Partially hardened') {
      color = 'border-amber-500/60 bg-amber-500/10 text-amber-200';
    }

    return (
      <div className="flex items-center gap-3">
        <div className="flex items-baseline gap-1">
          <span className="text-3xl font-semibold text-slate-50">
            {Number.isFinite(score) ? score : '--'}
          </span>
          <span className="text-xs uppercase tracking-wide text-slate-400">
            / 100
          </span>
        </div>
        <span
          className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${color}`}
        >
          {label}
        </span>
      </div>
    );
  };

  const renderHeaderStatusPill = (status) => {
    let cls = 'bg-slate-800/70 border-slate-600 text-slate-200';
    let label = status;

    if (status === 'ok') {
      cls = 'bg-emerald-500/10 border-emerald-500/60 text-emerald-200';
      label = 'OK';
    } else if (status === 'weak') {
      cls = 'bg-amber-500/10 border-amber-500/60 text-amber-200';
      label = 'Weak';
    } else if (status === 'missing') {
      cls = 'bg-rose-500/10 border-rose-500/60 text-rose-200';
      label = 'Missing';
    }

    return (
      <span
        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${cls}`}
      >
        {label}
      </span>
    );
  };

  const renderExposureBadge = (level) => {
    let cls = 'bg-slate-800/70 border-slate-600 text-slate-200';
    let label = 'Low exposure';

    if (level === 'moderate') {
      cls = 'bg-amber-500/10 border-amber-500/60 text-amber-200';
      label = 'Moderate exposure';
    } else if (level === 'elevated') {
      cls = 'bg-rose-500/10 border-rose-500/60 text-rose-200';
      label = 'Elevated exposure';
    }

    return (
      <span
        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${cls}`}
      >
        {label}
      </span>
    );
  };

  // -----------------------
  // JSX
  // -----------------------

  return (
    <div className="space-y-4 md:space-y-6">
      {/* Back to Hub */}
      <button
        type="button"
        onClick={onBack}
        className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/60 px-3 py-1 text-xs font-medium text-slate-200 hover:border-emerald-500/70 hover:text-emerald-300 hover:bg-slate-900 transition"
      >
        <span className="text-xs">←</span>
        <span>Back to Hub</span>
      </button>

      {/* Title + description */}
      <div className="space-y-2">
        <h1 className="text-xl md:text-2xl font-semibold text-slate-50 flex items-center gap-2">
          Web Surface Analyzer
        </h1>
        <p className="text-sm text-slate-300 max-w-2xl">
          Analyze website security from the outside-in. Paste HTTP response
          headers or page HTML to assess browser-side hardening, fingerprint
          the tech stack or scan for client-side security risks.
        </p>

        {/* Tab switcher */}
        <div className="mt-3 inline-flex rounded-full border border-slate-700 bg-slate-900/80 p-1 text-xs">
          <button
            type="button"
            onClick={() => handleTabChange('headers')}
            className={`px-3 py-1 rounded-full font-medium transition ${
              activeTab === 'headers'
                ? 'bg-emerald-500/20 text-emerald-200 border border-emerald-500/60 shadow-sm'
                : 'text-slate-300 hover:text-emerald-200'
            }`}
          >
            Headers
          </button>
          <button
            type="button"
            onClick={() => handleTabChange('stack')}
            className={`ml-1 px-3 py-1 rounded-full font-medium transition ${
              activeTab === 'stack'
                ? 'bg-emerald-500/20 text-emerald-200 border border-emerald-500/60 shadow-sm'
                : 'text-slate-300 hover:text-emerald-200'
            }`}
          >
            Tech Stack
          </button>
          <button
            type="button"
            onClick={() => handleTabChange('html-security')}
            className={`ml-1 px-3 py-1 rounded-full font-medium transition ${
              activeTab === 'html-security'
                ? 'bg-emerald-500/20 text-emerald-200 border border-emerald-500/60 shadow-sm'
                : 'text-slate-300 hover:text-emerald-200'
            }`}
          >
            HTML Security
          </button>
        </div>
      </div>

      {/* Mode 1: Security Header Analyzer */}
      {activeTab === 'headers' && (
        <div className="grid gap-4 md:gap-6 md:grid-cols-2 md:items-start">
          {/* Left: input */}
          <div className="space-y-3">
            <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3">
              <p className="text-xs text-slate-300">
                Paste raw HTTP <span className="font-semibold">response headers</span> from{' '}
                <span className="font-mono text-[11px]">curl -I</span>, Burp Suite
                or browser DevTools.
              </p>
              <div className="mt-2 rounded-lg bg-slate-900/80 px-3 py-2">
                <code className="text-[11px] text-slate-300">
                  curl -I https://example.com
                </code>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950/70">
              <textarea
                className="w-full rounded-2xl bg-transparent px-4 py-3 text-sm text-slate-100 outline-none resize-y min-h-[180px] placeholder:text-slate-500"
                spellCheck="false"
                value={rawHeaders}
                onChange={(e) => setRawHeaders(e.target.value)}
                placeholder={
                  'HTTP/2 200\n' +
                  'content-type: text/html; charset=UTF-8\n' +
                  'content-security-policy: ...\n' +
                  'strict-transport-security: max-age=63072000; includeSubDomains; preload\n' +
                  'x-frame-options: SAMEORIGIN\n' +
                  'x-content-type-options: nosniff\n' +
                  'referrer-policy: strict-origin-when-cross-origin\n' +
                  '...'
                }
              />
            </div>

            {headerError && (
              <p className="text-xs text-rose-300">{headerError}</p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleAnalyzeHeaders}
                disabled={isAnalyzingHeaders}
                className="inline-flex items-center gap-2 rounded-lg bg-emerald-500/90 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-emerald-400 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {isAnalyzingHeaders ? 'Analyzing…' : 'Analyze headers'}
              </button>
              <button
                type="button"
                onClick={handleClearHeaders}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-500 hover:bg-slate-900"
              >
                Clear
              </button>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              This mode reviews common browser security headers (CSP, HSTS, X-Frame-Options,
              X-Content-Type-Options, Referrer-Policy and modern cross-origin headers).
              It is heuristic and header-only: it does not probe endpoints or guarantee the
              absence of vulnerabilities.
            </p>
          </div>

          {/* Right: results */}
          <div className="space-y-3">
            {headerResult ? (
              <>
                {/* Summary card */}
                <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <p className="text-xs uppercase tracking-wide text-slate-400">
                        Header hardening score
                      </p>
                      {renderScoreBadge(
                        headerResult.overallScore,
                        headerResult.overallLabel
                      )}
                      <p className="mt-1 text-[11px] text-slate-400">
                        Detected{' '}
                        {
                          headerResult.headerFindings.filter(
                            (f) => f.status !== 'missing'
                          ).length
                        }
                        /{headerResult.headerFindings.length} core security headers
                        present.
                      </p>
                    </div>
                  </div>
                  <p className="text-xs text-slate-300">
                    {headerResult.overallMessage}
                  </p>
                  <p className="mt-1 text-[11px] text-slate-500">
                    Score is based on presence and strength of common browser
                    security headers (CSP, HSTS, XFO, X-CTO, Referrer-Policy). It
                    does not guarantee the absence of vulnerabilities.
                  </p>

                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={handleExportHeadersMarkdown}
                      className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900/80 px-2.5 py-1 text-[11px] font-medium text-slate-100 hover:border-emerald-500/70 hover:text-emerald-200"
                    >
                      Export report (.md)
                    </button>
                    <button
                      type="button"
                      onClick={handleCopyHeadersSummary}
                      className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900/80 px-2.5 py-1 text-[11px] font-medium text-slate-100 hover:border-emerald-500/70 hover:text-emerald-200"
                    >
                      {headerCopied ? 'Copied!' : 'Copy summary'}
                    </button>
                  </div>
                </div>

                {/* Header filter */}
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span className="text-slate-400">Filter:</span>
                  {['all', 'ok', 'weak', 'missing'].map((key) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => setHeaderFilter(key)}
                      className={`rounded-full border px-2.5 py-0.5 font-medium transition ${
                        headerFilter === key
                          ? 'border-emerald-500/70 bg-emerald-500/10 text-emerald-200'
                          : 'border-slate-700 bg-slate-900/60 text-slate-300 hover:border-slate-500 hover:text-emerald-200'
                      }`}
                    >
                      {key === 'all' ? 'All' : key.toUpperCase()}
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={() => setHeaderFilter('all')}
                    className="text-[11px] text-slate-400 hover:text-emerald-200 underline-offset-2 hover:underline ml-1"
                  >
                    Reset
                  </button>
                </div>

                {/* Per-header findings */}
                <div className="space-y-3">
                  {headerResult.headerFindings
                    .filter((f) =>
                      headerFilter === 'all' ? true : f.status === headerFilter
                    )
                    .map((finding) => (
                      <div
                        key={finding.name}
                        className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 space-y-1.5"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <p className="text-sm font-medium text-slate-50">
                              {finding.name}
                            </p>
                            <p className="mt-0.5 text-xs text-slate-300">
                              {finding.message}
                            </p>
                            {(finding.name === 'Content-Security-Policy' ||
                              finding.name === 'Strict-Transport-Security') && (
                              <p className="mt-1 text-[11px] text-amber-300">
                                High impact header: misconfiguration here can significantly
                                increase exposure to common web attacks.
                              </p>
                            )}
                          </div>
                          {renderHeaderStatusPill(finding.status)}
                        </div>
                        <p className="mt-1 text-[11px] text-slate-400">
                          Recommendation: {finding.recommendation}
                        </p>
                      </div>
                    ))}
                </div>
              </>
            ) : (
              <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-950/40 px-4 py-4 text-sm text-slate-300">
                <p className="font-medium text-slate-100">
                  Waiting for header input
                </p>
                <p className="mt-1 text-xs text-slate-400">
                  Paste response headers from a real site and run the analysis
                  to see a hardening score and per-header guidance for CSP,
                  HSTS, X-Frame-Options, X-Content-Type-Options and
                  Referrer-Policy.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Mode 2: Stack Fingerprinter */}
      {activeTab === 'stack' && (
        <div className="grid gap-4 md:gap-6 md:grid-cols-2 md:items-start">
          {/* Left: input */}
          <div className="space-y-3">
            <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3">
              <p className="text-xs text-slate-300">
                Paste the full <span className="font-semibold">HTML source</span> of the
                page (e.g. View Source → Select All → Copy). No URLs are fetched;
                detection is based only on the pasted HTML.
              </p>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950/70">
              <textarea
                className="w-full rounded-2xl bg-transparent px-4 py-3 text-sm text-slate-100 outline-none resize-y min-h-[200px] placeholder:text-slate-500"
                spellCheck="false"
                value={rawHtml}
                onChange={(e) => setRawHtml(e.target.value)}
                placeholder={
                  '<!doctype html>\n<html lang="en">\n  <head>\n    <meta name="generator" content="WordPress 6.x" />\n    <script src="https://cdn.shopify.com/..."></script>\n    <!-- etc. -->\n  </head>\n  <body>\n    <div id="__next">...</div>\n  </body>\n</html>'
                }
              />
            </div>

            {stackError && (
              <p className="text-xs text-rose-300">{stackError}</p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleAnalyzeStack}
                disabled={isAnalyzingStack}
                className="inline-flex items-center gap-2 rounded-lg bg-emerald-500/90 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-emerald-400 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {isAnalyzingStack ? 'Analyzing…' : 'Analyze HTML'}
              </button>
              <button
                type="button"
                onClick={handleClearStack}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-500 hover:bg-slate-900"
              >
                Clear
              </button>
            </div>

            <p className="text-[11px] text-slate-500">
              This mode fingerprints technologies using simple heuristics
              (WordPress, Drupal, React, Next.js, CDNs, analytics, etc.). It is
              not a vulnerability scanner and does not confirm any specific CVEs.
            </p>
          </div>

          {/* Right: results */}
          <div className="space-y-3">
            {stackResult ? (
              <>
                {/* Exposure summary */}
                <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <p className="text-xs uppercase tracking-wide text-slate-400">
                        Exposure profile
                      </p>
                      <p className="text-sm font-medium text-slate-50">
                        HTML-based tech fingerprint
                      </p>
                    </div>
                    {renderExposureBadge(stackResult.exposureLevel)}
                  </div>
                  <p className="text-xs text-slate-300">
                    {stackResult.summary}
                  </p>
                  {stackResult.exposureLevel === 'low' && (
                    <p className="mt-1 text-[11px] text-slate-400">
                      No clear CMS or e-commerce platform was identified. From HTML
                      alone, the visible attack surface looks relatively limited, but
                      this does not rule out vulnerabilities.
                    </p>
                  )}
                  <ul className="mt-2 space-y-1">
                    {uniqueExposureFactors.map((factor, idx) => (
                      <li
                        key={idx}
                        className="text-[11px] text-slate-400 leading-snug"
                      >
                        • {factor}
                      </li>
                    ))}
                  </ul>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={handleExportStackMarkdown}
                      className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900/80 px-2.5 py-1 text-[11px] font-medium text-slate-100 hover:border-emerald-500/70 hover:text-emerald-200"
                    >
                      Export report (.md)
                    </button>
                    <button
                      type="button"
                      onClick={handleCopyStackSummary}
                      className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900/80 px-2.5 py-1 text-[11px] font-medium text-slate-100 hover:border-emerald-500/70 hover:text-emerald-200"
                    >
                      {stackCopied ? 'Copied!' : 'Copy summary'}
                    </button>
                  </div>
                </div>

                {/* Rendering mode (heuristic) */}
                {renderingFindings.length > 0 && (
                  <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 space-y-2">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-medium text-slate-50">
                        Rendering mode (heuristic)
                      </p>
                    </div>
                    <div className="space-y-2">
                      {renderingFindings.map((finding, idx) => (
                        <div
                          key={`${finding.label}-${idx}`}
                          className="space-y-0.5"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <p className="text-xs font-medium text-slate-100">
                              {finding.label}
                            </p>
                            <ConfidencePill confidence={finding.confidence} />
                          </div>
                          <p className="text-[11px] text-slate-400">
                            Evidence: {finding.evidence}
                          </p>
                        </div>
                      ))}
                    </div>
                    <p className="mt-1 text-[11px] text-slate-500">
                      Rendering mode is inferred from HTML structure and framework
                      fingerprints only and may not match the full runtime behaviour.
                    </p>
                  </div>
                )}

                {/* Grouped tech findings by category */}
                <StackFindingsList
                  techFindings={stackResult.techFindings.filter(f => f.category !== 'Rendering')}
                  categoryFilter={stackCategoryFilter}
                  onCategoryFilterChange={setStackCategoryFilter}
                />
              </>
            ) : (
              <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-950/40 px-4 py-4 text-sm text-slate-300">
                <p className="font-medium text-slate-100">
                  Waiting for HTML input
                </p>
                <p className="mt-1 text-xs text-slate-400">
                  Paste HTML source from a page to detect high-level
                  technologies (CMS, JavaScript frameworks, hosting/CDNs,
                  analytics and more) and derive an exposure profile. Detection
                  is heuristic and based solely on the pasted HTML.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Mode 3: HTML Security Review */}
      {activeTab === 'html-security' && (
        <div className="grid gap-4 md:gap-6 md:grid-cols-2 md:items-start">
          {/* Left: input */}
          <div className="space-y-3">
            <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3">
              <p className="text-xs text-slate-300">
                Paste the full <span className="font-semibold">HTML source</span> of the
                page to scan for client-side security risks (inline event
                handlers, mixed-content hints, risky forms, comments with
                secrets, etc.). No URLs are fetched; analysis is based only on
                the pasted HTML.
              </p>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-950/70">
              <textarea
                className="w-full rounded-2xl bg-transparent px-4 py-3 text-sm text-slate-100 outline-none resize-y min-h-[200px] placeholder:text-slate-500"
                spellCheck="false"
                value={rawHtmlSecurity}
                onChange={(e) => setRawHtmlSecurity(e.target.value)}
                placeholder={
                  '<!doctype html>\n<html lang="en">\n  <head>\n    <!-- comments, scripts, forms, etc. -->\n  </head>\n  <body onload="init()">\n    <form method="get" action="http://example.com/login">...</form>\n  </body>\n</html>'
                }
              />
            </div>

            {htmlSecurityError && (
              <p className="text-xs text-rose-300">{htmlSecurityError}</p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleAnalyzeHtmlSecurityClick}
                disabled={isAnalyzingHtmlSecurity}
                className="inline-flex items-center gap-2 rounded-lg bg-emerald-500/90 px-3 py-1.5 text-xs font-medium text-slate-950 hover:bg-emerald-400 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {isAnalyzingHtmlSecurity ? 'Analyzing…' : 'Analyze HTML'}
              </button>
              <button
                type="button"
                onClick={handleClearHtmlSecurity}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-500 hover:bg-slate-900"
              >
                Clear
              </button>
            </div>

            <p className="text-[11px] text-slate-500">
              This mode surfaces risky client-side patterns only. It does not
              execute JavaScript or crawl links and it does not prove the
              presence of exploitable XSS or other vulnerabilities.
            </p>
            <div className="mt-2 rounded-2xl border border-slate-800 bg-slate-950/70 px-3 py-2">
              <p className="text-[11px] font-semibold text-slate-200 mb-1">
                Severity guide
              </p>
              <p className="text-[11px] text-slate-300">
                <span className="font-semibold text-rose-300">HIGH</span>{' '}
                marks patterns that can directly weaken HTTPS or expose credentials
                (for example, password forms using GET, HTTP form actions or
                <span className="font-mono text-[10px]"> javascript:</span> URLs).
              </p>
              <p className="mt-1 text-[11px] text-slate-300">
                <span className="font-semibold text-amber-300">MEDIUM</span>{' '}
                flags issues that expand attack surface or make CSP/XSS hardening
                harder (heavy inline JS/CSS, many third-party widgets, meta refresh
                redirects, target="_blank" without <span className="font-mono text-[10px]">rel="noopener"</span>).
              </p>
              <p className="mt-1 text-[11px] text-slate-300">
                <span className="font-semibold text-slate-200">LOW</span>{' '}
                indicates mostly hygiene-level or informational findings where impact is
                minimal (small inline JS/CSS, benign comments, basic mixed-content hints).
              </p>
            </div>
          </div>

          {/* Right: results */}
          <div className="space-y-3">
            {htmlSecurityResult ? (
              <>
                {/* Overview */}
                <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <p className="text-xs uppercase tracking-wide text-slate-400">
                        HTML security overview
                      </p>
                      <p className="text-sm font-medium text-slate-50">
                        Client-side security risks
                      </p>
                      <p className="text-xs text-slate-300 mt-1">
                        {htmlSecurityResult.overview}
                      </p>
                    </div>
                    {renderExposureBadge(htmlSecurityResult.riskLevel)}
                  </div>
                  {htmlSecurityResult.stats && (
                    <p className="mt-1 text-[11px] text-slate-400">
                      Stats: {htmlSecurityResult.stats.scriptBlockCount} script block
                      {htmlSecurityResult.stats.scriptBlockCount === 1 ? '' : 's'}
                      , {htmlSecurityResult.stats.formCount} form
                      {htmlSecurityResult.stats.formCount === 1 ? '' : 's'}
                      , {htmlSecurityResult.stats.inlineEventHandlers} inline{' '}
                      event handler
                      {htmlSecurityResult.stats.inlineEventHandlers === 1 ? '' : 's'}
                      , {htmlSecurityResult.stats.httpResourceCount} http:// resource
                      {htmlSecurityResult.stats.httpResourceCount === 1 ? '' : 's'}.
                    </p>
                  )}

                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={handleExportHtmlSecurityMarkdown}
                      className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900/80 px-2.5 py-1 text-[11px] font-medium text-slate-100 hover:border-emerald-500/70 hover:text-emerald-200"
                    >
                      Export report (.md)
                    </button>
                    <button
                      type="button"
                      onClick={handleCopyHtmlSecuritySummary}
                      className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900/80 px-2.5 py-1 text-[11px] font-medium text-slate-100 hover:border-emerald-500/70 hover:text-emerald-200"
                    >
                      {htmlSecurityCopied ? 'Copied!' : 'Copy summary'}
                    </button>
                  </div>
                </div>

                {/* Severity filter */}
                {htmlSecurityResult.issues.length > 0 && (
                  <div className="flex flex-wrap items-center gap-2 text-[11px]">
                    <span className="text-slate-400">Filter:</span>
                    {['all', 'high', 'medium', 'low'].map((key) => (
                      <button
                        key={key}
                        type="button"
                        onClick={() => setHtmlSeverityFilter(key)}
                        className={`rounded-full border px-2.5 py-0.5 font-medium transition ${
                          htmlSeverityFilter === key
                            ? 'border-emerald-500/70 bg-emerald-500/10 text-emerald-200'
                            : 'border-slate-700 bg-slate-900/60 text-slate-300 hover:border-slate-500 hover:text-emerald-200'
                        }`}
                      >
                        {key === 'all' ? 'All' : key.toUpperCase()}
                      </button>
                    ))}
                    <button
                      type="button"
                      onClick={() => setHtmlSeverityFilter('all')}
                      className="text-[11px] text-slate-400 hover:text-emerald-200 underline-offset-2 hover:underline ml-1"
                    >
                      Reset
                    </button>
                  </div>
                )}

                {/* Issues list */}
                <div className="space-y-3">
                  {htmlSecurityResult.issues.length === 0 ? (
                    <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3">
                      <p className="text-sm font-medium text-slate-100">
                        No obvious client-side risks
                      </p>
                      <p className="mt-1 text-xs text-slate-400">
                        No obvious risky patterns were detected in the markup, but this
                        does not guarantee the absence of vulnerabilities.
                      </p>
                    </div>
                  ) : (
                    htmlSecurityResult.issues
                      .filter((issue) =>
                        htmlSeverityFilter === 'all'
                          ? true
                          : issue.severity === htmlSeverityFilter
                      )
                      .map((issue, idx) => (
                        <div
                          key={`${issue.type}-${idx}`}
                          className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 space-y-1.5"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="text-sm font-medium text-slate-50">
                                {issue.title}
                              </p>
                              <p className="mt-0.5 text-xs text-slate-300">
                                {issue.detail}
                              </p>
                              {issue.recommendation && (
                                <p className="mt-1 text-[11px] text-slate-400">
                                  Recommendation: {issue.recommendation}
                                </p>
                              )}
                            </div>
                            <span
                              className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                                issue.severity === 'high'
                                  ? 'bg-rose-500/10 border-rose-500/60 text-rose-200'
                                  : issue.severity === 'medium'
                                  ? 'bg-amber-500/10 border-amber-500/60 text-amber-200'
                                  : 'bg-slate-800/70 border-slate-600 text-slate-200'
                              }`}
                            >
                              {issue.severity.toUpperCase()}
                            </span>
                          </div>
                          {issue.snippet && (
                            <pre className="mt-2 max-h-32 overflow-auto rounded-lg bg-slate-950/80 p-2 text-[11px] text-slate-400">
                              {issue.snippet}
                            </pre>
                          )}
                        </div>
                      ))
                  )}
                </div>
              </>
            ) : (
              <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-950/40 px-4 py-4 text-sm text-slate-300">
                <p className="font-medium text-slate-100">
                  Waiting for HTML input
                </p>
                <p className="mt-1 text-xs text-slate-400">
                  Paste HTML markup from a page to scan for inline handlers, forms
                  using GET for sensitive data, HTTP resources and other
                  client-side risks. Detection is heuristic and based solely on
                  the pasted HTML.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* About section */}
      <div className="pt-4 md:pt-6 border-t border-slate-800/60">
        <AboutSection />
      </div>
    </div>
  );
}

// -----------------------
// Helper components
// -----------------------

function StackFindingsList({
  techFindings,
  categoryFilter = 'all',
  onCategoryFilterChange,
}) {
  if (!techFindings || techFindings.length === 0) {
    return null;
  }

  const grouped = techFindings.reduce((acc, finding) => {
    if (!acc[finding.category]) acc[finding.category] = [];
    acc[finding.category].push(finding);
    return acc;
  }, {});

  const categories = Object.keys(grouped).sort();
  const activeCategory = categoryFilter || 'all';
  const filteredCategories =
    activeCategory === 'all'
      ? categories
      : categories.filter((c) => c === activeCategory);

  return (
    <div className="space-y-3">
      {categories.length > 1 && onCategoryFilterChange && (
        <div className="flex items-center justify-between gap-3">
          <p className="text-[11px] text-slate-400">Detected technologies</p>
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-400">Category:</span>
            <select
              value={activeCategory}
              onChange={(e) => onCategoryFilterChange(e.target.value)}
              className="bg-slate-900/80 border border-slate-700 rounded-md px-2 py-1 text-[11px] text-slate-100 focus:outline-none focus:border-emerald-500/70"
            >
              <option value="all">All categories</option>
              {categories.map((category) => (
                <option key={category} value={category}>
                  {category}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => onCategoryFilterChange('all')}
              className="text-[11px] text-slate-400 hover:text-emerald-200 underline-offset-2 hover:underline"
            >
              Reset
            </button>
          </div>
        </div>
      )}

      {filteredCategories.map((category) => (
        <div
          key={category}
          className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 space-y-2"
        >
          <div className="flex items-center justify-between gap-3">
            <p className="text-sm font-medium text-slate-50">
              {category}
            </p>
          </div>
          <div className="space-y-2">
            {grouped[category].map((finding, idx) => (
              <div key={`${finding.label}-${idx}`} className="space-y-0.5">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-medium text-slate-100">
                    {finding.label}
                  </p>
                  <ConfidencePill confidence={finding.confidence} />
                </div>
                <p className="text-[11px] text-slate-400">
                  Evidence: {finding.evidence}
                </p>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ConfidencePill({ confidence }) {
  let cls = 'bg-slate-800/70 border-slate-600 text-slate-200';
  let label = confidence;

  if (confidence === 'high') {
    cls = 'bg-emerald-500/10 border-emerald-500/60 text-emerald-200';
    label = 'High confidence';
  } else if (confidence === 'medium') {
    cls = 'bg-amber-500/10 border-amber-500/60 text-amber-200';
    label = 'Medium confidence';
  } else if (confidence === 'low') {
    cls = 'bg-slate-800/70 border-slate-600 text-slate-200';
    label = 'Low confidence';
  }

  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${cls}`}
    >
      {label}
    </span>
  );
}

// -----------------------
// Markdown & text builders
// -----------------------

function buildHeadersMarkdown(rawHeaders, result) {
  const lines = [];

  lines.push('# Web Surface Analyzer - Security Header Analysis');
  lines.push('');
  lines.push(`Overall score: **${result.overallScore}/100** (${result.overallLabel})`);
  lines.push('');
  lines.push(result.overallMessage);
  lines.push('');
  lines.push('> Score is based on presence and strength of CSP, HSTS, X-Frame-Options, X-Content-Type-Options and Referrer-Policy. This is not a vulnerability scan.');
  lines.push('');
  lines.push('## Raw headers');
  lines.push('');
  lines.push('```');
  lines.push(rawHeaders || '(none provided)');
  lines.push('```');
  lines.push('');
  lines.push('## Per-header findings');
  lines.push('');

  for (const finding of result.headerFindings) {
    lines.push(`### ${finding.name}`);
    lines.push(`- Status: **${finding.status.toUpperCase()}**`);
    lines.push(`- Message: ${finding.message}`);
    lines.push(`- Recommendation: ${finding.recommendation}`);
    lines.push('');
  }

  return lines.join('\n');
}

function buildHeadersTextSummary(result) {
  const parts = [];
  parts.push(
    `Header hardening score: ${result.overallScore}/100 (${result.overallLabel}).`
  );
  parts.push(result.overallMessage);

  const perHeader = result.headerFindings
    .map(
      (f) =>
        `${f.name}: ${f.status.toUpperCase()} - ${f.message} Recommendation: ${f.recommendation}`
    )
    .join('\n');

  return parts.join(' ') + '\n\n' + perHeader;
}

function buildStackMarkdown(rawHtml, result) {
  const lines = [];

  lines.push('# Web Surface Analyzer - Tech Stack Fingerprint');
  lines.push('');
  lines.push(`Exposure profile: **${result.exposureLevel.toUpperCase()}**`);
  lines.push('');
  lines.push(result.summary);
  lines.push('');
  lines.push('## Exposure factors');
  lines.push('');
  const factors = Array.from(new Set(result.exposureFactors || []));
  for (const factor of factors) {
    lines.push(`- ${factor}`);
  }
  lines.push('');
  lines.push('> Detection is heuristic and based only on the pasted HTML. This is not a vulnerability scan and does not confirm any specific CVEs.');
  lines.push('');
  lines.push('## Detected technologies');
  lines.push('');

  if (!result.techFindings || result.techFindings.length === 0) {
    lines.push('_No strong fingerprints detected._');
  } else {
    const grouped = result.techFindings.reduce((acc, f) => {
      if (!acc[f.category]) acc[f.category] = [];
      acc[f.category].push(f);
      return acc;
    }, {});

    for (const [category, findings] of Object.entries(grouped)) {
      lines.push(`### ${category}`);
      lines.push('');
      for (const f of findings) {
        lines.push(
          `- **${f.label}** (${f.confidence} confidence) - Evidence: ${f.evidence}`
        );
      }
      lines.push('');
    }
  }

  lines.push('## Raw HTML (optional snapshot)');
  lines.push('');
  lines.push('```html');
  lines.push(rawHtml || '(omitted)');
  lines.push('```');

  return lines.join('\n');
}

function buildStackTextSummary(result) {
  const parts = [];
  parts.push(
    `Exposure profile: ${result.exposureLevel.toUpperCase()}. ${result.summary}`
  );

  const factors = Array.from(new Set(result.exposureFactors || []))
    .map((f) => `- ${f}`)
    .join('\n');

  const techLines = result.techFindings
    .map(
      (f) =>
        `${f.category}: ${f.label} (${f.confidence} confidence). Evidence: ${f.evidence}`
    )
    .join('\n');

  return (
    parts.join(' ') +
    '\n\nExposure factors:\n' +
    factors +
    '\n\nDetected technologies:\n' +
    (techLines || '- None with strong confidence.')
  );
}

function buildHtmlSecurityMarkdown(rawHtml, result) {
  const lines = [];

  lines.push('# Web Surface Analyzer - HTML Security Review');
  lines.push('');
  lines.push(`Risk level: **${result.riskLevel.toUpperCase()}**`);
  lines.push('');
  lines.push(result.overview);
  lines.push('');
  if (result.stats) {
    lines.push(
      `Stats: ${result.stats.scriptBlockCount} script block(s), ${result.stats.formCount} form(s), ${result.stats.inlineEventHandlers} inline event handler(s), ${result.stats.httpResourceCount} http:// resource reference(s).`
    );
    lines.push('');
  }
  lines.push('> This is a heuristic review of client-side security risks only. It is not a full vulnerability scan and does not execute JavaScript.');
  lines.push('');
  lines.push('## Detected issues');
  lines.push('');

  if (!result.issues || result.issues.length === 0) {
    lines.push('_No obvious client-side security risks detected from HTML alone._');
  } else {
    for (const issue of result.issues) {
      lines.push(`### ${issue.title}`);
      lines.push(`- Severity: **${issue.severity.toUpperCase()}**`);
      lines.push(`- Type: \`${issue.type}\``);
      lines.push(`- Detail: ${issue.detail}`);
      if (issue.recommendation) {
        lines.push(`- Recommendation: ${issue.recommendation}`);
      }
      if (issue.snippet) {
        lines.push('');
        lines.push('```html');
        lines.push(issue.snippet);
        lines.push('```');
      }
      lines.push('');
    }
  }

  lines.push('## Raw HTML (optional snapshot)');
  lines.push('');
  lines.push('```html');
  lines.push(rawHtml || '(omitted)');
  lines.push('```');

  return lines.join('\n');
}

function buildHtmlSecurityTextSummary(result) {
  const parts = [];
  parts.push(
    `HTML security review - risk level: ${result.riskLevel.toUpperCase()}.`
  );
  parts.push(result.overview);

  const stats = result.stats
    ? `\n\nStats: ${result.stats.scriptBlockCount} script block(s), ${result.stats.formCount} form(s), ${result.stats.inlineEventHandlers} inline event handler(s), ${result.stats.httpResourceCount} http:// resource reference(s).`
    : '';

  const issueLines = (result.issues || [])
    .map(
      (issue) =>
        `- [${issue.severity.toUpperCase()}] ${issue.title}: ${issue.detail}${
          issue.recommendation ? ` Recommendation: ${issue.recommendation}` : ''
        }`
    )
    .join('\n');

  return (
    parts.join(' ') +
    stats +
    '\n\nIssues:\n' +
    (issueLines || '- No obvious client-side security risks detected from HTML alone.')
  );
}

export default WebsiteSurfaceAnalyzer;
