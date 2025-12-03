import React from 'react'

function Layout({ children, activeToolName, onHomeClick }) {
  const handleHomeClick = () => {
    if (onHomeClick) onHomeClick()
  }

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between gap-3">
          <div>
            <button
              type="button"
              onClick={handleHomeClick}
              className="text-left flex items-center gap-2 group"
            >
              <span className="inline-flex h-6 w-6 rounded-lg bg-emerald-500/10 border border-emerald-500/40 items-center justify-center text-emerald-300 text-xs font-semibold">
                SW
              </span>
              <div>
                <h1 className="text-xl font-semibold tracking-tight group-hover:text-emerald-300 transition-colors">
                  Security Webtools
                </h1>
                <p className="text-[0.65rem] text-slate-400">
                  Local-first security tools for developers & defenders
                </p>
              </div>
            </button>

            {activeToolName && (
              <div className="mt-1">
                <span className="inline-flex items-center rounded-full bg-slate-900/80 text-[0.65rem] text-slate-300 px-2 py-0.5 border border-slate-700">
                  Active tool: {activeToolName}
                </span>
              </div>
            )}
          </div>

          <span className="text-[0.65rem] text-slate-500">
            v0.1 · Frontend-only
          </span>
        </div>
      </header>

      <main className="flex-1">
        <div className="max-w-5xl mx-auto px-4 py-6">
          {children}
        </div>
      </main>

      <footer className="border-t border-slate-800 text-xs text-slate-500">
        <div className="max-w-5xl mx-auto px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <span>© {new Date().getFullYear()} Security Webtools</span>
          <span>All analysis is performed locally in your browser.</span>
        </div>
      </footer>
    </div>
  )
}

export default Layout
