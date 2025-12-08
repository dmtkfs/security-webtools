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
            v0.5.0 · Frontend-only
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

          <div className="flex flex-wrap items-center gap-3">
            <span>© {new Date().getFullYear()} Security Webtools</span>

            <a
              href="https://github.com/dmtkfs"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-400 hover:text-slate-200 underline"
              title="View author profile"
            >
              Created by dmtkfs
            </a>

            <a
              href="https://github.com/dmtkfs/security-webtools"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center text-slate-400 hover:text-slate-200"
              title="View repository on GitHub"
            >
              {/* GitHub Icon */}
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 24 24"
                fill="currentColor"
                className="w-4 h-4"
              >
                <path
                  fillRule="evenodd"
                  d="M12 2C6.48 2 2 6.586 2 12.255c0 4.503 2.865 8.319 6.839 9.676.5.093.683-.223.683-.496 
                    0-.245-.009-.894-.014-1.754-2.782.624-3.369-1.37-3.369-1.37-.455-1.178-1.11-1.492-1.11-1.492-.908-.637.07-.624.07-.624 
                    1.004.072 1.532 1.064 1.532 1.064.893 1.576 2.341 1.121 2.912.857.092-.665.35-1.121.636-1.379-2.22-.262-4.555-1.136-4.555-5.053
                    0-1.115.39-2.028 1.03-2.741-.104-.263-.447-1.323.098-2.757 0 0 .84-.275 2.75 1.048A9.39 9.39 0 0112 6.83c.85.004 
                    1.705.116 2.501.34 1.909-1.323 2.748-1.048 2.748-1.048.547 1.434.204 2.494.1 2.757.64.713 1.028 1.626 1.028 2.741 
                    0 3.928-2.339 4.787-4.566 5.044.359.32.679.949.679 1.915 0 1.382-.013 2.495-.013 2.834 0 .275.18.594.688.493 
                    3.97-1.36 6.833-5.175 6.833-9.675C22 6.586 17.523 2 12 2z"
                  clipRule="evenodd"
                />
              </svg>
            </a>
          </div>

          <span>Your data stays on your device.</span>
        </div>
</footer>

    </div>
  )
}

export default Layout
