import React from 'react'

function ToolCard({ title, description, status = 'available', onClick }) {
  const isDisabled = status !== 'available'

  let statusLabel = 'Available'
  let statusClasses =
    'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30'

  if (status === 'coming-soon') {
    statusLabel = 'Coming soon'
    statusClasses =
      'bg-slate-700/40 text-slate-300 border border-slate-600'
  }

  return (
    <button
      type="button"
      disabled={isDisabled}
      onClick={onClick}
      className={[
        'w-full text-left rounded-2xl p-4 sm:p-5 bg-slate-900/80 border border-slate-800 shadow-sm transition',
        isDisabled
          ? 'opacity-70 cursor-not-allowed'
          : 'hover:border-emerald-400/60 hover:shadow-lg hover:shadow-emerald-500/10 hover:-translate-y-0.5',
      ].join(' ')}
    >
      <div className="flex items-center justify-between mb-2 gap-3">
        <h3 className="text-base sm:text-lg font-semibold text-slate-50">
          {title}
        </h3>
        <span
          className={`text-[0.6rem] sm:text-[0.7rem] px-2 py-0.5 rounded-full ${statusClasses}`}
        >
          {statusLabel}
        </span>
      </div>
      <p className="text-xs sm:text-sm text-slate-300">
        {description}
      </p>
    </button>
  )
}

export default ToolCard
