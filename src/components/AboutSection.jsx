import React from 'react'

function AboutSection() {
  return (
    <section className="mt-8 border border-slate-800/80 rounded-2xl p-4 sm:p-5 bg-slate-950/70">
      <h2 className="text-sm font-semibold mb-1 text-slate-100">
        About & Privacy
      </h2>
      <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
        Security Webtools is a collection of browser-based security utilities.
        All analysis is performed locally in your browser. Any uploads and inputs never leave your device, and no data is sent to any
        external server or third-party API.
      </p>
    </section>
  )
}

export default AboutSection
