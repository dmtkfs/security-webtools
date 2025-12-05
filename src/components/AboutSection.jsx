import React from 'react'

function AboutSection() {
  return (
    <section className="mt-8 border border-slate-800/80 rounded-2xl p-4 sm:p-5 bg-slate-950/70">
      <h2 className="text-sm font-semibold mb-1 text-slate-100">
        About & Privacy
      </h2>
      <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
        Security Webtools is a set of security utilities that run entirely on your device. 
        Analysis happens locally in the browser and nothing you load or upload is sent to a server. Your data stays on your machine at all times.
      </p>
    </section>
  )
}

export default AboutSection
