import React from 'react'
import ToolCard from '../components/ToolCard.jsx'
import AboutSection from '../components/AboutSection.jsx'

function Home({ onSelectTool }) {
  return (
    <div className="space-y-6">
      <section>
        <h2 className="text-lg sm:text-xl font-semibold mb-1">
          Tool Hub
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 mb-4">
          Choose a tool to analyze and harden your security posture. All tools
          run fully in your browser with no backend.
        </p>

        <div className="grid gap-4 sm:grid-cols-2">
          <ToolCard
            title="Docker Image Security Analyzer"
            description="Paste or upload a Dockerfile to detect common security and hardening issues: unsafe base images, risky ports, secrets and more."
            status="available"
            onClick={() => onSelectTool('docker-analyzer')}
          />

          {/* Roadmap tools - coming soon */}
          <ToolCard
            title="Cloud Misconfiguration Scanner"
            description="Upload AWS, Azure or GCP JSON exports to flag risky network, storage, IAM misconfigurations and more."
            status="available"
            onClick={() => onSelectTool('cloud-misconfig')}
          />
          <ToolCard
            title="Threat Simulation Playground"
            description="Step through realistic attack timelines with sample logs, MITRE mappings and defender notes."
            onClick={() => onSelectTool('threat-playground')}
          />
          <ToolCard
            title="Web Surface Analyzer"
            description="Paste website headers or HTML to detect missing security controls, tech stack fingerprints and client-side risks."
            onClick={() => onSelectTool('web-surface-analyzer')}
          />
          <ToolCard
            title="Mini SIEM WebApp"
            description="Upload logs, apply detection rules and review alerts in a lightweight browser-based SIEM-style interface."
            status="coming-soon"
          />
          <ToolCard
            title="Cyber Hygiene Planner"
            description="Answer a short questionnaire and get a prioritized security roadmap tailored for small teams or projects."
            status="coming-soon"
          />
          <ToolCard
            title="Local Network Exposure Map"
            description="Import Nmap XML or generic JSON scan results to visualize hosts, open ports and basic exposure risk in a clean grid view."
            status="available"
            onClick={() => onSelectTool('network-exposure-map')}
          />
        </div>
      </section>

      <AboutSection />
    </div>
  )
}

export default Home
