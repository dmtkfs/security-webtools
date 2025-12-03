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
            description="Paste or upload a Dockerfile to detect common security and hardening issues: unsafe base images, missing USER, risky ports, and more."
            status="available"
            onClick={() => onSelectTool('docker-analyzer')}
          />

          {/* Future tools */}
          <ToolCard
            title="HTTP Security Header Checker"
            description="Inspect HTTP response headers for missing or unsafe security directives."
            status="coming-soon"
          />
          <ToolCard
            title="Subdomain & DNS Surface Explorer"
            description="Discover and map subdomains to understand your external attack surface."
            status="coming-soon"
          />
          <ToolCard
            title="Kubernetes Manifest Linter"
            description="Check Kubernetes YAML manifests for common security misconfigurations."
            status="coming-soon"
          />
        </div>
      </section>

      <AboutSection />
    </div>
  )
}

export default Home
