import React, { useEffect, useState } from "react";
import { usePageMeta } from './hooks/usePageMeta';
import Layout from './components/Layout.jsx';
import Home from './pages/Home.jsx';
import DockerAnalyzer from './tools/docker-analyzer/DockerAnalyzer.jsx';
import NetworkExposureMap from './tools/network-exposure-map/NetworkExposureMap.jsx';
import CloudMisconfigScanner from './tools/cloud-misconfig/CloudMisconfigScanner.jsx';
import { cleanupTemp, getPersistent, setPersistent } from "./utils/storage";

const TOOL_LABELS = {
  'docker-analyzer': 'Docker Image Security Analyzer',
  'network-exposure-map': 'Local Network Exposure Map',
  'cloud-misconfig': 'Cloud Misconfiguration Scanner',
};

const TOOL_IDS = Object.keys(TOOL_LABELS);

// Helper to pick initial tool from hash or storage
function getInitialTool() {
  if (typeof window !== 'undefined') {
    const raw = window.location.hash || '';
    const hash = raw.startsWith('#') ? raw.slice(1) : raw;
    if (TOOL_IDS.includes(hash)) {
      return hash;
    }
  }
  return getPersistent('sw_active_tool', null);
}

function App() {
  useEffect(() => {
    cleanupTemp();
  }, []);

  // use hash-aware initial value
  const [activeTool, setActiveTool] = useState(getInitialTool);

  // sync to storage + update hash
  useEffect(() => {
    setPersistent('sw_active_tool', activeTool);

    if (typeof window !== 'undefined') {
      if (activeTool) {
        window.location.hash = activeTool;
      } else {
        // clear hash but keep path and query
        const { pathname, search } = window.location;
        const newUrl = pathname + (search || '');
        window.history.replaceState(null, '', newUrl);
      }
    }
  }, [activeTool]);

  const handleSelectTool = (toolId) => {
    setActiveTool(toolId);
  };

  const handleBackToHome = () => {
    setActiveTool(null);
  };

  let content;

  if (activeTool === 'docker-analyzer') {
    content = <DockerAnalyzer onBack={handleBackToHome} />;
  } else if (activeTool === 'network-exposure-map') {
    content = <NetworkExposureMap onBack={handleBackToHome} />;
  } else if (activeTool === 'cloud-misconfig') {
    content = <CloudMisconfigScanner onBack={handleBackToHome} />;
  } else {
    content = <Home onSelectTool={handleSelectTool} />;
  }

  const activeToolName = activeTool ? TOOL_LABELS[activeTool] : null;

  const baseTitle = 'Security Webtools: Local-first browser security tools';
  const baseDescription =
    'Local-first browser security tools for developers and defenders. No servers, no uploads, 100% privacy.';

  const pageTitle = activeToolName
    ? `${activeToolName} - Security Webtools`
    : baseTitle;

  const pageDescription = activeToolName
    ? `${activeToolName} tool in Security Webtools. Runs 100% locally in your browser.`
    : baseDescription;

  usePageMeta(pageTitle, pageDescription);

  return (
    <Layout activeToolName={activeToolName} onHomeClick={handleBackToHome}>
      <div className="transition-opacity duration-200">
        {content}
      </div>
    </Layout>
  );
}

export default App;
