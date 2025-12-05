import React, { useEffect, useState } from "react";
import Layout from './components/Layout.jsx'
import Home from './pages/Home.jsx'
import DockerAnalyzer from './tools/docker-analyzer/DockerAnalyzer.jsx'
import NetworkExposureMap from './tools/network-exposure-map/NetworkExposureMap.jsx'
import CloudMisconfigScanner from './tools/cloud-misconfig/CloudMisconfigScanner.jsx'
import { cleanupTemp, getPersistent, setPersistent } from "./utils/storage";

const TOOL_LABELS = {
  'docker-analyzer': 'Docker Image Security Analyzer',
  'network-exposure-map': 'Local Network Exposure Map',
  'cloud-misconfig': 'Cloud Misconfiguration Scanner',
}


function App() {
    useEffect(() => {
    cleanupTemp();
  }, []);
  
  const [activeTool, setActiveTool] = useState(() =>
    getPersistent('sw_active_tool', null),
  )

  useEffect(() => {
    setPersistent('sw_active_tool', activeTool)
  }, [activeTool])

  const handleSelectTool = (toolId) => {
    setActiveTool(toolId)
  }

  const handleBackToHome = () => {
    setActiveTool(null)
  }

  let content

  if (activeTool === 'docker-analyzer') {
    content = <DockerAnalyzer onBack={handleBackToHome} />
  } else if (activeTool === 'network-exposure-map') {
    content = <NetworkExposureMap onBack={handleBackToHome} />
  } else if (activeTool === 'cloud-misconfig') {
    content = <CloudMisconfigScanner onBack={handleBackToHome} />
  } else {
    content = <Home onSelectTool={handleSelectTool} />
  }

  const activeToolName = activeTool ? TOOL_LABELS[activeTool] : null

  return (
    <Layout activeToolName={activeToolName} onHomeClick={handleBackToHome}>
      {/* Tiny global fade for view transitions */}
      <div className="transition-opacity duration-200">
        {content}
      </div>
    </Layout>
  )
}

export default App
