import React from 'react'
import Layout from './components/Layout.jsx'
import Home from './pages/Home.jsx'
import DockerAnalyzer from './tools/docker-analyzer/DockerAnalyzer.jsx'
import { useLocalStorage } from './hooks/useLocalStorage.js'

const TOOL_LABELS = {
  'docker-analyzer': 'Docker Image Security Analyzer',
}

function App() {
  const [activeTool, setActiveTool] = useLocalStorage('sw_active_tool', null)

  const handleSelectTool = (toolId) => {
    setActiveTool(toolId)
  }

  const handleBackToHome = () => {
    setActiveTool(null)
  }

  let content

  if (activeTool === 'docker-analyzer') {
    content = <DockerAnalyzer onBack={handleBackToHome} />
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
