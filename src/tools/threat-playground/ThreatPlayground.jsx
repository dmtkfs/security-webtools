import React, { useState, useMemo, useEffect } from 'react';
import AboutSection from '../../components/AboutSection.jsx';
import { SCENARIOS, getScenarioById } from './scenarios.js';
import { getPersistent, setPersistent } from '../../utils/storage.js';
import { downloadTextFile } from '../../utils/exportUtils.js';

function difficultyBadgeClasses(level) {
  switch (level) {
    case 'beginner':
      return 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/40';
    case 'intermediate':
      return 'bg-amber-500/10 text-amber-300 border border-amber-500/40';
    case 'advanced':
      return 'bg-rose-500/10 text-rose-300 border border-rose-500/40';
    default:
      return 'bg-slate-700/50 text-slate-200 border border-slate-600';
  }
}

function difficultyLabel(level) {
  switch (level) {
    case 'beginner':
      return 'Beginner';
    case 'intermediate':
      return 'Intermediate';
    case 'advanced':
      return 'Advanced';
    default:
      return 'Unknown';
  }
}

// Treat text between backticks as inline code
function renderWithInlineCode(text) {
  if (!text) return null;
  const parts = text.split(/(`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      const inner = part.slice(1, -1);
      return (
        <code
          key={idx}
          className="font-mono text-[0.7rem] bg-slate-900/80 px-1 py-0.5 rounded"
        >
          {inner}
        </code>
      );
    }
    return <span key={idx}>{part}</span>;
  });
}

// Build correct MITRE ATT&CK URL, including sub-techniques (e.g. T1110.003 → T1110/003)
function mitreTechniqueUrl(techId) {
  if (!techId || typeof techId !== 'string') {
    return 'https://attack.mitre.org/techniques/';
  }

  const parts = techId.split('.');

  // Sub-technique like "T1110.003" → "T1110/003/"
  if (parts.length === 2 && parts[0] && parts[1]) {
    return `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`;
  }

  // Regular technique like "T1071"
  return `https://attack.mitre.org/techniques/${techId}/`;
}

// Randomization helpers

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomHex(length) {
  const chars = 'abcdef0123456789';
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

function randomLabel(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

function random10NetIp(thirdOctet = null) {
  const o2 = randomInt(0, 255);
  const o3 = thirdOctet != null ? thirdOctet : randomInt(0, 255);
  const o4 = randomInt(10, 250);
  return `10.${o2}.${o3}.${o4}`;
}

const scenarioVarsCache = Object.create(null);

// Scenario-specific variable builder
function buildScenarioVarsForId(scenarioId) {
  switch (scenarioId) {
    // 1) Phishing → Endpoint compromise
    case 'phishing-endpoint-compromise': {
      const userIndex = randomInt(1, 99);
      const userSam = `USER${userIndex.toString().padStart(2, '0')}`;
      const hostName = `WKS-${userSam}`;
      return {
        emailMsgId: randomHex(8),
        emailRecipient: `${userSam.toLowerCase()}@org.local`,
        proxySrcIp: random10NetIp(5),
        proxyDstIp: `203.0.113.${randomInt(10, 220)}`,
        userSam,
        hostName,
      };
    }
    // 2) Web App SQLi
    case 'web-sqli-data-access':
      return {
        webClientIp: `203.0.113.${randomInt(10, 200)}`,
        webReqId1: `web-01-${randomLabel(3)}`,
        webReqId2: `web-01-${randomLabel(3)}`,
        webReqId3: `web-01-${randomLabel(3)}`,
      };
    // 3) Public bucket exfil
    case 'public-cloud-bucket-exfil':
      return {
        bucketName: `corp-backups-${randomLabel(4)}`,
        anonIp: `198.51.100.${randomInt(10, 200)}`,
      };
    // 4) VPN impossible travel
    case 'vpn-impossible-travel':
      return {
        idpIp1: `203.0.113.${randomInt(20, 230)}`,
        idpIp2: `198.51.100.${randomInt(20, 230)}`,
        vpnAssignedIp: random10NetIp(20),
        userName: 'alice', 
      };
    // 5) OAuth consent phish
    case 'oauth-mailbox-abuse':
      return {
        userName: 'bob',
        appId: `${randomHex(8)}-${randomHex(4)}-${randomHex(4)}-${randomHex(4)}-${randomHex(12)}`,
      };
    // 6) RDP + credential dump
    case 'lateral-rdp-credential-dump':
      return {
        rdpSrcIp: random10NetIp(30),
        rdpWorkstation: `WKS-OPS${randomInt(1, 9).toString().padStart(2, '0')}`,
        rdpFileServer: `FSRV-0${randomInt(1, 4)}`,
        rdpAppServer: `APP-0${randomInt(1, 4)}`,
      };
    // 7) AWS key abuse
    case 'aws-key-programmatic-abuse':
      return {
        attackerIp: `185.100.${randomInt(40, 110)}.${randomInt(2, 240)}`,
        backupBucket: `prod-app-backups-${randomLabel(3)}`,
      };
    // 8) Docker crypto-miner
    case 'docker-crypto-miner':
      return {
        nodeName: `node-${randomInt(1, 5).toString().padStart(2, '0')}`,
        containerName: `${randomLabel(6)}_${randomLabel(5)}`,
        registryHost: `registry.${randomLabel(6)}.net`,
      };
    // 9) DNS tunneling
    case 'dns-tunnel-beaconing':
      return {
        dnsClientIp: random10NetIp(30),
        dnsC2Ip: `203.0.113.${randomInt(20, 220)}`,
        dnsC2Domain: `example-${randomLabel(3)}.net`,
        dnsLabel1: randomLabel(18),
        dnsLabel2: randomLabel(20),
      };
    // 10) ICS Modbus
    case 'ics-modbus-unauthorized-writes':
      return {
        icsClientIp: `10.100.${randomInt(2, 40)}.${randomInt(10, 250)}`,
        plcIp: `10.100.${randomInt(1, 10)}.${randomInt(10, 250)}`,
      };
    // 11) Golden Ticket
    case 'ad-golden-ticket-detection':
      return {
        backupSvc: `DOMAIN\\\\backup-svc-${randomInt(1, 3)}`,
        adminSvc: `DOMAIN\\\\svc-admin-${randomInt(1, 3)}`,
        adIp: `10.50.${randomInt(2, 40)}.${randomInt(10, 250)}`,
        fileServer: `FSRV-0${randomInt(1, 3)}`,
      };
    // 12) CI secret abuse
    case 'ci-secret-abuse-cloud':
      return {
        ciIp: `185.220.${randomInt(90, 120)}.${randomInt(5, 250)}`,
        repoName: `org/app-service-${randomLabel(3)}`,
        ciRoleName: `ci-bot-${randomLabel(4)}`,
        secretsBucket: `prod-secrets-backups-${randomLabel(3)}`,
      };
    // 13) Password spray against IdP
    case 'idp-password-spray-lockout':
      return {
        sprayIp: `198.51.100.${randomInt(10, 220)}`,
        sprayUser1: `user${randomInt(1, 30).toString().padStart(2, '0')}`,
        sprayUser2: `user${randomInt(31, 60).toString().padStart(2, '0')}`,
        sprayUser3: `user${randomInt(61, 90).toString().padStart(2, '0')}`,
      };
    // 14) SaaS file download anomaly
    case 'saas-download-anomaly':
      return {
        saasUser: `user${randomInt(10, 99).toString().padStart(2, '0')}`,
        saasIp: `203.0.113.${randomInt(20, 230)}`,
        saasAppName: 'CloudDrive Pro',
      }; 

    default:
      return {};
  }
}

// Export helpers

function scenarioToMarkdown(scenario, scenarioVars = {}) {
  if (!scenario) return '# Threat Simulation Scenario\n\n_No scenario selected._\n';

  const lines = [];

  lines.push(`# ${scenario.title}`);
  lines.push('');
  lines.push(`**Difficulty:** ${difficultyLabel(scenario.difficulty)}`);
  if (scenario.tags && scenario.tags.length) {
    lines.push('');
    lines.push(`**Tags:** ${scenario.tags.join(', ')}`);
  }
  lines.push('');
  if (scenario.summary) {
    lines.push(`**Summary:** ${scenario.summary}`);
    lines.push('');
  }
  if (scenario.objective) {
    lines.push(`**Objective:** ${scenario.objective}`);
    lines.push('');
  }
  if (scenario.defenderFocus) {
    lines.push(`**Defender focus:** ${scenario.defenderFocus}`);
    lines.push('');
  }

  if (scenario.overallMitreTechniques && scenario.overallMitreTechniques.length) {
    lines.push('## MITRE ATT&CK (overall)');
    lines.push('');
    scenario.overallMitreTechniques.forEach((tech) => {
      lines.push(`- \`${tech.id}\` - ${tech.name}`);
    });
    lines.push('');
  }

  if (scenario.steps && scenario.steps.length) {
    scenario.steps.forEach((step, index) => {
      lines.push(`## Step ${index + 1}: ${step.title}`);
      lines.push('');
      if (step.description) {
        lines.push(step.description);
        lines.push('');
      }

      if (step.mitreTechniques && step.mitreTechniques.length) {
        lines.push('**MITRE ATT&CK (this step):**');
        step.mitreTechniques.forEach((tech) => {
          lines.push(`- \`${tech.id}\` - ${tech.name}`);
        });
        lines.push('');
      }

      let logs = [];
      if (step.sampleLogs) {
        logs =
          typeof step.sampleLogs === 'function'
            ? step.sampleLogs(scenarioVars)
            : step.sampleLogs;
      }

      if (logs && logs.length) {
        lines.push('**Sample logs:**');
        lines.push('');
        lines.push('```text');
        lines.push(...logs);
        lines.push('```');
        lines.push('');
      }

      if (step.defenderPerspective) {
        lines.push('**What a defender sees**');
        lines.push('');
        lines.push(step.defenderPerspective);
        lines.push('');
      }

      if (step.defenderActions && step.defenderActions.length) {
        lines.push('**Suggested defender actions**');
        lines.push('');
        step.defenderActions.forEach((action) => {
          lines.push(`- ${action}`);
        });
        lines.push('');
      }

      if (step.keySignals && step.keySignals.length) {
        lines.push('**Key signals to remember**');
        lines.push('');
        step.keySignals.forEach((sig) => {
          lines.push(`- ${sig}`);
        });
        lines.push('');
      }

      lines.push('---');
      lines.push('');
    });
  } else {
    lines.push('_No steps defined for this scenario yet._');
    lines.push('');
  }

  lines.push(
    '> Exported from Security Webtools - Threat Simulation Playground. All data is static and generated locally in your browser.',
  );

  return lines.join('\n');
}

function stepToMarkdown(scenario, step, stepIndex, scenarioVars = {}) {
  if (!scenario || !step) {
    return '# Threat Simulation Step\n\n_No step selected._\n';
  }

  const lines = [];
  lines.push(`# ${scenario.title}`);
  lines.push('');
  lines.push(`**Step ${stepIndex + 1}: ${step.title}**`);
  lines.push('');
  if (step.description) {
    lines.push(step.description);
    lines.push('');
  }

  if (step.mitreTechniques && step.mitreTechniques.length) {
    lines.push('**MITRE ATT&CK (this step):**');
    step.mitreTechniques.forEach((tech) => {
      lines.push(`- \`${tech.id}\` - ${tech.name}`);
    });
    lines.push('');
  }

  let logs = [];
  if (step.sampleLogs) {
    logs =
      typeof step.sampleLogs === 'function'
        ? step.sampleLogs(scenarioVars)
        : step.sampleLogs;
  }

  if (logs && logs.length) {
    lines.push('**Sample logs:**');
    lines.push('');
    lines.push('```text');
    lines.push(...logs);
    lines.push('```');
    lines.push('');
  }

  if (step.defenderPerspective) {
    lines.push('**What a defender sees**');
    lines.push('');
    lines.push(step.defenderPerspective);
    lines.push('');
  }

  if (step.defenderActions && step.defenderActions.length) {
    lines.push('**Suggested defender actions**');
    lines.push('');
    step.defenderActions.forEach((action) => {
      lines.push(`- ${action}`);
    });
    lines.push('');
  }

  if (step.keySignals && step.keySignals.length) {
    lines.push('**Key signals to remember**');
    lines.push('');
    step.keySignals.forEach((sig) => {
      lines.push(`- ${sig}`);
    });
    lines.push('');
  }

  lines.push('');
  lines.push(
    '> Exported from Security Webtools - Threat Simulation Playground. All data is static and generated locally in your browser.',
  );

  return lines.join('\n');
}

function generateScenarioVars(scenarioId) {
  if (!scenarioId) return {};

  if (scenarioVarsCache[scenarioId]) {
    return scenarioVarsCache[scenarioId];
  }

  const fresh = buildScenarioVarsForId(scenarioId);
  scenarioVarsCache[scenarioId] = fresh;
  return fresh;
}

// Main component

function ThreatPlayground({ onBack }) {
  const defaultScenarioId = SCENARIOS[0]?.id || null;

  const initialScenarioId = getPersistent(
    'sw_threat_selectedScenario',
    defaultScenarioId,
  );

  const [selectedScenarioId, setSelectedScenarioId] = useState(initialScenarioId);
  const [activeStepIndex, setActiveStepIndex] = useState(0);

  // Per-scenario notes (loaded once at mount based on initialScenarioId)
  const [scenarioNotes, setScenarioNotes] = useState(() =>
    initialScenarioId
      ? getPersistent(`sw_threat_notes_${initialScenarioId}`, '') || ''
      : '',
  );
  const [difficultyFilter, setDifficultyFilter] = useState('all'); 
  const [tagFilter, setTagFilter] = useState('all'); 
  const [tagMenuOpen, setTagMenuOpen] = useState(false);
  const [showHints, setShowHints] = useState(() =>
    getPersistent('sw_threat_showHints', true),
  );

  const [, forceVarsRerender] = useState(0);

  const selectedScenario = useMemo(() => {
    const fromId = selectedScenarioId && getScenarioById(selectedScenarioId);
    return fromId || (defaultScenarioId ? getScenarioById(defaultScenarioId) : null);
  }, [selectedScenarioId, defaultScenarioId]);
  
  const allTags = useMemo(() => {
    const tagSet = new Set();
    SCENARIOS.forEach((s) => {
      (s.tags || []).forEach((t) => tagSet.add(t));
    });
    return Array.from(tagSet).sort();
  }, []);

  const steps = selectedScenario?.steps || [];
  const currentStep =
    steps.length > 0 ? steps[Math.min(activeStepIndex, steps.length - 1)] : null;

  const scenarioVars = generateScenarioVars(selectedScenario?.id);

  const resolvedSampleLogs =
    currentStep && currentStep.sampleLogs
      ? typeof currentStep.sampleLogs === 'function'
        ? currentStep.sampleLogs(scenarioVars)
        : currentStep.sampleLogs
      : [];

  // Persist selected scenario id
  useEffect(() => {
    if (selectedScenario?.id) {
      setPersistent('sw_threat_selectedScenario', selectedScenario.id);
    }
  }, [selectedScenario?.id]);

  // Persist hint visibility preference
  useEffect(() => {
    setPersistent('sw_threat_showHints', showHints);
  }, [showHints]);

  // Persist notes for the current scenario
  useEffect(() => {
    if (!selectedScenario?.id) return;
    setPersistent(`sw_threat_notes_${selectedScenario.id}`, scenarioNotes);
  }, [selectedScenario?.id, scenarioNotes]);

  const handleSelectScenario = (id) => {
    setSelectedScenarioId(id);

    const stored = getPersistent(`sw_threat_notes_${id}`, '');
    setScenarioNotes(stored || '');

    setActiveStepIndex(0);
    setTagMenuOpen(false);
  };

  const handlePrevStep = () => {
    setActiveStepIndex((prev) => Math.max(prev - 1, 0));
  };

  const handleNextStep = () => {
    if (!steps || steps.length === 0) return;
    setActiveStepIndex((prev) => Math.min(prev + 1, steps.length - 1));
  };

  const handleJumpToStep = (index) => {
    if (!steps || steps.length === 0) return;
    if (index < 0 || index >= steps.length) return;
    setActiveStepIndex(index);
  };

  const handleExportScenario = () => {
    if (!selectedScenario) return;
    const markdown = scenarioToMarkdown(selectedScenario, scenarioVars);
    const safeId = selectedScenario.id || 'scenario';
    downloadTextFile(`threat-playground-${safeId}.md`, markdown);
  };

  const handleExportCurrentStep = () => {
    if (!selectedScenario || !currentStep) return;
    const markdown = stepToMarkdown(
      selectedScenario,
      currentStep,
      activeStepIndex,
      scenarioVars,
    );
    const safeId = selectedScenario.id || 'scenario';
    const stepId = currentStep.id || `step-${activeStepIndex + 1}`;
    downloadTextFile(`threat-playground-${safeId}-${stepId}.md`, markdown);
  };

  const handleRerollScenarioVars = () => {
    if (!selectedScenario?.id) return;
    delete scenarioVarsCache[selectedScenario.id];
    forceVarsRerender((prev) => prev + 1);
  };

  const handleDifficultyChange = (level) => {
    setDifficultyFilter(level);
    setTagMenuOpen(false);
  };

  const atFirstStep = activeStepIndex === 0;
  const atLastStep = steps.length === 0 || activeStepIndex === steps.length - 1;

  const filteredScenarios = useMemo(() => {
    return SCENARIOS.filter((s) => {
      if (difficultyFilter !== 'all' && s.difficulty !== difficultyFilter) {
        return false;
      }
      if (tagFilter !== 'all') {
        const tags = s.tags || [];
        if (!tags.includes(tagFilter)) return false;
      }
      return true;
    });
  }, [difficultyFilter, tagFilter]);

  return (
    <div className="space-y-6">
      {/* Header + back button */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <button
            type="button"
            onClick={onBack}
            className="text-xs inline-flex items-center gap-1 px-2 py-1 rounded-full border border-slate-700 text-slate-300 hover:border-emerald-400/60 hover:text-emerald-200 mb-2"
          >
            <span className="text-sm">←</span>
            Back to Hub
          </button>

          <h2 className="text-lg sm:text-xl font-semibold">
            Threat Simulation Playground
          </h2>
          <p className="text-xs sm:text-sm text-slate-300">
            Step through realistic attack narratives using static data only.
            No traffic is generated. This is an educational, local-only
            simulator that runs entirely in your browser.
          </p>
        </div>
      </div>

      {/* Main layout: scenarios list + active scenario/step view */}
      <section className="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,2.1fr)]">
        {/* Left column: scenario list */}
        <div className="space-y-3">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-4">
                <h3 className="text-sm font-semibold text-slate-100">
                    Choose a scenario
                </h3>

                <div className="mt-2 flex flex-wrap items-center gap-1 text-[0.65rem]">
                    <button
                    type="button"
                    onClick={() => handleDifficultyChange('all')}
                    className={[
                        'px-2 py-0.5 rounded-full border',
                        difficultyFilter === 'all'
                        ? 'border-emerald-400 bg-emerald-500/10 text-emerald-100'
                        : 'border-slate-700 bg-slate-900 text-slate-300 hover:border-emerald-400/60 hover:text-emerald-200',
                    ].join(' ')}
                    >
                    All
                    </button>
                    <button
                    type="button"
                    onClick={() => handleDifficultyChange('beginner')}
                    className={[
                        'px-2 py-0.5 rounded-full border',
                        difficultyFilter === 'beginner'
                        ? 'border-emerald-400 bg-emerald-500/10 text-emerald-100'
                        : 'border-slate-700 bg-slate-900 text-slate-300 hover:border-emerald-400/60 hover:text-emerald-200',
                    ].join(' ')}
                    >
                    Beginner
                    </button>
                    <button
                    type="button"
                    onClick={() => handleDifficultyChange('intermediate')}
                    className={[
                        'px-2 py-0.5 rounded-full border',
                        difficultyFilter === 'intermediate'
                        ? 'border-amber-400 bg-amber-500/10 text-amber-100'
                        : 'border-slate-700 bg-slate-900 text-slate-300 hover:border-amber-400/60 hover:text-amber-200',
                    ].join(' ')}
                    >
                    Intermediate
                    </button>
                    <button
                    type="button"
                    onClick={() => handleDifficultyChange('advanced')}
                    className={[
                        'px-2 py-0.5 rounded-full border',
                        difficultyFilter === 'advanced'
                        ? 'border-rose-400 bg-rose-500/10 text-rose-100'
                        : 'border-slate-700 bg-slate-900 text-slate-300 hover:border-rose-400/60 hover:text-rose-200',
                    ].join(' ')}
                    >
                    Advanced
                    </button>
                </div>

                                <div className="mt-2 flex items-center gap-1 text-[0.65rem]">
                  <span className="text-slate-400 mr-1">Filter by tag:</span>
                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => setTagMenuOpen((prev) => !prev)}
                      className={[
                        'inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-[0.65rem]',
                        tagFilter === 'all'
                          ? 'border-slate-700 bg-slate-900 text-slate-300 hover:border-emerald-400/60 hover:text-emerald-200'
                          : 'border-emerald-400 bg-emerald-500/10 text-emerald-100',
                      ].join(' ')}
                    >
                      {tagFilter === 'all' ? 'All tags' : tagFilter}
                      <span className="text-[0.55rem] opacity-80">▼</span>
                    </button>

                    {tagMenuOpen && (
                      <div className="absolute z-20 mt-1 w-44 rounded-xl border border-slate-700 bg-slate-950/95 shadow-lg max-h-52 overflow-auto">
                        <button
                          type="button"
                          onClick={() => {
                            setTagFilter('all');
                            setTagMenuOpen(false);
                          }}
                          className={[
                            'w-full text-left px-3 py-1 text-[0.65rem]',
                            tagFilter === 'all'
                              ? 'bg-slate-900 text-emerald-100'
                              : 'text-slate-200 hover:bg-slate-900/80',
                          ].join(' ')}
                        >
                          All tags
                        </button>
                        {allTags.map((tag) => (
                          <button
                            key={tag}
                            type="button"
                            onClick={() => {
                              setTagFilter(tag);
                              setTagMenuOpen(false);
                            }}
                            className={[
                              'w-full text-left px-3 py-1 text-[0.65rem]',
                              tagFilter === tag
                                ? 'bg-slate-900 text-emerald-100'
                                : 'text-slate-200 hover:bg-slate-900/80',
                            ].join(' ')}
                          >
                            {tag}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <p className="text-xs text-slate-300 mb-3 mt-2">
                Pick a predefined scenario to explore. Each scenario includes a
                step-by-step timeline, sample logs, MITRE ATT&CK mappings,
                and defender notes.
                </p>

                {filteredScenarios.length === 0 ? (
                <div className="mt-1 rounded-xl border border-slate-800 bg-slate-950/80 px-3 py-2 text-[0.7rem] text-slate-300">
                    <p>No scenarios match this combination yet.</p>
                    <button
                    type="button"
                    onClick={() => {
                        setDifficultyFilter('all');
                        setTagFilter('all');
                        setTagMenuOpen(false);
                    }}
                    className="mt-2 inline-flex items-center px-2.5 py-0.5 rounded-full border border-slate-700 text-[0.65rem] text-slate-200 hover:border-emerald-400/70 hover:text-emerald-100"
                    >
                    Reset filters
                    </button>
                </div>
                ) : (
                <div className="space-y-2">
                    {filteredScenarios.map((scenario) => {
                    const isActive = selectedScenario?.id === scenario.id;
                    return (
                        <button
                        key={scenario.id}
                        type="button"
                        onClick={() => handleSelectScenario(scenario.id)}
                        className={[
                            'w-full text-left rounded-xl px-3 py-2 text-xs sm:text-sm border transition',
                            isActive
                            ? 'border-emerald-400/70 bg-emerald-500/5 shadow-sm shadow-emerald-500/20'
                            : 'border-slate-800 bg-slate-950/60 hover:border-emerald-400/60 hover:bg-slate-900',
                        ].join(' ')}
                        >
                        <div className="flex items-start justify-between gap-2 mb-1">
                            <div>
                            <div className="font-semibold text-slate-100 text-[0.85rem] sm:text-sm">
                                {scenario.title}
                            </div>
                            <p className="text-[0.7rem] text-slate-300 line-clamp-2">
                                {renderWithInlineCode(scenario.summary)}
                            </p>
                            </div>
                            <span
                            className={[
                                'shrink-0 text-[0.6rem] px-2 py-0.5 rounded-full',
                                difficultyBadgeClasses(scenario.difficulty),
                            ].join(' ')}
                            >
                            {difficultyLabel(scenario.difficulty)}
                            </span>
                        </div>

                        {scenario.tags && scenario.tags.length > 0 && (
                            <div className="mt-1 flex flex-wrap gap-1">
                            {scenario.tags.map((tag) => (
                                <span
                                key={tag}
                                className="text-[0.6rem] px-1.5 py-0.5 rounded-full bg-slate-900/80 border border-slate-700 text-slate-300"
                                >
                                {tag}
                                </span>
                            ))}
                            </div>
                        )}
                        </button>
                    );
                    })}
                </div>
                )}
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-3 space-y-2">
            <h4 className="text-xs font-semibold text-slate-100">
              How to use this tool
            </h4>
            <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5">
              <li>Select a scenario on the left.</li>
              <li>
                Use the stepper to move between phases of the attack and see
                how logs evolve.
              </li>
              <li>
                Pay attention to the defender notes and key signals: they
                highlight what you would actually spot in a SOC.
              </li>
              <li>
                Toggle <span className="font-semibold">Interview mode</span> to hide hints and test yourself.
              </li>
            </ul>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-3 space-y-1.5">
            <h4 className="text-xs font-semibold text-slate-100">
              Difficulty scale
            </h4>
            <ul className="text-[0.7rem] text-slate-300 space-y-0.5">
              <li>
                <span className="font-semibold text-emerald-300">Beginner:</span>{' '}
                Single log source or short timeline, obvious signals.
              </li>
              <li>
                <span className="font-semibold text-amber-300">Intermediate:</span>{' '}
                2-3 log sources, some correlation needed.
              </li>
              <li>
                <span className="font-semibold text-rose-300">Advanced:</span>{' '}
                Multi-stage kill chain, several log sources and subtler signals.
              </li>
            </ul>
          </div>
          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-3 space-y-1.5">
            <h4 className="text-xs font-semibold text-slate-100">
              Practice &amp; detection ideas
            </h4>
            <ul className="text-[0.7rem] text-slate-300 space-y-0.5">
              <li>
                For each step, summarize the attacker&apos;s goal in one sentence.
              </li>
              <li>
                Write a plain-language detection rule (no syntax) that would catch this behaviour.
              </li>
              <li>
                Think of one way an attacker might try to evade that rule.
              </li>
              <li>
                Use <span className="font-semibold">Interview mode</span> to test yourself without hints.
              </li>
            </ul>
          </div>
        </div>

        {/* Right column: active scenario + stepper + notes */}
        <div className="space-y-3">
          {/* Scenario summary card + exports + interview mode */}
          {selectedScenario && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-4 space-y-2">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="text-sm sm:text-base font-semibold text-slate-100">
                    {selectedScenario.title}
                  </h3>
                  <p className="text-xs sm:text-sm text-slate-300 mt-1">
                    {renderWithInlineCode(selectedScenario.summary)}
                  </p>
                </div>
                <span
                  className={[
                    'text-[0.65rem] px-2 py-0.5 rounded-full self-start',
                    difficultyBadgeClasses(selectedScenario.difficulty),
                  ].join(' ')}
                >
                  {difficultyLabel(selectedScenario.difficulty)}
                </span>
              </div>

              {selectedScenario.objective && (
                <p className="text-[0.7rem] text-slate-300">
                  <span className="font-semibold text-slate-100">
                    Objective:{' '}
                  </span>
                  {renderWithInlineCode(selectedScenario.objective)}
                </p>
              )}

              {selectedScenario.defenderFocus && (
                <p className="text-[0.7rem] text-slate-300">
                  <span className="font-semibold text-slate-100">
                    Defender focus:{' '}
                  </span>
                  {renderWithInlineCode(selectedScenario.defenderFocus)}
                </p>
              )}

              {selectedScenario.overallMitreTechniques &&
                selectedScenario.overallMitreTechniques.length > 0 && (
                  <div className="mt-1">
                    <div className="text-[0.7rem] text-slate-300 mb-1">
                      <span className="font-semibold text-slate-100">
                        MITRE ATT&amp;CK (overall):
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedScenario.overallMitreTechniques.map((tech) => (
                        <a
                          key={tech.id}
                          href={mitreTechniqueUrl(tech.id)}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-[0.65rem] px-2 py-0.5 rounded-full bg-slate-900 border border-slate-700 text-slate-200 hover:border-emerald-400/70 hover:text-emerald-100"
                        >
                          <code className="font-mono text-emerald-300">
                            {tech.id}
                          </code>
                          <span className="text-slate-200">{tech.name}</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}

              <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[0.65rem]">
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handleExportScenario}
                    className="px-3 py-1.5 rounded-full border border-slate-700 text-slate-200 hover:border-emerald-400 hover:text-emerald-200"
                  >
                    Export scenario (.md)
                  </button>
                  <button
                    type="button"
                    onClick={handleExportCurrentStep}
                    disabled={!currentStep}
                    className={[
                      'px-3 py-1.5 rounded-full border',
                      currentStep
                        ? 'border-slate-700 text-slate-200 hover:border-emerald-400 hover:text-emerald-200'
                        : 'border-slate-800 text-slate-500 opacity-60 cursor-not-allowed',
                    ].join(' ')}
                  >
                    Export current step (.md)
                  </button>
                  <button
                    type="button"
                    onClick={handleRerollScenarioVars}
                    className="px-3 py-1.5 rounded-full border border-slate-700 text-slate-200 hover:border-emerald-400 hover:text-emerald-200"
                  >
                    Re-roll values
                  </button>
                </div>

                <button
                  type="button"
                  onClick={() => setShowHints((prev) => !prev)}
                  className={
                    showHints
                      ? 'px-3 py-1.5 rounded-full border border-amber-400 text-amber-100 bg-amber-500/15'
                      : 'px-3 py-1.5 rounded-full border border-slate-700 text-slate-200 bg-slate-900 hover:border-emerald-400 hover:text-emerald-200'
                  }
                >
                  {showHints ? 'Interview mode: hide hints' : 'Interview mode: show hints'}
                </button>
              </div>
            </div>
          )}

          {/* Stepper */}
          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-3 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-1">
                {steps.map((step, index) => {
                  const isActive = index === activeStepIndex;
                  return (
                    <button
                      key={step.id}
                      type="button"
                      onClick={() => handleJumpToStep(index)}
                      className={[
                        'text-[0.65rem] px-2.5 py-1 rounded-full border transition',
                        isActive
                          ? 'border-emerald-400 bg-emerald-500/15 text-emerald-100'
                          : 'border-slate-700 bg-slate-900/80 text-slate-300 hover:border-emerald-400/60 hover:text-emerald-200',
                      ].join(' ')}
                    >
                      Step {index + 1}
                    </button>
                  );
                })}
                {steps.length === 0 && (
                  <span className="text-[0.7rem] text-slate-400">
                    No steps defined for this scenario yet.
                  </span>
                )}
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handlePrevStep}
                  disabled={atFirstStep || steps.length === 0}
                  className={[
                    'text-[0.65rem] px-2.5 py-1 rounded-full border',
                    atFirstStep || steps.length === 0
                      ? 'border-slate-700 text-slate-500 opacity-60 cursor-not-allowed'
                      : 'border-slate-700 text-slate-300 hover:border-emerald-400/60 hover:text-emerald-200',
                  ].join(' ')}
                >
                  ← Previous
                </button>
                <button
                  type="button"
                  onClick={handleNextStep}
                  disabled={atLastStep || steps.length === 0}
                  className={[
                    'text-[0.65rem] px-2.5 py-1 rounded-full border',
                    atLastStep || steps.length === 0
                      ? 'border-slate-700 text-slate-500 opacity-60 cursor-not-allowed'
                      : 'border-emerald-400 text-emerald-100 bg-emerald-500/10 hover:bg-emerald-500/20',
                  ].join(' ')}
                >
                  Next →
                </button>
              </div>
            </div>

            {/* Current step content */}
            {currentStep ? (
              <div className="mt-1 rounded-xl border border-slate-800 bg-slate-900/80 p-3 space-y-2">
                <div>
                  <h4 className="text-sm font-semibold text-slate-100">
                    Step {activeStepIndex + 1}: {currentStep.title}
                  </h4>
                  <p className="text-xs sm:text-sm text-slate-300 mt-1">
                    {renderWithInlineCode(currentStep.description)}
                  </p>
                </div>

                {currentStep.mitreTechniques &&
                  currentStep.mitreTechniques.length > 0 && (
                    <div className="mt-1">
                      <div className="text-[0.7rem] text-slate-300 mb-1">
                        <span className="font-semibold text-slate-100">
                          MITRE ATT&amp;CK (this step):
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {currentStep.mitreTechniques.map((tech) => (
                          <a
                            key={tech.id}
                            href={mitreTechniqueUrl(tech.id)}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-[0.65rem] px-2 py-0.5 rounded-full bg-slate-900 border border-slate-700 text-slate-200 hover:border-emerald-400/70 hover:text-emerald-100"
                          >
                            <code className="font-mono text-emerald-300">
                              {tech.id}
                            </code>
                            <span className="text-slate-200">{tech.name}</span>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                {resolvedSampleLogs && resolvedSampleLogs.length > 0 && (
                  <div className="mt-2">
                    <div className="text-[0.7rem] font-semibold text-slate-100 mb-1">
                      Sample logs
                    </div>
                    <div className="rounded-lg bg-slate-950/80 border border-slate-800 p-2">
                      <pre className="text-[0.65rem] text-slate-200 font-mono whitespace-pre-wrap wrap-break-word">
                        {resolvedSampleLogs.join('\n')}
                      </pre>
                    </div>
                    <p className="mt-1 text-[0.65rem] text-slate-400">
                    These logs are static examples (some fields may be randomized each time).
                    This tool does not connect to your environment or execute any actions.
                    </p>
                  </div>
                )}

                {showHints ? (
                  <>
                    {currentStep.defenderPerspective && (
                      <div className="mt-2">
                        <div className="text-[0.7rem] font-semibold text-slate-100 mb-0.5">
                          What a defender sees
                        </div>
                        <p className="text-[0.7rem] text-slate-300">
                          {renderWithInlineCode(currentStep.defenderPerspective)}
                        </p>
                      </div>
                    )}

                    {currentStep.defenderActions &&
                      currentStep.defenderActions.length > 0 && (
                        <div className="mt-2">
                          <div className="text-[0.7rem] font-semibold text-slate-100 mb-0.5">
                            Suggested defender actions
                          </div>
                          <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5">
                            {currentStep.defenderActions.map((action, idx) => (
                              <li key={`${currentStep.id}-action-${idx}`}>
                                {renderWithInlineCode(action)}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                    {currentStep.keySignals &&
                      currentStep.keySignals.length > 0 && (
                        <div className="mt-2">
                          <div className="text-[0.7rem] font-semibold text-slate-100 mb-0.5">
                            Key signals to remember
                          </div>
                          <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5">
                            {currentStep.keySignals.map((signal, idx) => (
                              <li key={`${currentStep.id}-signal-${idx}`}>
                                {renderWithInlineCode(signal)}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                  </>
                ) : (
                  <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 space-y-1.5 text-[0.7rem] text-slate-300">
                    <p>
                      Hints are hidden in interview mode. Toggle{' '}
                      <span className="font-semibold">Interview mode</span> above
                      to reveal defender notes and key signals.
                    </p>
                    <div>
                      <div className="font-semibold text-slate-100 mb-0.5">
                        Interview prompts
                      </div>
                      <ul className="list-disc list-inside space-y-0.5">
                        <li>
                          What is the attacker trying to achieve in this step?
                        </li>
                        <li>
                          Which 2-3 fields in these logs provide the strongest detection signal?
                        </li>
                        <li>
                          How would you describe a detection rule for this step in plain language?
                        </li>
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="mt-1 rounded-xl border border-slate-800 bg-slate-900/80 p-3 text-xs text-slate-300">
                Select a scenario to view its timeline and logs.
              </div>
            )}
          </div>

          {/* Per-scenario notes */}
          {selectedScenario && (
            <section className="rounded-2xl border border-slate-800 bg-slate-950/70 p-3 space-y-2">
              <h3 className="text-xs font-semibold text-slate-100">
                Your notes for this scenario
              </h3>
                <textarea
                value={scenarioNotes}
                onChange={(e) =>
                    setScenarioNotes(e.target.value.slice(0, 20000))
                }
                maxLength={20000}
                placeholder="Write your own detection ideas, queries or interview notes here. Saved locally in your browser."
                className="w-full min-h-20 rounded-xl bg-slate-950/60 border border-slate-800 px-3 py-2 text-[0.7rem] text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-400/60"
                />
              <p className="text-[0.65rem] text-slate-400">
                Notes are stored only in your browser using local storage. They are not uploaded anywhere.
              </p>
            </section>
          )}
        </div>
      </section>

      {/* Shared About & Privacy section */}
      <section className="mt-4 pt-4 border-t border-slate-800">
        <AboutSection />
      </section>
    </div>
  );
}

export default ThreatPlayground;
