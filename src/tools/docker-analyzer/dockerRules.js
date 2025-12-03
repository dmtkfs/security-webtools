// Simple Dockerfile security/hardening rule engine.
// All logic runs locally in the browser.

const SEVERITY_ORDER = {
  high: 0,
  warning: 1,
  info: 2,
}

// Ports commonly associated with remote admin / sensitive protocols
const RISKY_PORTS = [21, 22, 23, 3389, 5900]

// Keywords used to detect likely secrets in ENV
const SECRET_KEYWORDS = [
  'PASSWORD',
  'PASS',
  'SECRET',
  'TOKEN',
  'API_KEY',
  'ACCESS_KEY',
  'KEY',
  'PRIVATE',
  'CREDENTIAL',
  'AUTH',
  'SIGNING',
]

const RULES = [
  // 1) FROM :latest
  {
    id: 'FROM_LATEST',
    description: 'Detects base images with :latest tag',
    check: (text, lines, rawLines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^FROM\s+/i.test(trimmed)) return

        const match = trimmed.match(/^FROM\s+(.+)$/i)
        if (!match) return

        const image = match[1].trim()
        if (/:latest(\s|$)/i.test(image)) {
          findings.push({
            id: `FROM_LATEST_${index + 1}`,
            ruleId: 'FROM_LATEST',
            severity: 'warning',
            title: 'Base image uses :latest tag',
            description: `The base image "${image}" uses the :latest tag, which can lead to non-reproducible builds and unexpected changes.`,
            recommendation:
              'Pin the base image to a specific version or digest (e.g., "ubuntu:22.04" or a SHA256 digest) instead of using :latest.',
            lineNumber: index + 1,
            lineContent: rawLines[index],
          })
        }
      })

      return findings
    },
  },

  // 2) FROM without explicit tag
  {
    id: 'FROM_UNPINNED',
    description: 'Detects base images without explicit tag',
    check: (text, lines, rawLines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^FROM\s+/i.test(trimmed)) return

        const match = trimmed.match(/^FROM\s+(.+)$/i)
        if (!match) return

        const image = match[1].trim()
        const imageOnly = image.split(/\s+AS\s+/i)[0].trim()
        if (!imageOnly.includes(':')) {
          findings.push({
            id: `FROM_UNPINNED_${index + 1}`,
            ruleId: 'FROM_UNPINNED',
            severity: 'warning',
            title: 'Base image is not pinned to a specific tag',
            description: `The base image "${imageOnly}" does not specify a tag, which implicitly uses :latest and can cause non-reproducible builds.`,
            recommendation:
              'Specify a stable, explicit tag for the base image (for example, "alpine:3.19" instead of "alpine").',
            lineNumber: index + 1,
            lineContent: rawLines[index],
          })
        }
      })

      return findings
    },
  },

  // 3) FROM node with very old major version
  {
    id: 'OLD_NODE_BASE_IMAGE',
    description: 'Detects very old Node.js base image versions',
    check: (text, lines, rawLines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^FROM\s+/i.test(trimmed)) return
        if (!/node:/i.test(trimmed)) return

        const match = trimmed.match(/node:(\d+)/i)
        if (!match) return

        const major = parseInt(match[1], 10)
        if (Number.isNaN(major)) return

        if (major < 14) {
          findings.push({
            id: `NODE_BASE_VERY_OLD_${index + 1}`,
            ruleId: 'OLD_NODE_BASE_IMAGE',
            severity: 'high',
            title: `Very old Node.js base image (node:${major})`,
            description:
              `The Dockerfile uses node:${major}, which is likely end-of-life and may no longer receive security updates.`,
            recommendation:
              'Upgrade to a supported Node.js LTS version and ensure the base image is kept up to date.',
            lineNumber: index + 1,
            lineContent: rawLines[index],
          })
        } else if (major < 18) {
          findings.push({
            id: `NODE_BASE_OLD_${index + 1}`,
            ruleId: 'OLD_NODE_BASE_IMAGE',
            severity: 'warning',
            title: `Old Node.js base image (node:${major})`,
            description:
              `The Dockerfile uses node:${major}, which may be close to or past end-of-life.`,
            recommendation:
              'Verify that this Node.js version is still supported. Consider upgrading to a more recent LTS release.',
            lineNumber: index + 1,
            lineContent: rawLines[index],
          })
        }
      })

      return findings
    },
  },

  // 4) No USER / root USER
  {
    id: 'NO_NON_ROOT_USER',
    description: 'Detects images that run as root or do not set a non-root USER',
    check: (text, lines, rawLines) => {
      const findings = []

      let userLine = null
      let userValue = null

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^USER\s+/i.test(trimmed)) return

        const match = trimmed.match(/^USER\s+(.+)$/i)
        if (!match) return

        userLine = index + 1
        userValue = match[1].trim()
      })

      if (userLine === null) {
        findings.push({
          id: 'NO_USER_SET',
          ruleId: 'NO_NON_ROOT_USER',
          severity: 'warning',
          title: 'No USER instruction set',
          description:
            'The Dockerfile does not specify a USER, which typically means the container will run as root.',
          recommendation:
            'Add a USER instruction to run the container as a dedicated non-root user and adjust file permissions accordingly.',
          lineNumber: null,
          lineContent: null,
        })
      } else if (/^(root|0)$/i.test(userValue)) {
        findings.push({
          id: `USER_ROOT_${userLine}`,
          ruleId: 'NO_NON_ROOT_USER',
          severity: 'high',
          title: 'Container is configured to run as root',
          description:
            `The Dockerfile sets USER to "${userValue}", which means the container will run as root and increase the impact of a compromise.`,
          recommendation:
            'Create and switch to a non-root user (for example, using RUN useradd/adduser) and update USER to that account.',
          lineNumber: userLine,
          lineContent: rawLines[userLine - 1],
        })
      }

      return findings
    },
  },

  // 5) ADD instead of COPY
  {
    id: 'ADD_INSTEAD_OF_COPY',
    description: 'Flags use of ADD where COPY is usually safer',
    check: (text, lines, rawLines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (/^ADD\s+/i.test(trimmed)) {
          findings.push({
            id: `ADD_INSTEAD_OF_COPY_${index + 1}`,
            ruleId: 'ADD_INSTEAD_OF_COPY',
            severity: 'warning',
            title: 'ADD instruction used instead of COPY',
            description:
              'The ADD instruction has additional behaviors (remote URL support, automatic extraction) that can be surprising or risky.',
            recommendation:
              'Prefer COPY for predictable file transfers. Only use ADD when you explicitly need features like remote URL fetch or archive extraction.',
            lineNumber: index + 1,
            lineContent: rawLines[index],
          })
        }
      })

      return findings
    },
  },

  // 6) Risky exposed ports
  {
    id: 'RISKY_EXPOSE_PORTS',
    description: 'Detects exposed ports commonly associated with remote administrative services',
    check: (text, lines, rawLines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^EXPOSE\s+/i.test(trimmed)) return

        const match = trimmed.match(/^EXPOSE\s+(.+)$/i)
        if (!match) return

        const portsPart = match[1]
        const tokens = portsPart.split(/\s+/)

        tokens.forEach((token) => {
          const portMatch = token.match(/^(\d+)/)
          if (!portMatch) return

          const portNumber = parseInt(portMatch[1], 10)
          if (RISKY_PORTS.includes(portNumber)) {
            findings.push({
              id: `RISKY_EXPOSE_${portNumber}_${index + 1}`,
              ruleId: 'RISKY_EXPOSE_PORTS',
              severity: 'high',
              title: `Risky port exposed (${portNumber})`,
              description:
                `The Dockerfile exposes port ${portNumber}, which is commonly used for remote administrative services and may increase attack surface.`,
              recommendation:
                'Avoid exposing administrative ports directly on containers unless strictly required. Consider using internal networking, bastion hosts, or VPNs.',
              lineNumber: index + 1,
              lineContent: rawLines[index],
            })
          }
        })
      })

      return findings
    },
  },

  // 7) Missing HEALTHCHECK
  {
    id: 'MISSING_HEALTHCHECK',
    description: 'Warns when no HEALTHCHECK instruction is present',
    check: (text, lines) => {
      const hasHealthcheck = lines.some((line) =>
        /^HEALTHCHECK\b/i.test(line.trim()),
      )
      if (hasHealthcheck) return []

      return [
        {
          id: 'MISSING_HEALTHCHECK',
          ruleId: 'MISSING_HEALTHCHECK',
          severity: 'info',
          title: 'No HEALTHCHECK instruction defined',
          description:
            'The Dockerfile does not define a HEALTHCHECK, so orchestrators cannot automatically detect and replace unhealthy containers.',
          recommendation:
            'Add a HEALTHCHECK instruction that periodically verifies that the application is functioning (for example, an HTTP endpoint or CLI probe).',
          lineNumber: null,
          lineContent: null,
        },
      ]
    },
  },

  // 8a) RUN apk add without --no-cache
  {
    id: 'ALPINE_APK_NO_NOCACHE',
    description: 'Detects apk add without --no-cache on Alpine images',
    check: (text, lines, rawLines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^RUN\s+/i.test(trimmed)) return
        if (!/apk\s+add/i.test(trimmed)) return
        if (/--no-cache/.test(trimmed)) return

        findings.push({
          id: `APK_NO_NOCACHE_${index + 1}`,
          ruleId: 'ALPINE_APK_NO_NOCACHE',
          severity: 'info',
          title: 'apk add used without --no-cache',
          description:
            'When using apk on Alpine, omitting --no-cache leaves behind index files and can increase image size.',
          recommendation:
            'Use "apk add --no-cache ..." to avoid caching the package index inside the final image.',
          lineNumber: index + 1,
          lineContent: rawLines[index],
        })
      })

      return findings
    },
  },

    // 8b) RUN apt-get install without cleaning apt cache
  {
    id: 'APT_INSTALL_NO_CLEAN',
    description: 'Detects apt-get install without cleaning the APT cache',
    check: (text, lines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^RUN\s+/i.test(trimmed)) return
        if (!/apt-get\s+.*install/i.test(trimmed)) return

        // Heuristic: consider it "cleaned" if this same line also contains
        // apt-get clean OR removal of /var/lib/apt/lists
        const hasClean =
          /apt-get\s+clean/i.test(trimmed) ||
          /rm\s+-rf\s+\/var\/lib\/apt\/lists/i.test(trimmed)

        if (hasClean) return

        findings.push({
          id: `APT_INSTALL_NO_CLEAN_${index + 1}`,
          ruleId: 'APT_INSTALL_NO_CLEAN',
          severity: 'info',
          title: 'apt-get install used without cleaning APT cache',
          description:
            'The Dockerfile runs apt-get install without cleaning the APT cache, which can leave behind package index data and increase image size.',
          recommendation:
            'After apt-get install, clean up the APT cache in the same RUN layer (for example, using "rm -rf /var/lib/apt/lists/*" or "apt-get clean") to keep the image small.',
          lineNumber: index + 1,
          lineContent: line,
        })
      })

      return findings
    },
  },


  // 9) chmod 777 (and similar overly-permissive patterns)
  {
    id: 'CHMOD_777',
    description: 'Detects overly permissive chmod 777 usage',
    check: (text, lines) => {
      const findings = []

      const patterns = [
        /\bchmod\s+777\b/,          // chmod 777 /path
        /\bchmod\s+-R\s+777\b/,     // chmod -R 777 /path
        /\binstall\b[^\n]*\b-m\s+777\b/, // install -m 777 file
      ]

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!trimmed || trimmed.startsWith('#')) return

        const isMatch = patterns.some((re) => re.test(trimmed))
        if (isMatch) {
          findings.push({
            id: `CHMOD_777_${index + 1}`,
            ruleId: 'CHMOD_777',
            severity: 'warning',
            title: 'Overly permissive 777 permissions detected',
            description:
              'The Dockerfile uses permissions mode 777 (full access for all users), which is usually more permissive than necessary.',
            recommendation:
              'Use the minimum required permissions (for example, 755 or 750) and restrict access to sensitive files.',
            lineNumber: index + 1,
            lineContent: line,
          })
        }
      })

      return findings
    },
  },


  // 10) curl | sh or wget | sh
  {
    id: 'CURL_PIPE_SH',
    description: 'Detects curl/wget piping directly to shell',
    check: (text, lines, rawLines) => {
      const findings = []

      const pattern = /(curl|wget)[^|]*\|\s*(sh|bash)/i

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!trimmed) return

        if (pattern.test(trimmed)) {
          findings.push({
            id: `CURL_PIPE_SH_${index + 1}`,
            ruleId: 'CURL_PIPE_SH',
            severity: 'warning',
            title: 'curl/wget piped directly to shell',
            description:
              'The Dockerfile downloads a script with curl or wget and pipes it directly to a shell. This can be risky if the remote content changes or is compromised.',
            recommendation:
              'Download scripts, verify integrity (checksums, signatures), and inspect them before execution instead of piping directly to a shell.',
            lineNumber: index + 1,
            lineContent: rawLines[index],
          })
        }
      })

      return findings
    },
  },

  // 11) ENV with likely secrets (one finding per line)
  {
    id: 'ENV_SECRETS',
    description: 'Detects ENV variables that may contain secrets',
    check: (text, lines, rawLines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^ENV\s+/i.test(trimmed)) return

        const rest = trimmed.replace(/^ENV\s+/i, '')
        const upper = rest.toUpperCase()

        const matchedKeywords = new Set()

        for (const keyword of SECRET_KEYWORDS) {
          if (upper.includes(keyword)) {
            matchedKeywords.add(keyword)
          }
        }

        if (matchedKeywords.size === 0) return

        const keywordsList = Array.from(matchedKeywords).join(', ')

        findings.push({
          id: `ENV_SECRET_${index + 1}`,
          ruleId: 'ENV_SECRETS',
          severity: 'warning',
          title: 'Potential secret stored in ENV',
          description:
            `The Dockerfile defines an ENV variable whose name suggests it may contain a secret or credential (matched keywords: ${keywordsList}).`,
          recommendation:
            'Avoid baking secrets into images. Use a secrets manager or runtime environment injection (for example, orchestrator secrets) instead of ENV instructions.',
          lineNumber: index + 1,
          lineContent: rawLines[index],
        })
      })

      return findings
    },
  },

  // 12) COPY/ADD of SSH keys
  {
    id: 'COPY_SSH_KEYS',
    description: 'Detects copying SSH keys or .ssh directory into images',
    check: (text, lines, rawLines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^(COPY|ADD)\s+/i.test(trimmed)) return

        if (/\b\.ssh\b/i.test(trimmed) || /id_rsa/i.test(trimmed) || /id_ed25519/i.test(trimmed)) {
          findings.push({
            id: `COPY_SSH_${index + 1}`,
            ruleId: 'COPY_SSH_KEYS',
            severity: 'high',
            title: 'SSH keys or .ssh directory copied into image',
            description:
              'The Dockerfile appears to copy SSH keys or the .ssh directory into the image. This can leak credentials if the image is shared.',
            recommendation:
              'Avoid copying personal SSH keys or .ssh directories into images. Use build-time secrets or deploy keys instead.',
            lineNumber: index + 1,
            lineContent: rawLines[index],
          })
        }
      })

      return findings
    },
  },

    // 13) Multi-stage builds: detect named stages that are never used with --from=
  {
    id: 'MULTISTAGE_UNUSED_STAGE',
    description: 'Detects named build stages that are never referenced by COPY --from=...',
    check: (text, lines) => {
      const stages = []
      const referencedStages = new Set()

      lines.forEach((line, index) => {
        const trimmed = line.trim()

        // FROM ... AS name
        if (/^FROM\s+/i.test(trimmed)) {
          const match = trimmed.match(/^FROM\s+(.+)$/i)
          if (match) {
            const rest = match[1].trim()
            const asMatch = rest.match(/\s+AS\s+([A-Za-z0-9._-]+)/i)
            if (asMatch) {
              const stageName = asMatch[1]
              stages.push({ name: stageName, lineNumber: index + 1, lineContent: line })
            }
          }
        }

        // COPY/ADD ... --from=name ...
        const copyMatch = trimmed.match(/^(COPY|ADD)\s+.*--from=([^\s]+)/i)
        if (copyMatch) {
          const refName = copyMatch[2]
          referencedStages.add(refName)
        }
      })

      const findings = []

      stages.forEach((stage) => {
        if (!referencedStages.has(stage.name)) {
          findings.push({
            id: `MULTISTAGE_UNUSED_STAGE_${stage.lineNumber}`,
            ruleId: 'MULTISTAGE_UNUSED_STAGE',
            severity: 'info',
            title: `Named build stage "${stage.name}" is never used`,
            description:
              'The Dockerfile defines a named build stage but never references it with COPY --from=. This may indicate dead code or an opportunity to simplify the multi-stage build.',
            recommendation:
              'Remove unused build stages, or ensure that COPY --from=<stage> is used where appropriate.',
            lineNumber: stage.lineNumber,
            lineContent: stage.lineContent,
          })
        }
      })

      return findings
    },
  },

    // 14) apk add without any version pinning for packages
  {
    id: 'APK_NO_VERSION_PIN',
    description: 'Detects apk add usage where packages are not version-pinned',
    check: (text, lines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^RUN\s+/i.test(trimmed)) return
        if (!/apk\s+add\s+/i.test(trimmed)) return

        const match = trimmed.match(/apk\s+add\s+(.+)/i)
        if (!match) return

        const rest = match[1]
        const tokens = rest.split(/\s+/).filter(Boolean)

        const packageTokens = tokens.filter((t) => !t.startsWith('-'))

        if (packageTokens.length === 0) return

        // Consider a token "pinned" if it contains a version operator
        const hasUnpinned = packageTokens.some((pkg) => !/[=<>~]/.test(pkg))

        if (!hasUnpinned) return

        findings.push({
          id: `APK_NO_VERSION_PIN_${index + 1}`,
          ruleId: 'APK_NO_VERSION_PIN',
          severity: 'info',
          title: 'apk add used without version pinning',
          description:
            'The Dockerfile installs packages with apk add but does not pin their versions. This can make builds less reproducible over time.',
          recommendation:
            'Consider pinning key packages to specific versions or version ranges (for example, "openssl=3.3-r0" or "openssl~=3.3").',
          lineNumber: index + 1,
          lineContent: line,
        })
      })

      return findings
    },
  },

    // Lint: apt-get install without -y / --yes
  {
    id: 'APT_INSTALL_NO_Y',
    description: 'Detects apt-get install calls without -y/--yes for non-interactive builds',
    check: (text, lines) => {
      const findings = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (!/^RUN\s+/i.test(trimmed)) return
        if (!/apt-get\s+.*install/i.test(trimmed)) return

        // If the line already has -y or --yes, skip
        if (/\s-(y)\b/i.test(trimmed) || /\s--yes\b/i.test(trimmed)) return

        findings.push({
          id: `APT_INSTALL_NO_Y_${index + 1}`,
          ruleId: 'APT_INSTALL_NO_Y',
          severity: 'warning',
          title: 'apt-get install without -y/--yes',
          description:
            'The Dockerfile runs apt-get install without -y/--yes, which can cause interactive prompts and break non-interactive Docker builds.',
          recommendation:
            'Add -y or --yes to apt-get install commands used in Dockerfiles (for example, "apt-get install -y curl wget").',
          lineNumber: index + 1,
          lineContent: line,
        })
      })

      return findings
    },
  },

    // Lint: duplicate CMD / ENTRYPOINT instructions (only the last one takes effect)
  {
    id: 'DUPLICATE_CMD_ENTRYPOINT',
    description: 'Detects multiple CMD or ENTRYPOINT instructions in the same Dockerfile',
    check: (text, lines) => {
      const cmdLines = []
      const entryLines = []

      lines.forEach((line, index) => {
        const trimmed = line.trim()
        if (/^CMD\b/i.test(trimmed)) {
          cmdLines.push({ lineNumber: index + 1, lineContent: line })
        }
        if (/^ENTRYPOINT\b/i.test(trimmed)) {
          entryLines.push({ lineNumber: index + 1, lineContent: line })
        }
      })

      const findings = []

      if (cmdLines.length > 1) {
        // Warn on all but the last CMD
        const allButLast = cmdLines.slice(0, -1)
        allButLast.forEach((entry) => {
          findings.push({
            id: `DUPLICATE_CMD_${entry.lineNumber}`,
            ruleId: 'DUPLICATE_CMD_ENTRYPOINT',
            severity: 'info',
            title: 'Multiple CMD instructions detected',
            description:
              'This Dockerfile defines multiple CMD instructions. Only the last CMD will take effect; earlier ones are overridden.',
            recommendation:
              'Keep a single CMD in the final image, or consolidate behavior into one entry point script.',
            lineNumber: entry.lineNumber,
            lineContent: entry.lineContent,
          })
        })
      }

      if (entryLines.length > 1) {
        const allButLast = entryLines.slice(0, -1)
        allButLast.forEach((entry) => {
          findings.push({
            id: `DUPLICATE_ENTRYPOINT_${entry.lineNumber}`,
            ruleId: 'DUPLICATE_CMD_ENTRYPOINT',
            severity: 'info',
            title: 'Multiple ENTRYPOINT instructions detected',
            description:
              'This Dockerfile defines multiple ENTRYPOINT instructions. Only the last ENTRYPOINT will take effect; earlier ones are overridden.',
            recommendation:
              'Keep a single ENTRYPOINT in the final image, or handle branching behavior inside that entry point script.',
            lineNumber: entry.lineNumber,
            lineContent: entry.lineContent,
          })
        })
      }

      return findings
    },
  },

]

// Public API: analyze a Dockerfile string into a list of findings.
export function analyzeDockerfile(dockerfileText) {
  const text = dockerfileText || ''

  // Raw lines from the original text
  const rawLines = text.split(/\r?\n/)

  // Processed lines: strip full-line comments / blank lines globally
  const processedLines = rawLines.map((line) => {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) {
      return ''
    }
    return line
  })

  const allFindings = RULES.flatMap((rule) => {
    try {
      return rule.check(text, processedLines, rawLines) || []
    } catch (err) {
      console.error(`Error in rule "${rule.id}":`, err)
      return []
    }
  })

  return allFindings.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  )
}
