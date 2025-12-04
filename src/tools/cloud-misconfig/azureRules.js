const SEVERITY_ORDER = {
  high: 0,
  warning: 1,
  info: 2,
}

const SENSITIVE_PORTS = [22, 3389, 5900]

function toArray(value) {
  if (Array.isArray(value)) return value
  if (value === undefined || value === null) return []
  return [value]
}

function normalizeString(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : ''
}

const RULES = [
  // 1) NSG: Internet → sensitive ports
  {
    id: 'AZURE_NSG_OPEN_SENSITIVE_PORT',
    description:
      'Detects Azure NSG rules that allow sensitive ports from Internet or Any.',
    check: (config) => {
        const findings = []
        const rawNsgs =
        config.networkSecurityGroups ||
        config.nsgs ||
        config.azureNetworkSecurityGroups ||
        []

        const nsgs = Array.isArray(rawNsgs) ? rawNsgs : []


      nsgs.forEach((nsg, nsgIndex) => {
        const nsgName = nsg.name || nsg.id || `nsg-${nsgIndex}`
        const rules = Array.isArray(nsg.rules) ? nsg.rules : []

        rules.forEach((rule, ruleIndex) => {
          const direction = normalizeString(rule.direction || 'inbound')
          if (direction !== 'inbound') return

          const source = normalizeString(rule.source || rule.sourceAddress || '')
          if (
            source !== 'internet' &&
            source !== 'any' &&
            source !== '*' &&
            source !== '0.0.0.0/0'
          ) {
            return
          }

          const from = Number(rule.fromPort)
          const to = Number(rule.toPort)
          if (Number.isNaN(from) || Number.isNaN(to)) return

          SENSITIVE_PORTS.forEach((port) => {
            if (from <= port && port <= to) {
              const label =
                port === 22
                  ? 'SSH'
                  : port === 3389
                    ? 'RDP'
                    : `port ${port}`

              findings.push({
                id: `AZURE_NSG_OPEN_SENSITIVE_PORT_${nsgName}_${ruleIndex}_${port}`,
                ruleId: 'AZURE_NSG_OPEN_SENSITIVE_PORT',
                severity: 'high',
                category: 'network',
                title: `NSG rule allows ${label} from Internet`,
                description:
                  `An inbound NSG rule allows TCP ${port} from Internet/Any, exposing this service to the public internet.`,
                recommendation:
                  'Restrict this rule to specific source IP ranges or private networks, or route administrative access through VPNs / jump hosts instead.',
                resourceType: 'security-group',
                resourceId: nsgName,
                location: {
                  path: `networkSecurityGroups[${nsgIndex}].rules[${ruleIndex}]`,
                },
              })
            }
          })
        })
      })

      return findings
    },
  },

  // 2) NSG: low-priority "allow all" rule
  {
    id: 'AZURE_NSG_ALLOW_ALL_LOW_PRIORITY',
    description:
      'Detects Azure NSG rules that allow all ports from Internet with very low priority.',
    check: (config) => {
        const findings = []
        const rawNsgs =
        config.networkSecurityGroups ||
        config.nsgs ||
        config.azureNetworkSecurityGroups ||
        []

        const nsgs = Array.isArray(rawNsgs) ? rawNsgs : []

      nsgs.forEach((nsg, nsgIndex) => {
        const nsgName = nsg.name || nsg.id || `nsg-${nsgIndex}`
        const rules = Array.isArray(nsg.rules) ? nsg.rules : []

        rules.forEach((rule, ruleIndex) => {
          const direction = normalizeString(rule.direction || 'inbound')
          if (direction !== 'inbound') return

          const source = normalizeString(rule.source || '')
          if (
            source !== 'internet' &&
            source !== 'any' &&
            source !== '*' &&
            source !== '0.0.0.0/0'
          ) {
            return
          }

          const from = Number(rule.fromPort)
          const to = Number(rule.toPort)
          if (Number.isNaN(from) || Number.isNaN(to)) return

          if (from <= 0 && to >= 65535) {
            const priority = Number(rule.priority)
            const isLowPriority = !Number.isNaN(priority) && priority <= 200

            findings.push({
              id: `AZURE_NSG_ALLOW_ALL_LOW_PRIORITY_${nsgName}_${ruleIndex}`,
              ruleId: 'AZURE_NSG_ALLOW_ALL_LOW_PRIORITY',
              severity: isLowPriority ? 'high' : 'warning',
              category: 'network',
              title: 'NSG rule allows all ports from Internet',
              description:
                'An inbound NSG rule allows all TCP ports from Internet/Any. This can expose many services to the internet.',
              recommendation:
                'Replace this rule with narrowly scoped rules for the required ports and trusted source ranges only.',
              resourceType: 'security-group',
              resourceId: nsgName,
              location: {
                path: `networkSecurityGroups[${nsgIndex}].rules[${ruleIndex}]`,
              },
            })
          }
        })
      })

      return findings
    },
  },

  // 3) Storage accounts: public access + encryption
  {
    id: 'AZURE_STORAGE_PUBLIC_ACCESS',
    description:
      'Detects Azure storage accounts with public access or no encryption.',
    check: (config) => {
        const findings = []
        const rawAccts =
        config.storageAccounts ||
        config.azureStorageAccounts ||
        config.storage ||
        []

        const accts = Array.isArray(rawAccts) ? rawAccts : []


      accts.forEach((acct, index) => {
        const name = acct.name || `storage-${index}`
        const publicRead = Boolean(acct.publicRead)
        const publicWrite = Boolean(acct.publicWrite)
        const allowBlobPublicAccess = acct.allowBlobPublicAccess !== false
        const encryptionEnabled = acct.encryptionEnabled !== false

        if (publicRead && publicWrite) {
          findings.push({
            id: `AZURE_STORAGE_PUBLIC_READ_WRITE_${name}`,
            ruleId: 'AZURE_STORAGE_PUBLIC_ACCESS',
            severity: 'high',
            category: 'storage',
            title: 'Storage account has public read and write access',
            description:
              `Storage account "${name}" is configured with public read and write access. Attackers could read and modify data.`,
            recommendation:
              'Disable public access, use private endpoints or SAS tokens, and restrict access via IAM / RBAC roles.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `storageAccounts[${index}]` },
          })
        } else if (publicWrite) {
          findings.push({
            id: `AZURE_STORAGE_PUBLIC_WRITE_${name}`,
            ruleId: 'AZURE_STORAGE_PUBLIC_ACCESS',
            severity: 'high',
            category: 'storage',
            title: 'Storage account has public write access',
            description:
              `Storage account "${name}" allows public write access. Attackers could upload or overwrite blobs or files.`,
            recommendation:
              'Disable public write, and require authenticated principals or shared access signatures for writes.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `storageAccounts[${index}]` },
          })
        } else if (publicRead || allowBlobPublicAccess) {
          findings.push({
            id: `AZURE_STORAGE_PUBLIC_READ_${name}`,
            ruleId: 'AZURE_STORAGE_PUBLIC_ACCESS',
            severity: 'warning',
            category: 'storage',
            title: 'Storage account may allow public read access',
            description:
              `Storage account "${name}" appears to permit public access based on this simplified schema.`,
            recommendation:
              'Ensure public access is strictly required; otherwise, disable it and use private endpoints or SAS tokens.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `storageAccounts[${index}]` },
          })
        }

        if (!encryptionEnabled) {
          findings.push({
            id: `AZURE_STORAGE_NO_ENCRYPTION_${name}`,
            ruleId: 'AZURE_STORAGE_PUBLIC_ACCESS',
            severity: 'info',
            category: 'storage',
            title: 'Storage account does not have encryption enabled',
            description:
              `Storage account "${name}" appears with encryption disabled in this simplified schema.`,
            recommendation:
              'Enable encryption at rest for the storage account using platform-managed or customer-managed keys.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `storageAccounts[${index}]` },
          })
        }
      })

      return findings
    },
  },

  // 4) Role definitions: wildcard actions & wide scopes
  {
    id: 'AZURE_ROLE_WILDCARD_ADMIN',
    description:
      'Detects Azure role definitions that contain "*" in actions or very broad assignable scopes.',
    check: (config) => {
        const findings = []
        const rawDefs =
        config.roleDefinitions ||
        config.azureRoleDefinitions ||
        config.roles ||
        []

        const defs = Array.isArray(rawDefs) ? rawDefs : []


      defs.forEach((def, index) => {
        const name = def.name || def.id || `role-${index}`
        const scopes = toArray(def.assignableScopes)
        const perms = toArray(def.permissions)

        const hasWildcardScope = scopes.some((s) =>
          String(s).includes('/*'),
        )

        let hasWildcardActions = false
        perms.forEach((p) => {
          const actions = toArray(p.actions)
          if (actions.includes('*')) {
            hasWildcardActions = true
          }
        })

        if (!hasWildcardScope && !hasWildcardActions) return

        let severity = 'warning'
        if (hasWildcardScope && hasWildcardActions) {
          severity = 'high'
        }

        findings.push({
          id: `AZURE_ROLE_WILDCARD_ADMIN_${index}`,
          ruleId: 'AZURE_ROLE_WILDCARD_ADMIN',
          severity,
          category: 'iam',
          title:
            'Role definition has wildcard actions and/or very broad assignable scopes',
          description:
            `Role definition "${name}" grants broad permissions with '*' actions and/or scopes that cover entire subscriptions/tenants.`,
          recommendation:
            'Create more granular custom roles with specific actions and limit assignable scopes to the smallest required scope.',
          resourceType: 'iam-policy',
          resourceId: name,
          location: { path: `roleDefinitions[${index}]` },
        })
      })

      return findings
    },
  },
]

export function analyzeConfig(config) {
  const safe = config && typeof config === 'object' ? config : {}

  const allFindings = RULES.flatMap((rule) => {
    try {
      return rule.check(safe) || []
    } catch (err) {
      console.error(`Error in Azure rule "${rule.id}":`, err)
      return []
    }
  })

  return allFindings.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  )
}
