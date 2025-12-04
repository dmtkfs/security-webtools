// src/tools/cloud-misconfig/gcpRules.js

const SEVERITY_ORDER = {
  high: 0,
  warning: 1,
  info: 2,
}

const SENSITIVE_PORTS = [22, 3389, 5985, 5986, 5900, 445]

function toArray(value) {
  if (Array.isArray(value)) return value
  if (value === undefined || value === null) return []
  return [value]
}

function parsePortRange(token) {
  if (token === undefined || token === null || token === '') {
    return null
  }

  if (typeof token === 'number') {
    const n = Number(token)
    if (Number.isNaN(n)) return null
    return [n, n]
  }

  if (typeof token === 'string') {
    const trimmed = token.trim()
    if (!trimmed) return null

    const rangeParts = trimmed.split('-')
    if (rangeParts.length === 1) {
      const n = Number(rangeParts[0])
      if (Number.isNaN(n)) return null
      return [n, n]
    }

    const start = Number(rangeParts[0])
    const end = Number(rangeParts[1])
    if (Number.isNaN(start) || Number.isNaN(end)) return null
    return [Math.min(start, end), Math.max(start, end)]
  }

  return null
}

// ------------------------ RULES ---------------------------------------------

const RULES = [
  // 1) Firewall: sensitive ports from public ranges
  {
    id: 'GCP_FIREWALL_OPEN_SENSITIVE_PORT',
    description:
      'Detects GCP firewall ingress rules that allow sensitive ports from public ranges.',
    check: (config) => {
        const findings = []
            const rawRules =
            config.firewallRules ||
            config.gcpFirewallRules ||
            config.networkFirewallRules ||
            []

        const rules = Array.isArray(rawRules) ? rawRules : []

      rules.forEach((rule, index) => {
        const direction = (rule.direction || 'INGRESS').toString().toUpperCase()
        if (direction !== 'INGRESS') return

        const sourceRanges = toArray(rule.sourceRanges).map((s) =>
          typeof s === 'string' ? s.trim().toLowerCase() : '',
        )

        const hasWideSource = sourceRanges.some((s) => {
          return s === '0.0.0.0/0' || s === '::/0' || s === '*' || s === 'any'
        })

        if (!hasWideSource) return

        const ports = toArray(rule.ports)
        const parsedRanges = ports.map(parsePortRange).filter(Boolean)
        const effectiveRanges =
          parsedRanges.length > 0 ? parsedRanges : [[0, 65535]]

        SENSITIVE_PORTS.forEach((port) => {
          const exposed = effectiveRanges.some(
            ([from, to]) => from <= port && port <= to,
          )
          if (!exposed) return

          const titlePortLabel =
            port === 22 ? 'SSH' : port === 3389 ? 'RDP' : `port ${port}`

          findings.push({
            id: `GCP_FIREWALL_OPEN_SENSITIVE_PORT_${rule.name || index}_${port}`,
            ruleId: 'GCP_FIREWALL_OPEN_SENSITIVE_PORT',
            severity: 'high',
            category: 'network',
            title: `Firewall rule allows ${titlePortLabel} from anywhere`,
            description:
              `An ingress firewall rule allows TCP ${port} from 0.0.0.0/0 or an equivalent public source range, exposing this service to the internet.`,
            recommendation:
              'Restrict this rule to specific source ranges (office IPs, VPN CIDR blocks) or route admin access through bastion hosts instead of the open internet.',
            resourceType: 'security-group',
            resourceId: rule.name || rule.id || `firewall-${index}`,
            location: { path: `firewallRules[${index}]` },
          })
        })
      })

      return findings
    },
  },

  // 2) Firewall: all ports from anywhere
  {
    id: 'GCP_FIREWALL_OPEN_ALL_PORTS',
    description:
      'Detects GCP firewall rules that allow all ports from public ranges.',
    check: (config) => {
        const findings = []
            const rawRules =
            config.firewallRules ||
            config.gcpFirewallRules ||
            config.networkFirewallRules ||
        []

        const rules = Array.isArray(rawRules) ? rawRules : []

      rules.forEach((rule, index) => {
        const direction = (rule.direction || 'INGRESS').toString().toUpperCase()
        if (direction !== 'INGRESS') return

        const sourceRanges = toArray(rule.sourceRanges).map((s) =>
          typeof s === 'string' ? s.trim().toLowerCase() : '',
        )

        const hasWideSource = sourceRanges.some((s) => {
          return s === '0.0.0.0/0' || s === '::/0' || s === '*' || s === 'any'
        })

        if (!hasWideSource) return

        const ports = toArray(rule.ports)
        const parsedRanges = ports.map(parsePortRange).filter(Boolean)
        const effectiveRanges =
          parsedRanges.length > 0 ? parsedRanges : [[0, 65535]]

        const openAll = effectiveRanges.some(
          ([from, to]) => from <= 0 && to >= 65535,
        )
        if (!openAll) return

        findings.push({
          id: `GCP_FIREWALL_OPEN_ALL_PORTS_${rule.name || index}`,
          ruleId: 'GCP_FIREWALL_OPEN_ALL_PORTS',
          severity: 'high',
          category: 'network',
          title: 'Firewall rule allows all ports from anywhere',
          description:
            'An ingress firewall rule allows traffic from 0.0.0.0/0 across the full port range, exposing many services to the internet.',
          recommendation:
            'Replace this rule with narrowly scoped rules for specific ports and trusted CIDR ranges only.',
          resourceType: 'security-group',
          resourceId: rule.name || rule.id || `firewall-${index}`,
          location: { path: `firewallRules[${index}]` },
        })
      })

      return findings
    },
  },

  // 3) Storage buckets: public access + encryption/versioning
  {
    id: 'GCP_STORAGE_PUBLIC_ACCESS',
    description:
      'Detects GCS buckets that are publicly readable/writable or lack encryption.',
    check: (config) => {
        const findings = []
            const rawBuckets =
            config.storageBuckets ||
            config.gcpStorageBuckets ||
            config.buckets ||
        []

        const buckets = Array.isArray(rawBuckets) ? rawBuckets : []


      buckets.forEach((bucket, index) => {
        const name = bucket.name || `bucket-${index}`
        const publicRead = Boolean(bucket.publicRead)
        const publicWrite = Boolean(bucket.publicWrite)
        const encryptionEnabled = bucket.encryptionEnabled !== false
        const versioningEnabled = bucket.versioningEnabled !== false

        if (publicRead && publicWrite) {
          findings.push({
            id: `GCP_STORAGE_PUBLIC_READ_WRITE_${name}`,
            ruleId: 'GCP_STORAGE_PUBLIC_ACCESS',
            severity: 'high',
            category: 'storage',
            title: 'Storage bucket has public read and write access',
            description:
              `Bucket "${name}" is configured with public read and public write access. Objects may be readable and modifiable by anyone on the internet.`,
            recommendation:
              'Disable public read/write and rely on IAM, ACLs, or signed URLs. Use organization policies to prevent public buckets where possible.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `storageBuckets[${index}]` },
          })
        } else if (publicWrite) {
          findings.push({
            id: `GCP_STORAGE_PUBLIC_WRITE_${name}`,
            ruleId: 'GCP_STORAGE_PUBLIC_ACCESS',
            severity: 'high',
            category: 'storage',
            title: 'Storage bucket has public write access',
            description:
              `Bucket "${name}" allows public write access. Attackers could upload or overwrite objects.`,
            recommendation:
              'Disable public write access and restrict writes to trusted identities only.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `storageBuckets[${index}]` },
          })
        } else if (publicRead) {
          findings.push({
            id: `GCP_STORAGE_PUBLIC_READ_${name}`,
            ruleId: 'GCP_STORAGE_PUBLIC_ACCESS',
            severity: 'warning',
            category: 'storage',
            title: 'Storage bucket has public read access',
            description:
              `Bucket "${name}" allows public read access. Objects may be downloaded by anyone on the internet.`,
            recommendation:
              'Ensure this is intended. Otherwise, disable public read and use controlled sharing via ACLs, IAM, or signed URLs.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `storageBuckets[${index}]` },
          })
        }

        if (!encryptionEnabled) {
          findings.push({
            id: `GCP_STORAGE_NO_ENCRYPTION_${name}`,
            ruleId: 'GCP_STORAGE_PUBLIC_ACCESS',
            severity: 'info',
            category: 'storage',
            title: 'Storage bucket does not have encryption enabled',
            description:
              `Bucket "${name}" appears with encryption disabled in this simplified schema.`,
            recommendation:
              'Enable default encryption for the bucket, preferably using a CMEK for sensitive workloads.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `storageBuckets[${index}]` },
          })
        }

        if (!versioningEnabled) {
          findings.push({
            id: `GCP_STORAGE_NO_VERSIONING_${name}`,
            ruleId: 'GCP_STORAGE_PUBLIC_ACCESS',
            severity: 'info',
            category: 'storage',
            title: 'Storage bucket does not have versioning enabled',
            description:
              `Bucket "${name}" does not have versioning enabled, which can make it harder to recover from overwrite or delete incidents.`,
            recommendation:
              'Enable object versioning for buckets that store important data to improve recoverability.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `storageBuckets[${index}]` },
          })
        }
      })

      return findings
    },
  },

  // 4) IAM bindings: public members or owner/editor/admin roles
  {
    id: 'GCP_IAM_PUBLIC_OR_OWNER_BINDING',
    description:
      'Detects IAM bindings that use allUsers/allAuthenticatedUsers or grant admin-level roles.',
    check: (config) => {
        const findings = []
        const rawBindings =
            config.iamBindings ||
            config.iamPolicies ||
            config.gcpIamBindings ||
        []

        const bindings = Array.isArray(rawBindings) ? rawBindings : []


      bindings.forEach((binding, index) => {
        const role = typeof binding.role === 'string' ? binding.role.trim() : ''
        const members = toArray(binding.members).map((m) =>
          typeof m === 'string' ? m.trim() : '',
        )
        const scope = binding.scope || binding.resource || 'project'

        const hasPublicMember = members.some(
          (m) => m === 'allUsers' || m === 'allAuthenticatedUsers',
        )

        const roleLower = role.toLowerCase()
        const isOwnerLike =
          roleLower === 'roles/owner' ||
          roleLower === 'roles/editor' ||
          roleLower.endsWith('.admin')

        if (hasPublicMember) {
          findings.push({
            id: `GCP_IAM_PUBLIC_BINDING_${index}`,
            ruleId: 'GCP_IAM_PUBLIC_OR_OWNER_BINDING',
            severity: 'high',
            category: 'iam',
            title: 'IAM binding grants public access',
            description:
              `An IAM binding for role "${role}" includes allUsers or allAuthenticatedUsers, making the resource at scope "${scope}" publicly accessible.`,
            recommendation:
              'Remove allUsers/allAuthenticatedUsers and restrict access to specific identities (service accounts, groups, or users).',
            resourceType: 'iam-policy',
            resourceId: role || `binding-${index}`,
            location: { path: `iamBindings[${index}]` },
          })
        }

        if (isOwnerLike) {
          findings.push({
            id: `GCP_IAM_OWNER_BINDING_${index}`,
            ruleId: 'GCP_IAM_PUBLIC_OR_OWNER_BINDING',
            severity: 'high',
            category: 'iam',
            title: 'IAM binding grants highly privileged role',
            description:
              `IAM binding for scope "${scope}" grants a highly privileged role "${role}", which can manage most or all resources in that scope.`,
            recommendation:
              'Use more granular roles (service- or resource-specific) instead of owner/editor/admin, and keep the number of such principals small.',
            resourceType: 'iam-policy',
            resourceId: role || `binding-${index}`,
            location: { path: `iamBindings[${index}]` },
          })
        }
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
      console.error(`Error in GCP rule "${rule.id}":`, err)
      return []
    }
  })

  return allFindings.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  )
}
