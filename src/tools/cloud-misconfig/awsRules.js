// src/tools/cloud-misconfig/awsRules.js

const SEVERITY_ORDER = {
  high: 0,
  warning: 1,
  info: 2,
}

const SENSITIVE_PORTS = [22, 3389, 5900]

// Helper
function toArray(value) {
  if (Array.isArray(value)) return value
  if (value === undefined || value === null) return []
  return [value]
}

function normalizeCidr(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : ''
}

// ------------------------ RULES ---------------------------------------------

const RULES = [
  // 1) SG: 0.0.0.0/0 on sensitive ports (SSH, RDP, VNC, etc.)
  {
    id: 'AWS_SG_OPEN_SENSITIVE_PORT',
    description:
      'Detects AWS security group rules that allow sensitive ports from 0.0.0.0/0.',
    check: (config) => {
      const findings = []
      const rawSgs =
        config.securityGroups ||
        config.awsSecurityGroups ||
        config.sg ||
        config.security_groups ||
        []

      const sgs = Array.isArray(rawSgs) ? rawSgs : []


      sgs.forEach((sg, sgIndex) => {
        const sgName = sg.name || sg.id || `sg-${sgIndex}`
        const inbound = Array.isArray(sg.inboundRules)
          ? sg.inboundRules
          : []

        inbound.forEach((rule, ruleIndex) => {
          const cidr = normalizeCidr(rule.cidr || rule.source || '')
          if (
            cidr !== '0.0.0.0/0' &&
            cidr !== '::/0' &&
            cidr !== 'any' &&
            cidr !== '*'
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
                id: `AWS_SG_OPEN_SENSITIVE_PORT_${sgName}_${ruleIndex}_${port}`,
                ruleId: 'AWS_SG_OPEN_SENSITIVE_PORT',
                severity: 'high',
                category: 'network',
                title: `Security group allows ${label} from anywhere`,
                description:
                  `An inbound rule allows TCP port ${port} from 0.0.0.0/0, exposing this service to the internet.`,
                recommendation:
                  'Restrict this rule to known IP ranges, use a bastion host, or require VPN / private connectivity instead of exposing these ports publicly.',
                resourceType: 'security-group',
                resourceId: sgName,
                location: {
                  path: `securityGroups[${sgIndex}].inboundRules[${ruleIndex}]`,
                },
              })
            }
          })
        })
      })

      return findings
    },
  },

  // 2) SG: open ALL ports to 0.0.0.0/0
  {
    id: 'AWS_SG_OPEN_ALL_PORTS',
    description:
      'Detects AWS security group rules that allow all ports from 0.0.0.0/0.',
    check: (config) => {
      const findings = []
      const rawSgs =
        config.securityGroups ||
        config.awsSecurityGroups ||
        config.sg ||
        config.security_groups ||
        []

      const sgs = Array.isArray(rawSgs) ? rawSgs : []

      sgs.forEach((sg, sgIndex) => {
        const sgName = sg.name || sg.id || `sg-${sgIndex}`
        const inbound = Array.isArray(sg.inboundRules)
          ? sg.inboundRules
          : []

        inbound.forEach((rule, ruleIndex) => {
          const cidr = normalizeCidr(rule.cidr || rule.source || '')
          if (
            cidr !== '0.0.0.0/0' &&
            cidr !== '::/0' &&
            cidr !== 'any' &&
            cidr !== '*'
          ) {
            return
          }

          const from = Number(rule.fromPort)
          const to = Number(rule.toPort)
          if (Number.isNaN(from) || Number.isNaN(to)) return

          if (from <= 0 && to >= 65535) {
            findings.push({
              id: `AWS_SG_OPEN_ALL_PORTS_${sgName}_${ruleIndex}`,
              ruleId: 'AWS_SG_OPEN_ALL_PORTS',
              severity: 'high',
              category: 'network',
              title: 'Security group allows all ports from anywhere',
              description:
                'An inbound rule allows traffic from 0.0.0.0/0 across the full port range, exposing many services to the internet.',
              recommendation:
                'Replace this rule with narrowly scoped rules for specific ports and trusted CIDR ranges.',
              resourceType: 'security-group',
              resourceId: sgName,
              location: {
                path: `securityGroups[${sgIndex}].inboundRules[${ruleIndex}]`,
              },
            })
          }
        })
      })

      return findings
    },
  },

  // 3) S3: public read/write and missing encryption
  {
    id: 'AWS_S3_PUBLIC_ACCESS',
    description:
      'Detects S3 buckets with public read/write access and lack of encryption.',
    check: (config) => {
      const findings = []
      const rawBuckets =
        config.s3Buckets ||
        config.storageBuckets ||
        config.buckets ||
        config.awsBuckets ||
        []

      const buckets = Array.isArray(rawBuckets) ? rawBuckets : []


      buckets.forEach((bucket, index) => {
        const name = bucket.name || `bucket-${index}`
        const publicRead = Boolean(bucket.publicRead)
        const publicWrite = Boolean(bucket.publicWrite)
        const encryptionEnabled = bucket.encryptionEnabled !== false // default: ok

        if (!publicRead && !publicWrite && encryptionEnabled) return

        if (publicRead && publicWrite) {
          findings.push({
            id: `AWS_S3_PUBLIC_READ_WRITE_${name}`,
            ruleId: 'AWS_S3_PUBLIC_ACCESS',
            severity: 'high',
            category: 'storage',
            title: 'S3 bucket has public read and write access',
            description:
              `Bucket "${name}" is configured with public read and public write access. Objects may be readable and modifiable by anyone on the internet.`,
            recommendation:
              'Disable public read/write, enable S3 Block Public Access, and restrict access via IAM policies or bucket policies to specific principals.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `s3Buckets[${index}]` },
          })
        } else if (publicWrite) {
          findings.push({
            id: `AWS_S3_PUBLIC_WRITE_${name}`,
            ruleId: 'AWS_S3_PUBLIC_ACCESS',
            severity: 'high',
            category: 'storage',
            title: 'S3 bucket has public write access',
            description:
              `Bucket "${name}" allows public write access. Attackers could upload or overwrite data.`,
            recommendation:
              'Disable public write access and restrict writes to trusted IAM principals only.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `s3Buckets[${index}]` },
          })
        } else if (publicRead) {
          findings.push({
            id: `AWS_S3_PUBLIC_READ_${name}`,
            ruleId: 'AWS_S3_PUBLIC_ACCESS',
            severity: 'warning',
            category: 'storage',
            title: 'S3 bucket has public read access',
            description:
              `Bucket "${name}" allows public read access. Objects may be downloaded by anyone on the internet.`,
            recommendation:
              'Ensure this is intended. Otherwise, disable public read and enforce access through authenticated IAM or signed URLs.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `s3Buckets[${index}]` },
          })
        }

        if (!encryptionEnabled) {
          findings.push({
            id: `AWS_S3_NO_ENCRYPTION_${name}`,
            ruleId: 'AWS_S3_PUBLIC_ACCESS',
            severity: 'info',
            category: 'storage',
            title: 'S3 bucket does not have encryption flag enabled',
            description:
              `Bucket "${name}" appears with encryption disabled in this simplified schema.`,
            recommendation:
              'Enable default encryption on the bucket using a KMS-managed or AWS-managed key, especially for sensitive data.',
            resourceType: 's3-bucket',
            resourceId: name,
            location: { path: `s3Buckets[${index}]` },
          })
        }
      })

      return findings
    },
  },

  // 4) IAM: wildcard actions/resources
  {
    id: 'AWS_IAM_WILDCARD_POLICY',
    description:
      'Detects IAM policies that use "*" for Action and/or Resource.',
    check: (config) => {
      const findings = []
      const rawPolicies =
        config.iamPolicies ||
        config.policies ||
        config.awsIamPolicies ||
        []

      const policies = Array.isArray(rawPolicies) ? rawPolicies : []


      policies.forEach((policy, index) => {
        const name = policy.name || `policy-${index}`
        const statements = Array.isArray(policy.statements)
          ? policy.statements
          : []

        statements.forEach((stmt, stmtIndex) => {
          const actions = toArray(stmt.actions)
          const resources = toArray(stmt.resources)
          const hasActionAll = actions.includes('*')
          const hasResourceAll = resources.includes('*')

          if (!hasActionAll && !hasResourceAll) return

          let severity = 'warning'
          if (hasActionAll && hasResourceAll) {
            severity = 'high'
          }

          findings.push({
            id: `AWS_IAM_WILDCARD_POLICY_${name}_${stmtIndex}`,
            ruleId: 'AWS_IAM_WILDCARD_POLICY',
            severity,
            category: 'iam',
            title: 'IAM policy uses "*" in actions or resources',
            description:
              `Policy "${name}" includes a statement that grants overly broad access with "*" in actions and/or resources.`,
            recommendation:
              'Replace wildcards with the minimum required actions and scope the resources to specific ARNs or paths where possible.',
            resourceType: 'iam-policy',
            resourceId: name,
            location: { path: `iamPolicies[${index}].statements[${stmtIndex}]` },
          })
        })
      })

      return findings
    },
  },
]

// Example config (you already have this; keep or tweak as needed)
export const exampleConfig = {
  metadata: {
    platform: 'aws',
    accountId: '123456789012',
    region: 'us-east-1',
    generatedAt: '2025-01-01T12:00:00Z',
    source: 'example',
  },
  securityGroups: [
    {
      id: 'sg-0123456789abcdef0',
      name: 'public-ssh-sg',
      inboundRules: [
        {
          protocol: 'tcp',
          fromPort: 22,
          toPort: 22,
          cidr: '0.0.0.0/0',
          description: 'Allow SSH from anywhere',
        },
      ],
      outboundRules: [],
    },
  ],
  s3Buckets: [
    {
      name: 'my-public-bucket',
      publicRead: true,
      publicWrite: true,
      encryptionEnabled: false,
    },
  ],
  iamPolicies: [
    {
      name: 'wildcard-admin',
      statements: [
        {
          effect: 'Allow',
          actions: ['*'],
          resources: ['*'],
        },
      ],
    },
  ],
}

export function analyzeConfig(config) {
  const safe = config && typeof config === 'object' ? config : {}

  const allFindings = RULES.flatMap((rule) => {
    try {
      return rule.check(safe) || []
    } catch (err) {
      console.error(`Error in AWS rule "${rule.id}":`, err)
      return []
    }
  })

  return allFindings.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  )
}
