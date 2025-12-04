// src/tools/cloud-misconfig/multiCloudEngine.js

import {
  analyzeConfig as analyzeAwsConfig,
  exampleConfig as awsExampleConfig,
} from './awsRules.js'
import {
  analyzeConfig as analyzeAzureConfig,
} from './azureRules.js'
import {
  analyzeConfig as analyzeGcpConfig,
} from './gcpRules.js'

export const PLATFORM_LABELS = {
  aws: 'AWS',
  azure: 'Azure',
  gcp: 'GCP',
  unknown: 'Unknown',
}

export function detectPlatform(config) {
  if (!config || typeof config !== 'object') {
    return 'unknown'
  }

  const scores = {
    aws: 0,
    azure: 0,
    gcp: 0,
  }

  const keys = new Set(Object.keys(config))

  const metadata =
    config.metadata && typeof config.metadata === 'object'
      ? config.metadata
      : null

  // ---- 1) Explicit metadata.platform wins hard -----------------------------

  const metaPlatform =
    metadata && typeof metadata.platform === 'string'
      ? metadata.platform.trim().toLowerCase()
      : null

  if (metaPlatform === 'aws') {
    scores.aws += 100
  } else if (metaPlatform === 'azure') {
    scores.azure += 100
  } else if (metaPlatform === 'gcp') {
    scores.gcp += 100
  }

  // ---- 2) Metadata fields --------------------------------------------------

  if (metadata) {
    if (typeof metadata.accountId === 'string') {
      // Typical AWS account id.
      scores.aws += 20
    }
    if (typeof metadata.subscriptionId === 'string') {
      scores.azure += 20
    }
    if (typeof metadata.projectId === 'string') {
      scores.gcp += 20
    }
    if (typeof metadata.region === 'string') {
      const r = metadata.region.toLowerCase()
      if (r.includes('us-east') || r.includes('eu-west')) {
        scores.aws += 3
      }
      if (
        r.includes('westeurope') ||
        r.includes('northeurope') ||
        r.includes('uksouth')
      ) {
        scores.azure += 3
      }
      if (r.includes('us-central') || r.includes('europe-west')) {
        scores.gcp += 3
      }
    }
  }

  // Helper to safely get arrays
  const asArray = (val) => (Array.isArray(val) ? val : [])

  // ---- 3) AWS-ish shapes ---------------------------------------------------

  if (keys.has('securityGroups')) {
    scores.aws += 15
    const sgs = asArray(config.securityGroups)
    if (sgs.length > 0) {
      const sg = sgs[0]
      if (Array.isArray(sg.inboundRules) || Array.isArray(sg.outboundRules)) {
        scores.aws += 10
      }
    }
  }

  if (keys.has('s3Buckets')) {
    scores.aws += 15
    const buckets = asArray(config.s3Buckets)
    if (buckets.length > 0) {
      const b = buckets[0]
      if ('publicRead' in b || 'publicWrite' in b) {
        scores.aws += 5
      }
    }
  }

  if (keys.has('iamPolicies')) {
    scores.aws += 15
    const policies = asArray(config.iamPolicies)
    if (policies.length > 0) {
      const p = policies[0]
      if (Array.isArray(p.statements)) {
        scores.aws += 5
      }
    }
  }

  // ---- 4) Azure-ish shapes -------------------------------------------------

  if (keys.has('networkSecurityGroups')) {
    scores.azure += 15
    const nsgs = asArray(config.networkSecurityGroups)
    if (nsgs.length > 0) {
      const nsg = nsgs[0]
      if (Array.isArray(nsg.rules)) {
        scores.azure += 10
      }
    }
  }

  if (keys.has('storageAccounts')) {
    scores.azure += 15
    const accts = asArray(config.storageAccounts)
    if (accts.length > 0) {
      const a = accts[0]
      if (
        'allowBlobPublicAccess' in a ||
        'publicRead' in a ||
        'publicWrite' in a
      ) {
        scores.azure += 5
      }
    }
  }

  if (keys.has('roleDefinitions')) {
    scores.azure += 15
    const roles = asArray(config.roleDefinitions)
    if (roles.length > 0) {
      const r = roles[0]
      if (Array.isArray(r.permissions) || Array.isArray(r.assignableScopes)) {
        scores.azure += 5
      }
    }
  }

  // ---- 5) GCP-ish shapes ---------------------------------------------------

  if (keys.has('firewallRules')) {
    scores.gcp += 15
    const fw = asArray(config.firewallRules)
    if (fw.length > 0) {
      const f = fw[0]
      if (
        Array.isArray(f.sourceRanges) ||
        'direction' in f ||
        'ports' in f
      ) {
        scores.gcp += 10
      }
    }
  }

  if (keys.has('storageBuckets')) {
    scores.gcp += 15
    const buckets = asArray(config.storageBuckets)
    if (buckets.length > 0) {
      const b = buckets[0]
      if ('publicRead' in b || 'publicWrite' in b) {
        scores.gcp += 5
      }
    }
  }

  if (keys.has('iamBindings')) {
    scores.gcp += 15
    const bindings = asArray(config.iamBindings)
    if (bindings.length > 0) {
      const b = bindings[0]
      if (Array.isArray(b.members) || typeof b.role === 'string') {
        scores.gcp += 5
      }
    }
  }

  // ---- 6) Choose the best score -------------------------------------------

  let bestPlatform = 'unknown'
  let bestScore = 0

  for (const [platform, score] of Object.entries(scores)) {
    if (score > bestScore) {
      bestScore = score
      bestPlatform = platform
    }
  }

  // If we genuinely have no signal, stay unknown.
  if (bestScore === 0) {
    return 'unknown'
  }

  return bestPlatform
}


export function analyzeMultiCloudConfig(config) {
  const platform = detectPlatform(config)

  if (platform === 'aws') {
    return {
      platform,
      findings: analyzeAwsConfig(config),
    }
  }

  if (platform === 'azure') {
    return {
      platform,
      findings: analyzeAzureConfig(config),
    }
  }

    if (platform === 'gcp') {
    return {
      platform,
      findings: analyzeGcpConfig(config),
    }
  }

  // GCP engine can be added here later.
  return {
    platform,
    findings: [],
  }
}

// For now, keep the sample as the AWS example.
// (If you want, we can add a UI toggle to choose AWS vs Azure sample later.)
export const exampleMultiCloudConfig = awsExampleConfig
