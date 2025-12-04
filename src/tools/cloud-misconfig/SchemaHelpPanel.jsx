import React, { useState } from 'react'

const PLATFORM_TABS = [
  { id: 'aws', label: 'AWS' },
  { id: 'azure', label: 'Azure' },
  { id: 'gcp', label: 'GCP' },
]

function SchemaHelpPanel() {
  const [activePlatform, setActivePlatform] = useState('aws')

  return (
    <section className="mt-2 border border-slate-800 rounded-2xl bg-slate-950/70 p-3">
      <div className="flex items-center justify-between gap-2 mb-2">
        <h3 className="text-sm font-semibold text-slate-100">
          How to use this tool
        </h3>
        <div className="inline-flex items-center rounded-full bg-slate-900/80 border border-slate-700 p-0.5 text-[0.65rem]">
          {PLATFORM_TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActivePlatform(tab.id)}
              className={
                activePlatform === tab.id
                  ? 'px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-100 font-semibold'
                  : 'px-2 py-0.5 rounded-full text-slate-300 hover:text-slate-100 hover:bg-slate-800/70'
              }
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <p className="text-[0.7rem] text-slate-300 mb-2">
        Upload a JSON file describing your cloud security configuration using the simplified
        schema below. The scanner runs entirely in your browser and never sends configuration
        data anywhere. Each platform has its own lightweight schema to keep exports easy to
        generate and review.
      </p>

      <p className="text-[0.7rem] text-slate-300 mb-1 font-semibold">
        Common metadata (all platforms):
      </p>
      <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5 mb-3">
        <li>
          <code className="font-mono">metadata</code> - optional object with fields like{' '}
          <code className="font-mono">accountId</code>,{' '}
          <code className="font-mono">projectId</code>,{' '}
          <code className="font-mono">subscriptionId</code>,{' '}
          <code className="font-mono">region</code> and{' '}
          <code className="font-mono">generatedAt</code>.
        </li>
      </ul>

      {/* Platform-specific schemas */}
      {activePlatform === 'aws' && (
        <div>
          <p className="text-[0.7rem] text-slate-300 mb-1 font-semibold">
            AWS expected top-level structure:
          </p>
          <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5 mb-1.5">
            <li>
              <code className="font-mono">securityGroups</code> - array of security group
              objects with <code className="font-mono">inboundRules</code> and{' '}
              <code className="font-mono">outboundRules</code>. Each rule includes{' '}
              <code className="font-mono">protocol</code>,{' '}
              <code className="font-mono">fromPort</code>,{' '}
              <code className="font-mono">toPort</code>,{' '}
              <code className="font-mono">cidr</code> and optional{' '}
              <code className="font-mono">description</code>.
            </li>
            <li>
              <code className="font-mono">s3Buckets</code> - array of buckets with{' '}
              <code className="font-mono">name</code>,{' '}
              <code className="font-mono">publicRead</code>,{' '}
              <code className="font-mono">publicWrite</code> and optional{' '}
              <code className="font-mono">encryptionEnabled</code>,{' '}
              <code className="font-mono">versioningEnabled</code> and{' '}
              <code className="font-mono">policy</code>.
            </li>
            <li>
              <code className="font-mono">iamPolicies</code> - array of IAM policy
              documents. Each policy has <code className="font-mono">name</code> and{' '}
              <code className="font-mono">statements</code>, where every statement contains{' '}
              <code className="font-mono">effect</code>,{' '}
              <code className="font-mono">actions</code> (array) and{' '}
              <code className="font-mono">resources</code> (array).
            </li>
          </ul>
        </div>
      )}

      {activePlatform === 'azure' && (
        <div>
          <p className="text-[0.7rem] text-slate-300 mb-1 font-semibold">
            Azure expected top-level structure:
          </p>
          <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5 mb-1.5">
            <li>
              <code className="font-mono">networkSecurityGroups</code> - array of NSG
              objects with <code className="font-mono">rules</code>. Each rule includes{' '}
              <code className="font-mono">direction</code> (inbound/outbound),{' '}
              <code className="font-mono">protocol</code>,{' '}
              <code className="font-mono">fromPort</code>,{' '}
              <code className="font-mono">toPort</code>,{' '}
              <code className="font-mono">source</code> (CIDR or tag),{' '}
              <code className="font-mono">destination</code> and optional{' '}
              <code className="font-mono">description</code>.
            </li>
            <li>
              <code className="font-mono">storageAccounts</code> - array of storage accounts
              with <code className="font-mono">name</code>,{' '}
              <code className="font-mono">publicRead</code>,{' '}
              <code className="font-mono">publicWrite</code> and flags such as{' '}
              <code className="font-mono">encryptionEnabled</code> and{' '}
              <code className="font-mono">allowBlobPublicAccess</code>.
            </li>
            <li>
              <code className="font-mono">roleDefinitions</code> - array of role or policy
              definitions with <code className="font-mono">name</code>,{' '}
              <code className="font-mono">assignableScopes</code> and{' '}
              <code className="font-mono">permissions</code> (including{' '}
              <code className="font-mono">actions</code> and{' '}
              <code className="font-mono">notActions</code>). A separate{' '}
              <code className="font-mono">roleAssignments</code> array can map principals to
              roles and scopes.
            </li>
          </ul>
        </div>
      )}

      {activePlatform === 'gcp' && (
        <div>
          <p className="text-[0.7rem] text-slate-300 mb-1 font-semibold">
            GCP expected top-level structure:
          </p>
          <ul className="list-disc list-inside text-[0.7rem] text-slate-300 space-y-0.5 mb-1.5">
            <li>
              <code className="font-mono">firewallRules</code> - array of firewall rules
              with <code className="font-mono">direction</code> (INGRESS/EGRESS),{' '}
              <code className="font-mono">protocol</code>,{' '}
              <code className="font-mono">ports</code>,{' '}
              <code className="font-mono">sourceRanges</code> or{' '}
              <code className="font-mono">destinationRanges</code> and optional{' '}
              <code className="font-mono">targetTags</code> and{' '}
              <code className="font-mono">description</code>.
            </li>
            <li>
              <code className="font-mono">storageBuckets</code> - array of buckets with{' '}
              <code className="font-mono">name</code>,{' '}
              <code className="font-mono">publicRead</code>,{' '}
              <code className="font-mono">publicWrite</code> and flags such as{' '}
              <code className="font-mono">uniformBucketLevelAccess</code>,{' '}
              <code className="font-mono">encryptionEnabled</code> and{' '}
              <code className="font-mono">versioningEnabled</code>.
            </li>
            <li>
              <code className="font-mono">iamBindings</code> - array of IAM bindings where
              each entry contains <code className="font-mono">role</code>,{' '}
              <code className="font-mono">members</code> and optional{' '}
              <code className="font-mono">condition</code>. These can be attached to
              projects, folders or buckets.
            </li>
          </ul>
        </div>
      )}

      <p className="text-[0.65rem] text-slate-400 mt-1">
        You can generate these JSON documents from scripts, IaC templates or cloud CLI tools.
        The scanner focuses on static properties such as open CIDR ranges, public storage
        access and overly broad IAM permissions.
      </p>
    </section>
  )
}

export default SchemaHelpPanel
