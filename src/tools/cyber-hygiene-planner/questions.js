// Profiles (explicit, user-proof)
export const PROFILES = [
  {
    id: 'personal',
    title: 'Personal use (home/family)',
    description:
      'Everyday accounts and devices for home life. No clients, no employees, no business systems.',
  },
  {
    id: 'freelancer',
    title: 'Freelancer/Contractor (solo)',
    description:
      'You work alone but handle client work, accounts or data (even if it’s “just a few clients”).',
  },
  {
    id: 'small-org',
    title: 'Small business/organization (1-20 people)',
    description:
      'Multiple people, shared systems, onboarding/offboarding and shared cloud/SaaS administration.',
  },
]

// Verticals
export const VERTICALS = [
  {
    id: 'general',
    title: 'General/mixed use',
    description:
      'No specific industry focus, a bit of everything (or not sure what to pick).',
  },
  {
    id: 'payments',
    title: 'Retail/payments/financial transactions',
    description:
      'You accept payments or handle financial transactions (POS, e-commerce, invoices).',
  },
  {
    id: 'sensitive-client-data',
    title: 'Sensitive client data (professional services, healthcare)',
    description:
      'You handle sensitive client/patient information such as medical records, legal/financial documents or personal identifiers.',
  },  
  {
    id: 'online-services',
    title: 'Online services/software',
    description:
      'You run websites, apps, APIs or online services with user accounts and uptime concerns.',
  },
]

// Wizard sections (domains)
export const SECTIONS = [
  {
    id: 'identity_access',
    title: 'Identity & Access',
    description:
      'Account security, authentication strength, admin separation and recovery.',
    appliesTo: ['personal', 'freelancer', 'small-org'],
  },
  {
    id: 'devices_endpoints',
    title: 'Devices & Endpoints',
    description: 'Updates, malware protection, encryption and device hygiene.',
    appliesTo: ['personal', 'freelancer', 'small-org'],
  },
  {
    id: 'data_backups',
    title: 'Data & Backups',
    description:
      'Backups, recovery readiness, ransomware resilience and sensitive data handling.',
    appliesTo: ['personal', 'freelancer', 'small-org'],
  },
  {
    id: 'network_cloud',
    title: 'Network & Cloud',
    description:
      'Wi-Fi/router basics, cloud/SaaS posture and exposure reduction.',
    appliesTo: ['personal', 'freelancer', 'small-org'],
  },
  {
    id: 'monitoring_response',
    title: 'Monitoring & Response',
    description: 'Alerting, logging basics and incident response readiness.',
    appliesTo: ['personal', 'freelancer', 'small-org'],
  },
]

// Priority ordering
export const PRIORITY_ORDER = {
  High: 3,
  Medium: 2,
  Low: 1,
}

// Helper for default boosts
const DEFAULT_VERTICAL_BOOSTS = {
  general: 0,
  'sensitive-client-data': 0,
  payments: 0,
  'online-services': 0,
}

// Action library
export const ACTIONS = [
  // Identity & Access
  {
    id: 'enable_mfa_everywhere',
    domain: 'identity_access',
    title: 'Enable MFA on important accounts',
    why: 'Multi-factor authentication is one of the highest ROI controls against account takeover.',
    firstSteps: [
      'Start with email, password manager, banking and primary cloud/admin accounts.',
      'Prefer authenticator apps or hardware keys over SMS where possible.',
      'Store recovery codes securely (offline or in a password manager vault).',
    ],
    basePriority: 'High',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 25,
      payments: 25,
      'online-services': 25,
    },
    references: [
      {
        label: 'NIST SP 800-63B (Digital Identity Guidelines)',
        url: 'https://pages.nist.gov/800-63-4/sp800-63.html',
      },
    ],
  },
  {
    id: 'use_password_manager',
    domain: 'identity_access',
    title: 'Use a password manager + unique passwords',
    why: 'Unique passwords reduce blast radius from credential reuse and breaches.',
    firstSteps: [
      'Pick a reputable password manager and enable MFA for it.',
      'Generate unique passwords for high-value accounts first.',
      'Avoid storing secrets in plain notes or shared docs.',
    ],
    basePriority: 'High',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 15,
      payments: 20,
      'online-services': 15,
    },
    references: [
      {
        label: 'CIS Critical Security Controls v8.1 (Account Management, Access Control)',
        url: 'https://www.cisecurity.org/controls',
      },
    ],
  },
  {
    id: 'secure_recovery_methods',
    domain: 'identity_access',
    title: 'Harden account recovery (email, phone, backup codes)',
    why: 'Recovery paths are often the weakest link and are targeted by attackers.',
    firstSteps: [
      'Remove old phone numbers/emails from recovery settings.',
      'Use an authenticator app and keep backup codes offline.',
      'Document “break-glass” recovery for critical/admin accounts.',
    ],
    basePriority: 'High',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 20,
      payments: 20,
      'online-services': 20,
    },
    references: [
      {
        label: 'NIST SP 800-63B (Recovery considerations)',
        url: 'https://pages.nist.gov/800-63-4/sp800-63b.html',
      },
    ],
  },
  {
    id: 'admin_separation',
    domain: 'identity_access',
    title: 'Separate admin accounts from daily-use accounts',
    why: 'Reduces exposure: admin credentials should be used rarely and protected more strongly.',
    firstSteps: [
      'Create dedicated admin accounts for cloud/SaaS consoles.',
      'Require MFA (prefer hardware keys) on admin identities.',
      'Use least privilege, avoid “everyone is admin”.',
    ],
    basePriority: 'High',
    effort: 'Medium',
    execution: 'IT Support',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 25,
      payments: 20,
      'online-services': 30,
    },
    references: [
      {
        label: 'CIS Critical Security Controls v8.1 (Access Control Management)',
        url: 'https://www.cisecurity.org/controls',
      },
    ],
  },
  {
    id: 'offboarding_process',
    domain: 'identity_access',
    title: 'Implement a simple onboarding/offboarding checklist',
    why: 'Stale accounts and access sprawl are common in small teams and lead to unintended exposure.',
    firstSteps: [
      'Keep a list of systems where accounts exist (email, SaaS, Git, VPN, cloud).',
      'Use a checklist for joiner/mover/leaver events.',
      'Remove access within 24 hours of departure, rotate shared secrets.',
    ],
    basePriority: 'High',
    effort: 'Medium',
    execution: 'IT Support',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 30,
      payments: 15,
      'online-services': 20,
    },
    references: [
      {
        label: 'CIS Critical Security Controls v8.1 (Account Management)',
        url: 'https://www.cisecurity.org/controls',
      },
    ],
  },

  // Devices & Endpoints
  {
    id: 'standardize_updates',
    domain: 'devices_endpoints',
    title: 'Keep OS and key apps automatically updated',
    why: 'Patch lag is a top driver of compromise for both individuals and small teams.',
    firstSteps: [
      'Enable automatic OS updates on all endpoints.',
      'Update browsers, password managers, VPN clients and productivity suites.',
      'For teams: define a patch window and track exceptions.',
    ],
    basePriority: 'High',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 20,
      payments: 15,
      'online-services': 15,
    },
    references: [
      {
        label: 'CISA Secure by Design (general guidance)',
        url: 'https://www.cisa.gov/securebydesign',
      },
    ],
  },
  {
    id: 'endpoint_encryption',
    domain: 'devices_endpoints',
    title: 'Enable full-disk encryption on laptops and mobile devices',
    why: 'Protects data if a device is lost/stolen and reduces incident impact.',
    firstSteps: [
      'Enable BitLocker/FileVault and store recovery keys safely.',
      'Use strong device PIN/password and lock screen timeouts.',
      'For teams: require encryption for any device accessing work accounts.',
    ],
    basePriority: 'High',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 30,
      payments: 15,
      'online-services': 10,
    },
    references: [
      {
        label: 'CIS Critical Security Controls v8.1 (Device Security)',
        url: 'https://www.cisecurity.org/controls',
      },
    ],
  },
  {
    id: 'endpoint_malware_protection',
    domain: 'devices_endpoints',
    title: 'Use reputable endpoint protection and safe defaults',
    why: 'Baseline endpoint protection and safe configuration reduces commodity malware success.',
    firstSteps: [
      'Ensure built-in protections are enabled (e.g., Microsoft Defender) and updated.',
      'Avoid daily “run as admin”, use least privilege.',
      'For teams: standardize endpoint baseline settings.',
    ],
    basePriority: 'Medium',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 15,
      payments: 20,
      'online-services': 10,
    },
    references: [
      { label: 'CIS Critical Security Controls v8.1', url: 'https://www.cisecurity.org/controls' },
    ],
  },
  {
    id: 'mdm_or_inventory',
    domain: 'devices_endpoints',
    title: 'Maintain a basic device inventory (and device management if possible)',
    why: 'You can’t secure what you can’t enumerate, small teams often lose track of endpoints.',
    firstSteps: [
      'Create a simple inventory: device, owner, OS version, encryption status.',
      'If feasible, use device management (MDM) for policy enforcement and remote wipe.',
      'Define rules for BYOD vs company-owned devices.',
    ],
    basePriority: 'Medium',
    effort: 'Medium',
    execution: 'IT Support',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 25,
      payments: 15,
      'online-services': 10,
    },
    references: [
      { label: 'CIS Critical Security Controls v8.1', url: 'https://www.cisecurity.org/controls' },
    ],
  },

  // Data & Backups
  {
    id: 'tested_backups_3_2_1',
    domain: 'data_backups',
    title: 'Adopt 3-2-1 backups and test restores',
    why: 'Backups without restore testing often fail during real incidents.',
    firstSteps: [
      'Keep 3 copies, on 2 different media, with 1 copy offline/offsite.',
      'Test a restore monthly (even a small sample).',
      'For teams: define RPO/RTO targets and label critical datasets.',
    ],
    basePriority: 'High',
    effort: 'Medium',
    execution: 'IT Support',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 20,
      payments: 20,
      'online-services': 35,
    },
    references: [
      { label: 'CISA Stop Ransomware (general guidance)', url: 'https://www.cisa.gov/stopransomware' },
    ],
  },
  {
    id: 'protect_backups_from_ransomware',
    domain: 'data_backups',
    title: 'Protect backups from ransomware and account takeover',
    why: 'Attackers often delete or encrypt backups first.',
    firstSteps: [
      'Use separate credentials for backup storage.',
      'Enable versioning/immutability where available.',
      'Restrict who can delete backups, require MFA.',
    ],
    basePriority: 'High',
    effort: 'Medium',
    execution: 'IT Support',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 25,
      payments: 25,
      'online-services': 40,
    },
    references: [
      { label: 'CISA Stop Ransomware', url: 'https://www.cisa.gov/stopransomware' },
    ],
  },
  {
    id: 'data_classification_light',
    domain: 'data_backups',
    title: 'Identify sensitive data and reduce unnecessary retention',
    why: 'Lower retention and clearer data handling reduces breach impact.',
    firstSteps: [
      'List the sensitive data you store (client records, financial data, credentials).',
      'Remove old exports and shared links you no longer need.',
      'For teams: define approved storage locations and a “do not store” list.',
    ],
    basePriority: 'Medium',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 40,
      payments: 20,
      'online-services': 10,
    },
    references: [
      { label: 'NIST Privacy Framework', url: 'https://www.nist.gov/privacy-framework' },
    ],
  },

  // Network & Cloud
  {
    id: 'secure_wifi_router',
    domain: 'network_cloud',
    title: 'Secure Wi-Fi/router basics (WPA2/3, firmware, admin password)',
    why: 'Home and small office routers are common weak points.',
    firstSteps: [
      'Use WPA2/WPA3 with a strong passphrase, disable WPS.',
      'Change router admin password, update firmware.',
      'Segment guest/IoT devices from main devices if possible.',
    ],
    basePriority: 'Medium',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 10,
      payments: 10,
      'online-services': 5,
    },
    references: [
      {
        label: 'CISA Home Network Security',
        url: 'https://www.cisa.gov/news-events/news/home-network-security',
      },
    ],
  },
  {
    id: 'review_cloud_sharing',
    domain: 'network_cloud',
    title: 'Review cloud/SaaS sharing and access regularly',
    why: 'Overshared files and stale permissions cause silent exposure.',
    firstSteps: [
      'Audit public links and externally shared folders.',
      'Use least-privilege sharing: specific people, expiration, view-only.',
      'For teams: ensure offboarding removes shared access and links.',
    ],
    basePriority: 'High',
    effort: 'Low',
    execution: 'IT Support',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 35,
      payments: 15,
      'online-services': 15,
    },
    references: [
      { label: 'CIS Critical Security Controls v8.1', url: 'https://www.cisecurity.org/controls' },
    ],
  },
  {
    id: 'lock_down_admin_console',
    domain: 'network_cloud',
    title: 'Harden admin consoles (MFA, alerts, privileged roles)',
    why: 'Admin consoles are high-value targets, hardening reduces takeover risk.',
    firstSteps: [
      'Require MFA for all admins, prefer hardware keys if feasible.',
      'Enable suspicious login alerts, review privileged roles.',
      'Restrict admin access devices (where supported).',
    ],
    basePriority: 'High',
    effort: 'Medium',
    execution: 'IT Support',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 30,
      payments: 25,
      'online-services': 35,
    },
    references: [
      { label: 'CIS Critical Security Controls v8.1', url: 'https://www.cisecurity.org/controls' },
    ],
  },

  // Monitoring & Response
  {
    id: 'enable_security_alerts',
    domain: 'monitoring_response',
    title: 'Enable security alerts for key services',
    why: 'Early detection reduces dwell time and containment cost.',
    firstSteps: [
      'Turn on alerts for new logins, MFA changes, forwarding rules, suspicious access.',
      'Route alerts to at least two channels (email + phone/secondary mailbox).',
      'For teams: route alerts to a shared mailbox or ticketing channel.',
    ],
    basePriority: 'High',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 25,
      payments: 30,
      'online-services': 25,
    },
    references: [
      { label: 'CISA Cyber Guidance', url: 'https://www.cisa.gov/topics/cybersecurity-best-practices' },
    ],
  },
  {
    id: 'basic_ir_plan',
    domain: 'monitoring_response',
    title: 'Create a lightweight incident response plan',
    why: 'A simple plan prevents panic and speeds containment.',
    firstSteps: [
      'Write down: who to contact, where backups are, how to reset accounts.',
      'Define “stop the bleeding” steps: revoke sessions, rotate keys, isolate devices.',
      'For teams: assign roles (incident lead, communications, technical).',
    ],
    basePriority: 'Medium',
    effort: 'Low',
    execution: 'Self',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 20,
      payments: 20,
      'online-services': 25,
    },
    references: [
      {
        label: 'NIST SP 800-61 (Incident Response Recommendations and Considerations for Cybersecurity Risk Management)',
        url: 'https://csrc.nist.gov/pubs/sp/800/61/r3/final',
      },
    ],
  },
  {
    id: 'log_centralization_light',
    domain: 'monitoring_response',
    title: 'Centralize critical logs (even minimally)',
    why: 'Basic logs help you confirm what happened and scope incidents.',
    firstSteps: [
      'At minimum: identity provider logs, email audit logs, admin console logs.',
      'Store logs in a protected location with restricted deletion.',
      'Review weekly or after major changes.',
    ],
    basePriority: 'Medium',
    effort: 'Medium',
    execution: 'IT Support',
    verticalBoosts: {
      ...DEFAULT_VERTICAL_BOOSTS,
      'sensitive-client-data': 35,
      payments: 25,
      'online-services': 35,
    },
    references: [
      {
        label: 'CIS Critical Security Controls v8.1 (Audit Log Management)',
        url: 'https://www.cisecurity.org/controls',
      },
    ],
  },
]

// Questions (data only, no UI)
export const QUESTIONS = [
  // Identity & Access
  {
    id: 'ida_mfa_coverage',
    sectionId: 'identity_access',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'How widely is MFA enabled on important accounts?',
    helpText:
      'Think: primary email, password manager, banking, cloud/SaaS admin, Git, VPN.',
    options: [
      {
        value: 'none',
        label: 'Rarely/almost nowhere',
        points: 0,
        triggersOnSelect: ['enable_mfa_everywhere'],
        riskBoost: 2,
      },
      {
        value: 'some',
        label: 'On some important accounts',
        points: 6,
        triggersOnSelect: ['enable_mfa_everywhere'],
        riskBoost: 1,
      },
      { value: 'most', label: 'On most important accounts', points: 10 },
    ],
  },
  {
    id: 'ida_passwords',
    sectionId: 'identity_access',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Password habits today look like…',
    options: [
      {
        value: 'reuse',
        label: 'Some reuse/predictable patterns',
        points: 0,
        triggersOnSelect: ['use_password_manager'],
        riskBoost: 2,
      },
      {
        value: 'mostly_unique',
        label: 'Mostly unique, but inconsistent',
        points: 6,
        triggersOnSelect: ['use_password_manager'],
        riskBoost: 1,
      },
      {
        value: 'manager',
        label: 'Password manager + unique passwords',
        points: 10,
      },
    ],
  },
  {
    id: 'ida_recovery',
    sectionId: 'identity_access',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'How confident are you in account recovery readiness?',
    helpText:
      'Recovery email/phone is current, backup codes stored safely, you could recover without panic.',
    options: [
      {
        value: 'not_ready',
        label: 'Not confident/unsure',
        points: 0,
        triggersOnSelect: ['secure_recovery_methods'],
        riskBoost: 2,
      },
      {
        value: 'somewhat',
        label: 'Somewhat confident',
        points: 6,
        triggersOnSelect: ['secure_recovery_methods'],
        riskBoost: 1,
      },
      { value: 'ready', label: 'Confident and tested', points: 10 },
    ],
  },
  {
    id: 'ida_admin_separation',
    sectionId: 'identity_access',
    appliesTo: ['small-org', 'freelancer'],
    type: 'radio',
    prompt: 'Do you separate admin accounts from daily accounts?',
    options: [
      {
        value: 'no',
        label: 'No (same account does everything)',
        points: 0,
        triggersOnSelect: ['admin_separation'],
        riskBoost: 2,
      },
      {
        value: 'partial',
        label: 'Some separation (inconsistent)',
        points: 6,
        triggersOnSelect: ['admin_separation'],
        riskBoost: 1,
      },
      {
        value: 'yes',
        label: 'Yes (dedicated admin + stronger controls)',
        points: 10,
      },
    ],
  },
  {
    id: 'ida_offboarding',
    sectionId: 'identity_access',
    appliesTo: ['small-org'],
    type: 'radio',
    prompt: 'Do you have a repeatable offboarding process?',
    helpText:
      'Remove access promptly, rotate shared secrets, disable accounts, remove shared links.',
    options: [
      {
        value: 'none',
        label: 'No process/ad hoc',
        points: 0,
        triggersOnSelect: ['offboarding_process'],
        riskBoost: 2,
      },
      {
        value: 'some',
        label: 'Some checklist, not always followed',
        points: 6,
        triggersOnSelect: ['offboarding_process'],
        riskBoost: 1,
      },
      { value: 'yes', label: 'Yes, documented and followed', points: 10 },
    ],
  },

  // Devices & Endpoints
  {
    id: 'dev_updates',
    sectionId: 'devices_endpoints',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Update posture for OS and key apps is…',
    options: [
      {
        value: 'manual_rare',
        label: 'Mostly manual/often delayed',
        points: 0,
        triggersOnSelect: ['standardize_updates'],
        riskBoost: 2,
      },
      {
        value: 'mixed',
        label: 'Mixed (some auto updates)',
        points: 6,
        triggersOnSelect: ['standardize_updates'],
        riskBoost: 1,
      },
      { value: 'auto', label: 'Automatic + consistent', points: 10 },
    ],
  },
  {
    id: 'dev_encryption',
    sectionId: 'devices_endpoints',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Are laptops and mobile devices encrypted?',
    options: [
      {
        value: 'no',
        label: 'No/not sure',
        points: 0,
        triggersOnSelect: ['endpoint_encryption'],
        riskBoost: 2,
      },
      {
        value: 'some',
        label: 'Some devices',
        points: 6,
        triggersOnSelect: ['endpoint_encryption'],
        riskBoost: 1,
      },
      {
        value: 'yes',
        label: 'Yes (and recovery keys handled safely)',
        points: 10,
      },
    ],
  },
  {
    id: 'dev_protection',
    sectionId: 'devices_endpoints',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Malware protection/endpoint security is…',
    options: [
      {
        value: 'unknown',
        label: 'Not sure/inconsistent',
        points: 0,
        triggersOnSelect: ['endpoint_malware_protection'],
        riskBoost: 1,
      },
      {
        value: 'baseline',
        label: 'Baseline (built-in protection enabled)',
        points: 7,
      },
      { value: 'managed', label: 'Strong baseline + managed settings', points: 10 },
    ],
  },
  {
    id: 'dev_inventory',
    sectionId: 'devices_endpoints',
    appliesTo: ['small-org'],
    type: 'radio',
    prompt: 'Do you maintain a device inventory (and policies)?',
    options: [
      {
        value: 'no',
        label: 'No',
        points: 0,
        triggersOnSelect: ['mdm_or_inventory'],
        riskBoost: 1,
      },
      {
        value: 'basic',
        label: 'Basic list/informal',
        points: 6,
        triggersOnSelect: ['mdm_or_inventory'],
      },
      { value: 'yes', label: 'Yes (inventory + enforcement where possible)', points: 10 },
    ],
  },

  // Data & Backups
  {
    id: 'data_backups',
    sectionId: 'data_backups',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Backups today are…',
    helpText: 'Consider both devices and cloud storage, include restore testing.',
    options: [
      {
        value: 'none',
        label: 'No real backups/unsure',
        points: 0,
        triggersOnSelect: ['tested_backups_3_2_1', 'protect_backups_from_ransomware'],
        riskBoost: 2,
      },
      {
        value: 'some',
        label: 'Some backups, not tested',
        points: 5,
        triggersOnSelect: ['tested_backups_3_2_1'],
        riskBoost: 1,
      },
      { value: 'good', label: '3-2-1-ish and tested occasionally', points: 10 },
    ],
  },
  {
    id: 'data_backup_protection',
    sectionId: 'data_backups',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Backup protection against deletion/encryption is…',
    options: [
      {
        value: 'weak',
        label: 'Weak (same credentials, easy to delete)',
        points: 0,
        triggersOnSelect: ['protect_backups_from_ransomware'],
        riskBoost: 2,
      },
      {
        value: 'some',
        label: 'Some protection (versioning or separate credentials)',
        points: 6,
        triggersOnSelect: ['protect_backups_from_ransomware'],
        riskBoost: 1,
      },
      {
        value: 'strong',
        label: 'Strong (restricted deletion, versioning/immutability, MFA)',
        points: 10,
      },
    ],
  },
  {
    id: 'data_sensitivity',
    sectionId: 'data_backups',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Do you know where sensitive data lives and how long you keep it?',
    options: [
      {
        value: 'no',
        label: 'Not really',
        points: 0,
        triggersOnSelect: ['data_classification_light'],
        riskBoost: 1,
      },
      {
        value: 'some',
        label: 'Some awareness, inconsistent',
        points: 6,
        triggersOnSelect: ['data_classification_light'],
      },
      {
        value: 'yes',
        label: 'Yes and we reduce unnecessary retention',
        points: 10,
      },
    ],
  },

  // Network & Cloud
  {
    id: 'net_wifi',
    sectionId: 'network_cloud',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Wi-Fi/router hygiene is…',
    options: [
      {
        value: 'unknown',
        label: 'Unknown/default-ish',
        points: 0,
        triggersOnSelect: ['secure_wifi_router'],
        riskBoost: 1,
      },
      {
        value: 'basic',
        label: 'Basic (WPA2/3, updated sometimes)',
        points: 6,
        triggersOnSelect: ['secure_wifi_router'],
      },
      {
        value: 'strong',
        label: 'Strong (firmware updates, no WPS, segmented)',
        points: 10,
      },
    ],
  },
  {
    id: 'cloud_sharing',
    sectionId: 'network_cloud',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Cloud/SaaS sharing and permissions are…',
    options: [
      {
        value: 'wild',
        label: 'Often shared broadly/public links exist',
        points: 0,
        triggersOnSelect: ['review_cloud_sharing'],
        riskBoost: 2,
      },
      {
        value: 'mixed',
        label: 'Mostly controlled, some drift',
        points: 6,
        triggersOnSelect: ['review_cloud_sharing'],
        riskBoost: 1,
      },
      {
        value: 'tight',
        label: 'Least privilege, reviewed regularly',
        points: 10,
      },
    ],
  },
  {
    id: 'cloud_admin_console',
    sectionId: 'network_cloud',
    appliesTo: ['small-org', 'freelancer'],
    type: 'radio',
    prompt: 'Admin console hardening (MFA, alerts, privileged roles) is…',
    options: [
      {
        value: 'weak',
        label: 'Weak/inconsistent',
        points: 0,
        triggersOnSelect: ['lock_down_admin_console'],
        riskBoost: 2,
      },
      {
        value: 'some',
        label: 'Some hardening, not complete',
        points: 6,
        triggersOnSelect: ['lock_down_admin_console'],
        riskBoost: 1,
      },
      { value: 'strong', label: 'Strong and reviewed', points: 10 },
    ],
  },

  // Monitoring & Response
  {
    id: 'mon_alerts',
    sectionId: 'monitoring_response',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'Security alerts for key services are…',
    helpText:
      'New login alerts, suspicious access, forwarding rule changes, MFA changes, admin changes.',
    options: [
      {
        value: 'off',
        label: 'Mostly off/not configured',
        points: 0,
        triggersOnSelect: ['enable_security_alerts'],
        riskBoost: 2,
      },
      {
        value: 'some',
        label: 'Some alerts enabled',
        points: 6,
        triggersOnSelect: ['enable_security_alerts'],
        riskBoost: 1,
      },
      { value: 'good', label: 'Enabled and routed reliably', points: 10 },
    ],
  },
  {
    id: 'mon_ir_plan',
    sectionId: 'monitoring_response',
    appliesTo: ['personal', 'freelancer', 'small-org'],
    type: 'radio',
    prompt: 'If something goes wrong (phish, malware, takeover), you have…',
    options: [
      {
        value: 'no_plan',
        label: 'No plan',
        points: 0,
        triggersOnSelect: ['basic_ir_plan'],
        riskBoost: 1,
      },
      {
        value: 'rough',
        label: 'A rough idea, not written',
        points: 6,
        triggersOnSelect: ['basic_ir_plan'],
      },
      {
        value: 'written',
        label: 'A written mini plan and contact list',
        points: 10,
      },
    ],
  },
  {
    id: 'mon_logs',
    sectionId: 'monitoring_response',
    appliesTo: ['small-org', 'freelancer'],
    type: 'radio',
    prompt: 'Do you retain basic audit logs for critical systems?',
    options: [
      {
        value: 'no',
        label: 'No/rarely',
        points: 0,
        triggersOnSelect: ['log_centralization_light'],
        riskBoost: 1,
      },
      {
        value: 'some',
        label: 'Some logs, inconsistent',
        points: 6,
        triggersOnSelect: ['log_centralization_light'],
      },
      {
        value: 'yes',
        label: 'Yes (identity/email/admin logs protected)',
        points: 10,
      },
    ],
  },
]
