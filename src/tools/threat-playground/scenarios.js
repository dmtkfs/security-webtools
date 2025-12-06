export const SCENARIOS = [
  // ---------------------------------------------------------------------------
  // 1) Phishing → Endpoint compromise (Beginner)
  // ---------------------------------------------------------------------------
  {
    id: 'phishing-endpoint-compromise',
    title: 'Phishing Email → Endpoint Compromise',
    difficulty: 'beginner',
    tags: ['email', 'endpoint', 'EDR'],
    summary:
      'A user receives a phishing email with a malicious attachment that leads to script execution and an EDR alert.',
    objective:
      'Follow how a single phishing email can lead to code execution on an endpoint and how it appears in logs.',
    defenderFocus:
      'Email security, endpoint telemetry (Sysmon/EDR) and early containment steps.',
    overallMitreTechniques: [
      { id: 'T1566', name: 'Phishing' },
      { id: 'T1204', name: 'User Execution' },
      { id: 'T1059', name: 'Command and Scripting Interpreter' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'Suspicious Email Delivered',
        description:
          'A user receives an unexpected email claiming to be an invoice, with a macro-enabled Office attachment. The sender domain looks similar to a known vendor, but with a small typo.',
        sampleLogs: (vars = {}) => {
          const msgId = vars.emailMsgId || 'ab12cd34';
          const to = vars.emailRecipient || 'user@org.local';
          return [
            `[Email Gateway] 2025-03-10T09:12:33Z MSGID=${msgId} From="billing@vend0r-example.com" To="${to}" Subject="Invoice March 2025" Attachments="Invoice_March2025.docm" SPF=pass DKIM=pass DMARC=pass`,
            `[Email Gateway] 2025-03-10T09:12:34Z MSGID=${msgId} PolicyAction=Allow Rule="Default Inbound Policy"`,
          ];
        },
        mitreTechniques: [{ id: 'T1566', name: 'Phishing (Attachment)' }],
        defenderPerspective:
          'From the defender’s view, this email may look normal: SPF/DKIM/DMARC pass and the subject appears business related. The main clue is the slightly off sender domain and unexpected macro-enabled attachment.',
        defenderActions: [
          'Encourage users to report unexpected invoices and attachments.',
          'Enable attachment sandboxing and stricter policies for macro-enabled files.',
          'Add detections for lookalike domains targeting your organization.',
        ],
        keySignals: [
          'Lookalike (typo-squatted) sender domain.',
          'Macro-enabled document sent to finance or generic mailboxes.',
        ],
      },
      {
        id: 'step-2',
        title: 'User Opens Attachment & Macro Executes',
        description:
          'The user opens the attachment and enables macros. The document spawns a scripting engine that reaches out to an external host.',
        sampleLogs: (vars = {}) => {
          const srcIp = vars.proxySrcIp || '10.0.5.23';
          const dstIp = vars.proxyDstIp || '203.0.113.50';
          const userSam = vars.userSam || 'USER01';
          return [
            `[Windows Security] 2025-03-10T09:14:55Z EventID=4688 NewProcessName="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" ParentProcessName="C:\\Windows\\explorer.exe" SubjectUserName="${userSam}"`,
            `[Sysmon] 2025-03-10T09:15:02Z EventID=1 ProcessCreate ParentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell.exe -nop -w hidden -EncodedCommand ..." User="${userSam}"`,
            `[Proxy] 2025-03-10T09:15:05Z SRC_IP=${srcIp} DST_IP=${dstIp} DST_PORT=443 URL="https://updates-example[.]com/bootstrap.bin" ACTION=Allow`,
          ];
        },
        mitreTechniques: [
          { id: 'T1204', name: 'User Execution' },
          { id: 'T1059', name: 'Command and Scripting Interpreter' },
        ],
        defenderPerspective:
          'The key pivot is Office spawning PowerShell with suspicious flags, followed by outbound HTTPS to an unknown domain. These signals are much stronger than the initial email alone.',
        defenderActions: [
          'Alert when `Office` applications spawn scripting interpreters (`powershell.exe`, `cmd.exe`, `wscript.exe`).',
          'Use EDR to restrict or prompt when high-risk command-line arguments are observed.',
          'Block outbound connections to newly registered or low-reputation domains where possible.',
        ],
        keySignals: [
          '`WINWORD.exe` → `powershell.exe` process chain.',
          'PowerShell launched with `-nop` / `-w hidden` / encoded command.',
          'Outbound HTTPS to an unfamiliar domain immediately after macro execution.',
        ],
      },
      {
        id: 'step-3',
        title: 'EDR Alert & Containment',
        description:
          'The EDR identifies the behavior as suspicious and raises an alert. The SOC analyst investigates and isolates the host.',
        sampleLogs: (vars = {}) => {
          const userSam = vars.userSam || 'USER01';
          const hostName = vars.hostName || 'WKS-USER01';
          return [
            `[EDR Alert] 2025-03-10T09:15:10Z AlertID=56789 HostName="${hostName}" User="${userSam}" Severity=High Detection="Office spawning PowerShell with obfuscated command" Status=New`,
            `[EDR Action] 2025-03-10T09:17:25Z AlertID=56789 HostName="${hostName}" Action="NetworkIsolation" Result=Success`,
          ];
        },
        mitreTechniques: [
          { id: 'T1105', name: 'Ingress Tool Transfer (attempted)' },
        ],
        defenderPerspective:
          'At this point the attack has been partially executed, but EDR has enough context to flag suspicious behavior. Quick containment can prevent persistence or credential theft.',
        defenderActions: [
          'Isolate the endpoint from the network and collect volatile artifacts.',
          'Reset user credentials and invalidate active sessions.',
          'Search for similar process chains across the environment (threat hunting).',
          'Update detection content and user awareness materials with this incident.',
        ],
        keySignals: [
          'High-severity EDR alert tied to macro and PowerShell behavior.',
          'Same pattern across multiple endpoints (campaign vs one-off).',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 2) Web App SQL Injection → Data Access (Intermediate)
  // ---------------------------------------------------------------------------
  {
    id: 'web-sqli-data-access',
    title: 'Web App SQL Injection → Data Access',
    difficulty: 'intermediate',
    tags: ['web', 'database', 'WAF'],
    summary:
      'An internet-facing login endpoint is probed with SQL injection payloads, leading to suspicious database queries.',
    objective:
      'See how application, WAF and database logs fit together in a SQL injection scenario.',
    defenderFocus:
      'Web logs, WAF telemetry and database audit logs to detect and respond to injection attempts.',
    overallMitreTechniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application' },
      { id: 'T1059', name: 'Command and Scripting Interpreter (SQL)' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'Probing the Login Endpoint',
        description:
          'The attacker sends crafted HTTP requests to a `/login` endpoint, experimenting with SQL injection payloads in the `username` parameter.',
        sampleLogs: (vars = {}) => {
          const ip = vars.webClientIp || '10.0.10.15';
          const req1 = vars.webReqId1 || 'web-01-abc';
          const req2 = vars.webReqId2 || 'web-01-def';
          return [
            `${ip} - - [2025-04-02T18:21:11Z] "POST /login HTTP/1.1" 200 512 "-" "curl/8.4.0" req_id=${req1} user="-", params="username=admin&password=Password123!"`,
            `${ip} - - [2025-04-02T18:21:27Z] "POST /login HTTP/1.1" 500 1024 "-" "curl/8.4.0" req_id=${req2} user="-", params="username=admin' OR 1=1--&password=anything"`,
            `[WAF] 2025-04-02T18:21:27Z action=LOG rule="SQLi-Generic-001" request_id=${req2} matched_pattern="(\\bor\\b\\s+1=1)" severity=Medium`,
          ];
        },
        mitreTechniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
        defenderPerspective:
          'Spikes of `500` errors and odd user agents like `curl` hitting authentication endpoints are common signals. The WAF is logging, but currently only in detection/monitoring mode.',
        defenderActions: [
          'Monitor error rates (`4xx`/`5xx`) and unusual user agents for sensitive endpoints.',
          'Tune WAF rules to block clearly malicious SQL patterns, not just log them.',
          'Add rate limits to authentication and critical business endpoints.',
        ],
        keySignals: [
          'Login requests with SQL operators in parameters (`OR 1=1`, `UNION SELECT`, etc.).',
          'Same IP repeatedly triggering WAF SQLi rules in a short timeframe.',
        ],
      },
      {
        id: 'step-2',
        title: 'Suspicious Database Queries',
        description:
          'One of the crafted payloads reaches the database. The application constructs a query unsafely and the DB logs unusual patterns.',
        sampleLogs: [
          '[DB Audit] 2025-04-02T18:21:27Z user="app_web" db="prod_app" statement="SELECT * FROM users WHERE username = \'admin\' OR 1=1--\' AND password = \'********\'" duration_ms=12 rows=250',
          '[DB Audit] 2025-04-02T18:21:27Z user="app_web" db="prod_app" statement="SELECT id, email, password_hash FROM users" duration_ms=34 rows=250',
        ],
        mitreTechniques: [
          { id: 'T1059', name: 'Command and Scripting Interpreter (SQL)' },
        ],
        defenderPerspective:
          'The DB sees queries that are more like bulk data access than a typical login flow. Even if results are partially blocked by the app, the pattern is suspicious.',
        defenderActions: [
          'Add database auditing for sensitive tables (`users`, credentials, payments).',
          'Build detections for queries that return unusually large result sets for authentication paths.',
          'Work with developers to replace string-concatenated SQL with parameterized queries.',
        ],
        keySignals: [
          'Auth-related queries returning entire user tables.',
          'Queries containing comment markers (`--`) or always-true predicates (`1=1`).',
        ],
      },
      {
        id: 'step-3',
        title: 'Containment & Hardening',
        description:
          'The security team correlates WAF alerts, web logs and DB audit logs, confirming attempted SQL injection. They deploy fixes and monitor for recurrence.',
        sampleLogs: (vars = {}) => {
            const req3 = vars.webReqId3 || 'web-01-ghi';
            return [
            '[Security Platform] 2025-04-02T18:25:10Z IncidentID=INC-2025-0042 Category="Web Application" Summary="Repeated SQL injection attempts against /login" Status=Open',
            `[WAF] 2025-04-02T18:27:05Z action=BLOCK rule="SQLi-Generic-001" request_id=${req3} matched_pattern="UNION SELECT" severity=High`,
            ];
        },
        mitreTechniques: [
          { id: 'T1190', name: 'Exploit Public-Facing Application (blocked)' },
        ],
        defenderPerspective:
          'This is a classic scenario where multiple log sources tell the full story. Effective hardening reduces the impact of future attempts.',
        defenderActions: [
          'Deploy code fix (parameterized queries / ORM) and re-test critical flows.',
          'Turn WAF SQL injection rules to blocking mode after validation.',
          'Add synthetic monitoring to detect broken login functionality after changes.',
          'Review other endpoints for similar vulnerable patterns.',
        ],
        keySignals: [
          'Post-fix WAF logs show continued attempts being blocked.',
          'No further spikes in DB queries returning full user tables.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 3) Exposed Cloud Storage Bucket → Data Exfiltration (Intermediate)
  // ---------------------------------------------------------------------------
  {
    id: 'public-cloud-bucket-exfil',
    title: 'Exposed Cloud Storage Bucket → Data Exfiltration',
    difficulty: 'intermediate',
    tags: ['cloud', 'storage', 'exfiltration'],
    summary:
      'A misconfigured public storage bucket allows unauthenticated listing and download of sensitive files.',
    objective:
      'Understand how access logs and configuration changes can reveal storage misconfigurations and data access.',
    defenderFocus:
      'Cloud access logs, permission reviews and remediation of public storage exposure.',
    overallMitreTechniques: [
      { id: 'T1526', name: 'Cloud Service Discovery' },
      { id: 'T1530', name: 'Data from Cloud Storage Object' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'Bucket Discovery & Listing',
        description:
          'An attacker discovers a publicly exposed bucket name through OSINT and attempts to list its contents without authentication.',
        sampleLogs: (vars = {}) => {
          const bucket = vars.bucketName || 'corp-backups';
          const ip = vars.anonIp || '198.51.100.25';
          return [
            `[Cloud Access Log] 2025-05-12T11:03:02Z bucket="${bucket}" requester="anonymous" operation="ListBucket" responseCode=200 bytesSent=1024 userAgent="aws-sdk-go/1.50 (unknown)" clientIp="${ip}"`,
            `[Cloud Access Log] 2025-05-12T11:03:04Z bucket="${bucket}" requester="anonymous" operation="ListBucket" keyPrefix="prod/db/" responseCode=200 clientIp="${ip}"`,
          ];
        },
        mitreTechniques: [{ id: 'T1526', name: 'Cloud Service Discovery' }],
        defenderPerspective:
          'Anonymous `ListBucket` operations are an immediate red flag for sensitive buckets. Even if no data has been downloaded yet, the misconfiguration is exposed.',
        defenderActions: [
          'Alert on `anonymous` or unexpected principals performing `ListBucket` on non-public buckets.',
          'Review bucket policies and block public access at the account/organization level.',
          'Inventory all storage buckets and classify them by sensitivity.',
        ],
        keySignals: [
          'Requester=`anonymous` or public IP principals accessing internal-sounding buckets.',
          '`ListBucket` operations targeting backup or database prefixes.',
        ],
      },
      {
        id: 'step-2',
        title: 'Object Downloads from Anonymous User',
        description:
          'After confirming that the bucket is open, the attacker downloads multiple objects containing sensitive data.',
        sampleLogs: (vars = {}) => {
          const bucket = vars.bucketName || 'corp-backups';
          const ip = vars.anonIp || '198.51.100.25';
          return [
            `[Cloud Access Log] 2025-05-12T11:05:12Z bucket="${bucket}" requester="anonymous" operation="GetObject" key="prod/db/users-2025-05-01.sql.gz" responseCode=200 bytesSent=4512392 clientIp="${ip}"`,
            `[Cloud Access Log] 2025-05-12T11:05:33Z bucket="${bucket}" requester="anonymous" operation="GetObject" key="prod/db/payments-2025-05-01.sql.gz" responseCode=200 bytesSent=7392011 clientIp="${ip}"`,
          ];
        },
        mitreTechniques: [{ id: 'T1530', name: 'Data from Cloud Storage Object' }],
        defenderPerspective:
          'This is active data exfiltration. The volume and nature of accessed keys (DB backups, exports) should trigger a high-severity alert.',
        defenderActions: [
          'Immediately block public access and rotate any credentials that may be contained in backups.',
          'Notify internal stakeholders about potential data exposure and begin incident response procedures.',
          'Establish rules to alert on anonymous access to sensitive prefixes (`prod/db`, `backups`, `exports`).',
        ],
        keySignals: [
          'Anonymous access to database backup files or exports.',
          'Large volumes of data sent to previously unseen IPs within a short window.',
        ],
      },
      {
        id: 'step-3',
        title: 'Remediation & Future Prevention',
        description:
          'The security and cloud teams remediate the misconfiguration, implement guardrails and validate that similar issues do not exist elsewhere.',
        sampleLogs: (vars = {}) => {
          const bucket = vars.bucketName || 'corp-backups';
          return [
            `[Cloud Config] 2025-05-12T11:20:00Z ChangeType="PutBucketPublicAccessBlock" bucket="${bucket}" BlockPublicAcls=true BlockPublicPolicy=true RestrictPublicBuckets=true`,
            '[Cloud Config] 2025-05-12T11:25:45Z ChangeType="AttachServiceControlPolicy" policy="DenyPublicBuckets" target="ProdAccount"',
          ];
        },
        mitreTechniques: [
          { id: 'T1530', name: 'Data from Cloud Storage Object (prevented)' },
        ],
        defenderPerspective:
          'Remediation should include both this bucket and broader guardrails so the same pattern cannot reoccur unnoticed.',
        defenderActions: [
          'Enable organization-wide controls that deny or strongly limit public storage buckets.',
          'Continuously scan for publicly exposed buckets and alert owners.',
          'Update data classification and backup processes to reduce stored sensitive data volume.',
        ],
        keySignals: [
          'No new anonymous access attempts are successful after guardrails are applied.',
          'Configuration baselines prevent reintroducing the same misconfiguration.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 4) Suspicious VPN Login → Impossible Travel (Beginner)
  // ---------------------------------------------------------------------------
  {
    id: 'vpn-impossible-travel',
    title: 'Suspicious VPN Login → Impossible Travel',
    difficulty: 'beginner',
    tags: ['identity', 'vpn', 'geoip'],
    summary:
      'A user logs in to VPN from an unusual country, followed shortly by a login from their normal location, triggering impossible-travel alerts.',
    objective:
      'Understand how IdP, VPN and geoIP signals combine to flag risky sign-ins.',
    defenderFocus:
      'Identity provider logs, VPN concentrator logs and geoIP-based correlation.',
    overallMitreTechniques: [{ id: 'T1078', name: 'Valid Accounts' }],
    steps: [
      {
        id: 'step-1',
        title: 'First Login from Unusual Country',
        description:
          'A VPN sign-in succeeds from a country the user has never connected from before, using a familiar device type.',
        sampleLogs: (vars = {}) => {
          const user = vars.userName || 'alice';
          const idpIp = vars.idpIp1 || '203.0.113.25';
          const vpnIp = vars.vpnAssignedIp || '10.20.5.14';
          return [
            `[IdP] 2025-06-15T07:12:03Z user="${user}" result=success ip="${idpIp}" location="Warsaw, PL" device="Windows 10" mfaResult=passed riskLevel=medium`,
            `[VPN] 2025-06-15T07:12:08Z username="${user}" public_ip="${idpIp}" assigned_ip="${vpnIp}" tunnel="ipsec" action=allow`,
          ];
        },
        mitreTechniques: [{ id: 'T1078', name: 'Valid Accounts' }],
        defenderPerspective:
          'On its own, this might look like travel. GeoIP and `first-time` signals make it suspicious but not conclusive.',
        defenderActions: [
          'Alert on first-time sign-ins from new countries for privileged users.',
          'Require step-up MFA for high-risk locations or anonymous VPN providers.',
        ],
        keySignals: [
          'Successful sign-in from a new country with `riskLevel=medium` or higher.',
          'VPN session immediately following the IdP sign-in from the same IP.',
        ],
      },
      {
        id: 'step-2',
        title: 'Second Login from Home Country Minutes Later',
        description:
          'Shortly after the first login, the same account signs in from their usual country, making the travel time impossible.',
        sampleLogs: (vars = {}) => {
          const user = vars.userName || 'alice';
          const idpIp = vars.idpIp2 || '198.51.100.44';
          return [
            `[IdP] 2025-06-15T07:30:41Z user="${user}" result=success ip="${idpIp}" location="Montreal, CA" device="Windows 10" mfaResult=passed riskLevel=low`,
            `[ImpossTravel] 2025-06-15T07:30:45Z user="${user}" fromLocation="Warsaw, PL" toLocation="Montreal, CA" minutesBetween=18 distanceKm=6400 flagged=true`,
          ];
        },
        mitreTechniques: [{ id: 'T1078', name: 'Valid Accounts' }],
        defenderPerspective:
          'Improbable travel between `PL` and `CA` within minutes is a strong indicator of account compromise.',
        defenderActions: [
          'Automatically flag the account for review and require password reset.',
          'Check whether both sessions are still active and terminate them.',
          'Correlate with VPN logs to see which internal resources were accessed.',
        ],
        keySignals: [
          'Two successful sign-ins with distant geoIP locations within a short time window.',
          'Imposs-travel engine or UEBA model raising a `flagged=true` event.',
        ],
      },
      {
        id: 'step-3',
        title: 'Containment & Hardening',
        description:
          'The SOC treats the event as potential credential theft, containing access and strengthening protections.',
        sampleLogs: (vars = {}) => {
          const user = vars.userName || 'alice';
          return [
            `[SecurityPlatform] 2025-06-15T07:35:00Z IncidentID=INC-2025-0615 Category="Identity" Summary="Impossible travel for user ${user}" Severity=High Status=Open`,
            `[IdP] 2025-06-15T07:38:20Z user="${user}" action="forcePasswordReset" actor="SecurityTeam"`,
          ];
        },
        mitreTechniques: [{ id: 'T1078', name: 'Valid Accounts (contained)' }],
        defenderPerspective:
          'Even if no further activity is observed, treating impossible travel seriously can prevent lateral movement.',
        defenderActions: [
          'Reset credentials, revoke refresh tokens and invalidate active sessions.',
          'Review sign-in logs around the same time window for similar patterns.',
          'Educate users about reusing passwords across personal and corporate services.',
        ],
        keySignals: [
          'Identity incident opened around impossible-travel events.',
          'Forced password reset and token revocation for the affected account.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 5) OAuth Consent Phish → Mailbox Access (Intermediate)
  // ---------------------------------------------------------------------------
  {
    id: 'oauth-mailbox-abuse',
    title: 'OAuth Consent Phish → Mailbox Access',
    difficulty: 'intermediate',
    tags: ['oauth', 'email', 'cloud'],
    summary:
      'A user grants consent to a malicious OAuth app that gains read access to their mailbox without stealing the password.',
    objective:
      'See how audit logs and OAuth events can reveal malicious app consent and mailbox access.',
    defenderFocus:
      'Cloud IdP audit logs, OAuth consent events and mailbox access logs.',
    overallMitreTechniques: [
      { id: 'T1550', name: 'Use of Application Access Tokens' },
      { id: 'T1114', name: 'Email Collection' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'User Grants Consent to Malicious App',
        description:
          'The user clicks a link in an email and is prompted to grant consent to a third-party app with broad mailbox permissions.',
        sampleLogs: (vars = {}) => {
          const user = vars.userName || 'bob';
          const appId =
            vars.appId || '00000000-1111-2222-3333-444444444444';
          return [
            `[CloudAudit] 2025-07-02T14:03:12Z user="${user}" action="ConsentToApp" appName="MailSync Pro" appId="${appId}" permissions="Mail.Read, Mail.ReadWrite" consentType="User"`,
            `[IdP] 2025-07-02T14:03:15Z user="${user}" ip="203.0.113.99" location="London, GB" app="MailSync Pro" result=success`,
          ];
        },
        mitreTechniques: [
          { id: 'T1550', name: 'Use of Application Access Tokens' },
        ],
        defenderPerspective:
          'Nothing here looks like a classic login failure. The dangerous part is the combination of new app consent and high-privilege scopes like `Mail.ReadWrite`.',
        defenderActions: [
          'Alert when new multi-tenant apps request high-privilege scopes such as `Mail.Read` or `Mail.ReadWrite`.',
          'Restrict user consent to a curated list of approved apps.',
        ],
        keySignals: [
          'New OAuth app with broad mailbox permissions and `consentType="User"`.',
          'App name or publisher that does not match your organization’s expected vendors.',
        ],
      },
      {
        id: 'step-2',
        title: 'Background Mailbox Access via App Token',
        description:
          'The OAuth app starts using its access token to read the mailbox in the background without interactive sign-ins.',
        sampleLogs: (vars = {}) => {
          const user = vars.userName || 'bob';
          return [
            `[ExchangeAudit] 2025-07-02T14:05:32Z user="${user}" clientApp="MailSync Pro" operation="MailItemsAccessed" accessType="AppToken" ip="198.51.100.77" status=success`,
            `[ExchangeAudit] 2025-07-02T14:05:40Z user="${user}" clientApp="MailSync Pro" operation="SearchFolder" accessType="AppToken" query="folder:Inbox AND (subject:Invoice OR subject:Payment)"`,
          ];
        },
        mitreTechniques: [{ id: 'T1114', name: 'Email Collection' }],
        defenderPerspective:
          'Mailbox activity appears under a trusted app name. The key signal is the `accessType="AppToken"` and unusual search patterns driven by the attacker.',
        defenderActions: [
          'Detect mailbox operations using `AppToken` from newly consented apps.',
          'Profile normal OAuth app behaviour and alert on spikes or unusual search queries.',
        ],
        keySignals: [
          'Mailbox access operations where `clientApp` is new and `accessType="AppToken"`.',
          'Search queries that look like hunting for invoices, payments or password resets.',
        ],
      },
      {
        id: 'step-3',
        title: 'Consent Revocation & App Block',
        description:
          'The security team identifies the malicious app, revokes consent and blocks the app tenant-wide.',
        sampleLogs: (vars = {}) => {
          const appId =
            vars.appId || '00000000-1111-2222-3333-444444444444';
          return [
            `[CloudAudit] 2025-07-02T15:10:05Z actor="SecurityAdmin" action="RevokeAppConsent" appId="${appId}" targetUsers="bob"`,
            `[CloudAudit] 2025-07-02T15:11:20Z actor="SecurityAdmin" action="BlockApp" appId="${appId}" scope="Tenant"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1550', name: 'Use of Application Access Tokens (blocked)' },
        ],
        defenderPerspective:
          'Revoking consent stops further background access, but you still need to assess what data was accessed and whether similar apps exist.',
        defenderActions: [
          'Revoke consent for the malicious app and block it at the tenant level.',
          'Review mailbox audit logs to understand the scope of access.',
          'Hunt for other users who granted consent to the same or similar apps.',
        ],
        keySignals: [
          'Administrative actions revoking consent and blocking the offending app.',
          'No further `AppToken` access for that app after the block.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 6) Lateral Movement via RDP & Credential Dumping (Advanced)
  // ---------------------------------------------------------------------------
  {
    id: 'lateral-rdp-credential-dump',
    title: 'Lateral Movement via RDP & Credential Dumping',
    difficulty: 'advanced',
    tags: ['windows', 'lateral movement', 'credential access'],
    summary:
      'An attacker uses stolen credentials to RDP into a server, runs credential-dumping tools and attempts lateral movement.',
    objective:
      'Trace how Windows logs, Sysmon and EDR alerts expose lateral movement and credential access.',
    defenderFocus:
      'Windows security logs, Sysmon process/file events and EDR detections.',
    overallMitreTechniques: [
      { id: 'T1021', name: 'Remote Services (RDP)' },
      { id: 'T1003', name: 'OS Credential Dumping' },
      { id: 'T1075', name: 'Pass the Hash' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'RDP Login to File Server',
        description:
          'A domain admin account initiates an RDP session to a file server from a workstation it rarely uses.',
        sampleLogs: (vars = {}) => {
          const srcIp = vars.rdpSrcIp || '10.0.30.55';
          const workstation = vars.rdpWorkstation || 'WKS-OPS01';
          const fileServer = vars.rdpFileServer || 'FSRV-01';
          return [
            `[Windows Security] 2025-08-10T21:12:02Z EventID=4624 LogonType=10 TargetUserName="DOMAIN\\\\svc-admin" SourceIpAddress="${srcIp}" WorkstationName="${workstation}" TargetServer="${fileServer}"`,
            `[Windows Security] 2025-08-10T21:12:05Z EventID=4776 UserName="DOMAIN\\\\svc-admin" Workstation="${fileServer}" Status=0x0`,
          ];
        },
        mitreTechniques: [{ id: 'T1021', name: 'Remote Services (RDP)' }],
        defenderPerspective:
          'RDP by domain admins is expected for some servers, but unusual source hosts or times can be strong signals.',
        defenderActions: [
          'Baseline which admin accounts are allowed to RDP into which servers.',
          'Alert on new admin-to-server RDP pairs or unusual access times.',
        ],
        keySignals: [
          '`LogonType=10` (RDP) for high-privilege accounts to sensitive servers.',
          'Source workstation that is not normally associated with that admin.',
        ],
      },
      {
        id: 'step-2',
        title: 'Credential Dump Attempt on LSASS',
        description:
          'Shortly after the RDP session starts, a tool attempts to dump `lsass.exe` memory to disk.',
        sampleLogs: (vars = {}) => {
          const fileServer = vars.rdpFileServer || 'FSRV-01';
          return [
            `[Sysmon] 2025-08-10T21:13:11Z EventID=1 ProcessCreate Image="C:\\\\Tools\\\\procdump.exe" CommandLine="procdump.exe -accepteula -ma lsass.exe C:\\\\temp\\\\lsass.dmp" User="DOMAIN\\\\svc-admin" ComputerName="${fileServer}"`,
            `[Sysmon] 2025-08-10T21:13:13Z EventID=10 ProcessAccess SourceImage="C:\\\\Tools\\\\procdump.exe" TargetImage="C:\\\\Windows\\\\System32\\\\lsass.exe" GrantedAccess="0x1FFFFF" ComputerName="${fileServer}"`,
          ];
        },
        mitreTechniques: [{ id: 'T1003', name: 'OS Credential Dumping' }],
        defenderPerspective:
          'Tools accessing `lsass.exe` with full read permission are a classic credential-dumping signal.',
        defenderActions: [
          'Alert when non-AV/EDR processes access `lsass.exe` with high privileges.',
          'Block or restrict known credential-dumping tools such as `procdump.exe` on servers.',
        ],
        keySignals: [
          'Process creation of tools such as `procdump.exe`, `mimikatz.exe` or renamed variants.',
          'Process access events where the target image is `lsass.exe` with high access rights.',
        ],
      },
      {
        id: 'step-3',
        title: 'EDR Alert & Lateral Movement Attempt',
        description:
          'The attacker uses harvested material to attempt further lateral movement, while EDR raises an alert.',
        sampleLogs: (vars = {}) => {
          const fileServer = vars.rdpFileServer || 'FSRV-01';
          const appServer = vars.rdpAppServer || 'APP-01';
          return [
            `[EDR Alert] 2025-08-10T21:14:01Z HostName="${fileServer}" User="DOMAIN\\\\svc-admin" Detection="Credential dumping tool accessing lsass.exe" Severity=Critical`,
            `[Windows Security] 2025-08-10T21:15:20Z EventID=4624 LogonType=3 TargetUserName="DOMAIN\\\\svc-admin" IpAddress="10.0.40.20" WorkstationName="${fileServer}" TargetServer="${appServer}"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1075', name: 'Pass the Hash' },
          { id: 'T1021', name: 'Remote Services (SMB)' },
        ],
        defenderPerspective:
          'Even if the credential dump is blocked, follow-on lateral movement attempts reveal where the attacker was headed.',
        defenderActions: [
          'Isolate the affected servers and reset credentials for the involved admin accounts.',
          'Review other servers for similar `lsass` access patterns and RDP activity.',
          'Tighten RDP and SMB access controls for sensitive tiers.',
        ],
        keySignals: [
          'EDR alert tied to `lsass.exe` access followed by new network logons from that host.',
          'RDP or SMB logons originating from the compromised server to additional high-value servers.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 7) Compromised AWS Access Key → Programmatic Abuse (Intermediate/Advanced)
  // ---------------------------------------------------------------------------
  {
    id: 'aws-key-programmatic-abuse',
    title: 'Compromised AWS Access Key → Programmatic Abuse',
    difficulty: 'intermediate',
    tags: ['aws', 'iam', 'cloudtrail'],
    summary:
      'An exposed IAM access key is used from an unusual IP to enumerate and access S3 data programmatically.',
    objective:
      'Connect IAM, CloudTrail and S3 access logs to detect abused access keys and data access patterns.',
    defenderFocus:
      'CloudTrail events, IAM configuration, S3 data access and anomaly detection for API usage.',
    overallMitreTechniques: [
      { id: 'T1078', name: 'Valid Accounts (Cloud)' },
      { id: 'T1526', name: 'Cloud Service Discovery' },
      { id: 'T1530', name: 'Data from Cloud Storage Object' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'First Use of Key from Unusual IP',
        description:
          'An IAM user access key that normally operates from a narrow IP range suddenly appears from an internet-range IP and new user-agent.',
        sampleLogs: (vars = {}) => {
          const ip = vars.attackerIp || '185.100.87.33';
          return [
            `[CloudTrail] 2025-09-01T10:11:20Z eventName="AssumeRole" userIdentity.type="IAMUser" userIdentity.userName="build-bot" sourceIPAddress="${ip}" userAgent="aws-cli/2.15.1" errorCode=""`,
            `[CloudTrail] 2025-09-01T10:11:22Z eventName="GetCallerIdentity" userIdentity.arn="arn:aws:iam::123456789012:user/build-bot" sourceIPAddress="${ip}" userAgent="aws-cli/2.15.1"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1078', name: 'Valid Accounts (Cloud)' },
          { id: 'T1526', name: 'Cloud Service Discovery' },
        ],
        defenderPerspective:
          'GetCallerIdentity immediately after unusual AssumeRole usage from a new IP is a classic sign of key testing by an attacker.',
        defenderActions: [
          'Alert on IAM users or roles used from new countries / ASN ranges outside their baseline.',
          'Correlate `GetCallerIdentity` and discovery calls shortly after first-time usage of a key.',
        ],
        keySignals: [
          'First-time usage of `build-bot` key from an internet IP not in your corporate ranges.',
          'Immediate sequence of `AssumeRole` → `GetCallerIdentity` from that IP.',
        ],
      },
      {
        id: 'step-2',
        title: 'S3 Enumeration & Bulk Object Access',
        description:
          'The attacker enumerates S3 buckets and then accesses database backup objects using the same key.',
        sampleLogs: (vars = {}) => {
          const ip = vars.attackerIp || '185.100.87.33';
          const bucket = vars.backupBucket || 'prod-app-backups';
          return [
            `[CloudTrail] 2025-09-01T10:12:05Z eventName="ListBuckets" userIdentity.userName="build-bot" sourceIPAddress="${ip}" userAgent="aws-cli/2.15.1"`,
            `[CloudTrail] 2025-09-01T10:12:15Z eventName="ListObjectsV2" requestParameters.bucketName="${bucket}" requestParameters.prefix="db/"`,
            `[S3 Access Log] 2025-09-01T10:12:40Z bucket="${bucket}" requester="123456789012:build-bot" operation="REST.GET.OBJECT" key="db/users-2025-08-31.sql.gz" httpStatus=200 bytesSent=5432011`,
          ];
        },
        mitreTechniques: [
          { id: 'T1526', name: 'Cloud Service Discovery' },
          { id: 'T1530', name: 'Data from Cloud Storage Object' },
        ],
        defenderPerspective:
          'A CI/CD user accessing database backups directly is unusual. Enumerations across buckets followed by backup downloads is high-risk.',
        defenderActions: [
          'Profile normal S3 access patterns for CI/CD principals and alert on direct backup access.',
          'Require IAM conditions (IP ranges, MFA, roles) for access to backup buckets.',
        ],
        keySignals: [
          'ListBuckets and ListObjects against backup buckets from a build-focused IAM principal.',
          'REST.GET.OBJECT operations on database dumps by principals that do not normally read them.',
        ],
      },
      {
        id: 'step-3',
        title: 'Key Revocation & Access Review',
        description:
          'The security team revokes the compromised key, rotates secrets and reviews additional activity.',
        sampleLogs: (vars = {}) => {
          const bucket = vars.backupBucket || 'prod-app-backups';
          return [
            '[CloudTrail] 2025-09-01T10:25:10Z eventName="UpdateAccessKey" userIdentity.userName="security-admin" requestParameters.userName="build-bot" requestParameters.status="Inactive"',
            `[CloudTrail] 2025-09-01T10:26:00Z eventName="PutUserPolicy" userIdentity.userName="security-admin" requestParameters.userName="build-bot" requestParameters.policyName="Deny-BuildBot-${bucket}"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1078', name: 'Valid Accounts (Cloud) - contained' },
        ],
        defenderPerspective:
          'Revoking the key is step one; you must also ensure long-lived sessions are invalidated and similar keys are reviewed.',
        defenderActions: [
          'Deactivate the compromised access key and rotate any secrets derived from the accessed backups.',
          'Review CloudTrail for the same IP or userAgent against other IAM users/roles.',
          'Tighten IAM policies and SCPs around backup buckets to prevent similar abuse.',
        ],
        keySignals: [
          'Access key status changed to Inactive shortly after suspicious activity.',
          'New deny policies attached to the previously abused principal or backup buckets.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 8) Malicious Docker Image → Crypto Miner Deployment (Intermediate)
  // ---------------------------------------------------------------------------
  {
    id: 'docker-crypto-miner',
    title: 'Malicious Docker Image → Crypto Miner Deployment',
    difficulty: 'intermediate',
    tags: ['docker', 'containers', 'resource hijacking'],
    summary:
      'A compromised Docker image is pulled to a node and starts a hidden crypto-mining process.',
    objective:
      'Show how container runtime logs, host telemetry and network traffic reveal resource hijacking.',
    defenderFocus:
      'Container engine logs, host process monitoring, outbound network observations.',
    overallMitreTechniques: [
      { id: 'T1204', name: 'User Execution (Container)' },
      { id: 'T1496', name: 'Resource Hijacking' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'Image Pull from Untrusted Registry',
        description:
          'An admin pulls a container image from a registry that is not part of the normal workflow.',
        sampleLogs: (vars = {}) => {
          const node = vars.nodeName || 'node-01';
          const container = vars.containerName || 'hopeful_roentgen';
          const registry = vars.registryHost || 'registry.example.net';
          return [
            `[Docker] 2025-09-10T08:02:11Z action="pull" image="${registry}/tools/ubuntu-base:latest" host="${node}" user="ops-admin"`,
            `[Docker] 2025-09-10T08:02:25Z action="create" container="${container}" image="${registry}/tools/ubuntu-base:latest" host="${node}"`,
          ];
        },
        mitreTechniques: [{ id: 'T1204', name: 'User Execution (Container)' }],
        defenderPerspective:
          'Pulls from non-approved registries or personal namespaces are a common entry point for backdoored images.',
        defenderActions: [
          'Restrict container pulls to approved registries and signed images only.',
          'Alert on image pulls from external registries for production nodes.',
        ],
        keySignals: [
          'New registry hostname not seen before on that node.',
          'Images deployed to production from personal or unverified namespaces.',
        ],
      },
      {
        id: 'step-2',
        title: 'Hidden Miner Process Inside Container',
        description:
          'Shortly after start, the container spawns a CPU-intensive mining process with outbound connections to a mining pool.',
        sampleLogs: (vars = {}) => {
          const container = vars.containerName || 'hopeful_roentgen';
          return [
            `[ContainerRuntime] 2025-09-10T08:03:05Z container="${container}" pid=2142 process="/usr/bin/bash" args="-c ./entrypoint.sh" cpuPct=35`,
            `[ContainerRuntime] 2025-09-10T08:03:10Z container="${container}" pid=2199 process="/usr/bin/xmrig" args="--donate-level=1" cpuPct=290`,
            `[NetFlow] 2025-09-10T08:03:12Z srcPod="${container}" dstIp="pool.crypto-example.com" dstPort=3333 proto="tcp" bytesOut=983432`,
          ];
        },
        mitreTechniques: [{ id: 'T1496', name: 'Resource Hijacking' }],
        defenderPerspective:
          'Host CPU usage jumps and outbound traffic to a known mining pool strongly suggests cryptomining.',
        defenderActions: [
          'Monitor per-container CPU and alert on sustained high usage for non-batch workloads.',
          'Block outbound connections to known mining pools and risky ports.',
        ],
        keySignals: [
          'Processes like `xmrig` or similar miners inside containers.',
          'Sustained high CPU and outbound connections to mining pool domains/ports.',
        ],
      },
      {
        id: 'step-3',
        title: 'Container Kill & Image Quarantine',
        description:
          'The security team kills the container, blocks the image and audits other nodes for similar deployments.',
        sampleLogs: (vars = {}) => {
          const container = vars.containerName || 'hopeful_roentgen';
          const node = vars.nodeName || 'node-01';
          const registry = vars.registryHost || 'registry.example.net';
          return [
            `[Docker] 2025-09-10T08:05:20Z action="kill" container="${container}" signal="SIGKILL" host="${node}"`,
            `[Registry] 2025-09-10T08:06:11Z action="quarantine" image="${registry}/tools/ubuntu-base:latest" reason="malicious content"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1496', name: 'Resource Hijacking (contained)' },
        ],
        defenderPerspective:
          'Removing the image from circulation and scanning for clones on other nodes is critical to stop recurrence.',
        defenderActions: [
          'Terminate suspicious containers and block the corresponding images in the registry.',
          'Scan nodes for containers created from the same image digest.',
          'Implement admission controls (e.g., signed images, predefined allowlists).',
        ],
        keySignals: [
          'Kill actions against the miner container followed by registry quarantine events.',
          'No further mining traffic from that cluster after remediation.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 9) DNS Tunneling C2 → Beaconing Detection (Advanced)
  // ---------------------------------------------------------------------------
  {
    id: 'dns-tunnel-beaconing',
    title: 'DNS Tunneling C2 → Beaconing Detection',
    difficulty: 'advanced',
    tags: ['network', 'dns', 'c2'],
    summary:
      'An endpoint uses DNS queries with encoded subdomains to talk to a command-and-control server.',
    objective:
      'Use DNS logs and basic statistics to detect beaconing and tunneling patterns.',
    defenderFocus:
      'DNS query logs, proxy/firewall logs and network telemetry (NetFlow).',
    overallMitreTechniques: [
      { id: 'T1071', name: 'Application Layer Protocol (DNS)' },
      { id: 'T1572', name: 'Protocol Tunneling' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'High-Entropy Subdomain Queries',
        description:
          'A workstation begins issuing frequent DNS queries with long, random-looking subdomains to a single domain.',
        sampleLogs: (vars = {}) => {
          const srcIp = vars.dnsClientIp || '10.30.5.44';
          const c2Ip = vars.dnsC2Ip || '203.0.113.200';
          const domain = vars.dnsC2Domain || 'example-c2.net';
          const label1 = vars.dnsLabel1 || 'oafj39afj3lkjsdf9a';
          const label2 = vars.dnsLabel2 || '9as8d7f9asd7f98asd7f';

          return [
            `[DNS] 2025-09-20T19:01:12Z srcIp="${srcIp}" query="${label1}.${domain}" qtype="A" response="${c2Ip}"`,
            `[DNS] 2025-09-20T19:01:22Z srcIp="${srcIp}" query="${label2}.${domain}" qtype="A" response="${c2Ip}"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1071', name: 'Application Layer Protocol (DNS)' },
        ],
        defenderPerspective:
          'High-entropy labels with consistent parent domain and short intervals often indicate DNS tunneling or C2 beacons.',
        defenderActions: [
          'Compute basic entropy/length statistics for queried subdomains and flag outliers.',
          'Alert when one host repeatedly queries many unique subdomains under the same parent domain.',
        ],
        keySignals: [
          'Very long, random-looking subdomains under a single domain.',
          'Regular intervals between queries from the same host.',
        ],
      },
      {
        id: 'step-2',
        title: 'Correlating DNS with Outbound Traffic',
        description:
          'NetFlow confirms that the host also maintains long-lived connections to the resolved IP.',
        sampleLogs: (vars = {}) => {
          const srcIp = vars.dnsClientIp || '10.30.5.44';
          const c2Ip = vars.dnsC2Ip || '203.0.113.200';
          return [
            `[NetFlow] 2025-09-20T19:01:25Z srcIp="${srcIp}" dstIp="${c2Ip}" dstPort=443 bytesOut=84532 bytesIn=10322 connDuration=45s`,
            `[Firewall] 2025-09-20T19:01:25Z rule="Default-Allow-HTTPS" srcIp="${srcIp}" dstIp="${c2Ip}" action=Allow`,
          ];
        },
        mitreTechniques: [{ id: 'T1572', name: 'Protocol Tunneling' }],
        defenderPerspective:
          'DNS alone can be noisy. Seeing corresponding persistent HTTPS sessions to the same IP strengthens the case for C2.',
        defenderActions: [
          'Correlate high-entropy DNS domains with subsequent long-lived outbound connections.',
          'Enrich suspicious IPs/domains with threat intel to confirm known C2 infrastructure.',
        ],
        keySignals: [
          'Long-lived connections to IPs resolved from suspicious domains.',
          'Traffic volume inconsistent with typical user browsing patterns.',
        ],
      },
      {
        id: 'step-3',
        title: 'Blocking Domain & Host Containment',
        description:
          'The SOC blocks the domain, isolates the host and investigates potential lateral movement.',
        sampleLogs: (vars = {}) => {
          const domain = vars.dnsC2Domain || 'example-c2.net';
          return [
            `[DNSPolicy] 2025-09-20T19:10:00Z action="BlockDomain" domain="${domain}" actor="SocTier2"`,
            '[EDR Action] 2025-09-20T19:11:20Z host="WKS-SALES01" action="NetworkIsolation" status=Success reason="Suspicious DNS tunneling pattern"',
          ];
        },
        mitreTechniques: [
          { id: 'T1071', name: 'Application Layer Protocol (DNS) - contained' },
        ],
        defenderPerspective:
          'Blocking the domain cuts off C2, but you still need to identify the implanted malware and any lateral movement.',
        defenderActions: [
          'Isolate the affected endpoint and collect forensic artifacts.',
          'Scan for the same tunneling pattern across other hosts.',
          'Update detections for DNS tunneling and beaconing based on this incident.',
        ],
        keySignals: [
          'DNS policy updates targeting the tunneling domain.',
          'EDR isolation actions tied back to the same host and timeframe.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 10) ICS Modbus Anomaly → Unauthorized Writes (Advanced)
  // ---------------------------------------------------------------------------
  {
    id: 'ics-modbus-unauthorized-writes',
    title: 'ICS Modbus Anomaly → Unauthorized Writes',
    difficulty: 'advanced',
    tags: ['ics', 'scada', 'modbus'],
    summary:
      'A rogue Modbus client issues unauthorized write commands to a PLC controlling a critical process.',
    objective:
      'Illustrate how Modbus function codes, write/read ratios and address ranges reveal anomalies in OT traffic.',
    defenderFocus:
      'ICS network captures, Modbus function-code statistics and engineering station baselines.',
    overallMitreTechniques: [
      { id: 'T0865', name: 'Modify Controller Tasking' }, 
      { id: 'T0880', name: 'Modify Control Logic' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'New Modbus Client Appears on Control VLAN',
        description:
          'A previously unseen host begins sending Modbus traffic to a PLC, using only read functions at first.',
        sampleLogs: (vars = {}) => {
          const clientIp = vars.icsClientIp || '10.100.5.50';
          const plcIp = vars.plcIp || '10.100.1.10';
          return [
            `[ICS Sensor] 2025-10-01T13:01:10Z proto="modbus" srcIp="${clientIp}" dstIp="${plcIp}" functionCode=3 (Read Holding Registers) unitId=1`,
            `[ICS Sensor] 2025-10-01T13:01:15Z proto="modbus" srcIp="${clientIp}" dstIp="${plcIp}" functionCode=3 (Read Holding Registers) address=40001 length=12`,
          ];
        },
        mitreTechniques: [
          { id: 'T0865', name: 'Modify Controller Tasking (recon stage)' },
        ],
        defenderPerspective:
          'A new Modbus master on a control VLAN is suspicious, even if it only performs reads initially.',
        defenderActions: [
          'Baseline which engineering stations and HMIs are allowed to talk Modbus to each PLC.',
          'Alert on new Modbus masters or unexpected source IPs on control VLANs.',
        ],
        keySignals: [
          'New srcIp speaking Modbus to a PLC IP not seen in historical baselines.',
          'Read-only traffic that does not match expected polling patterns from HMIs/SCADA.',
        ],
      },
      {
        id: 'step-2',
        title: 'Spike in Write Commands to Critical Addresses',
        description:
          'Shortly after reconnaissance, the same client starts sending write commands to coil and holding-register addresses that control breakers or setpoints.',
        sampleLogs: (vars = {}) => {
          const clientIp = vars.icsClientIp || '10.100.5.50';
          const plcIp = vars.plcIp || '10.100.1.10';
          return [
            `[ICS Sensor] 2025-10-01T13:02:05Z proto="modbus" srcIp="${clientIp}" dstIp="${plcIp}" functionCode=5 (Write Single Coil) address=00017 value=0x00`,
            `[ICS Sensor] 2025-10-01T13:02:09Z proto="modbus" srcIp="${clientIp}" dstIp="${plcIp}" functionCode=16 (Write Multiple Registers) address=40021 length=4`,
          ];
        },
        mitreTechniques: [{ id: 'T0880', name: 'Modify Control Logic' }],
        defenderPerspective:
          'A read→write pivot, especially to safety- or process-critical addresses, is a strong anomaly in many ICS environments.',
        defenderActions: [
          'Alert on sudden increases in Modbus write ratio for PLCs, especially from new clients.',
          'Flag writes to address ranges mapped to breakers, safety interlocks or critical setpoints.',
        ],
        keySignals: [
          'Read-heavy traffic from a new master followed by a sudden burst of writes.',
          'Writes to addresses that historically see only engineering-station changes during maintenance windows.',
        ],
      },
      {
        id: 'step-3',
        title: 'Engineering Review & Network Containment',
        description:
          'The operations and security teams work together to block the rogue client and validate PLC logic and process state.',
        sampleLogs: (vars = {}) => {
          const clientIp = vars.icsClientIp || '10.100.5.50';
          const plcIp = vars.plcIp || '10.100.1.10';
          return [
            `[OT Firewall] 2025-10-01T13:05:30Z rule="Block-Rogue-ICS-Client" srcIp="${clientIp}" dstSubnet="${plcIp}/32" proto="tcp/502" action=Block`,
            '[EngineeringStation] 2025-10-01T13:07:10Z action="UploadLogic" plc="PLC-Substation-01" result="No unauthorized ladder changes"',
          ];
        },
        mitreTechniques: [
          { id: 'T0880', name: 'Modify Control Logic (contained)' },
        ],
        defenderPerspective:
          'Even if logic is unchanged, verifying state and blocking the rogue client reduces risk of future attempts.',
        defenderActions: [
          'Block the rogue client at the OT firewall and investigate how it reached the control VLAN.',
          'Validate PLC logic and current process state with engineering teams.',
          'Update baselines and alerts around Modbus clients and write ratios.',
        ],
        keySignals: [
          'Firewall rules added specifically to block the rogue Modbus client.',
          'Engineering validation tasks (logic upload/compare) scheduled after the anomaly.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 11) Golden Ticket / Kerberos Abuse → Domain Recon & Lateral Movement (Adv)
  // ---------------------------------------------------------------------------
  {
    id: 'ad-golden-ticket-detection',
    title: 'Golden Ticket / Kerberos Abuse → Domain Recon & Lateral Movement',
    difficulty: 'advanced',
    tags: ['windows', 'active directory', 'kerberos'],
    summary:
      'An attacker with DC-level access forges Kerberos tickets to maintain persistence and move laterally without reusing passwords.',
    objective:
      'Highlight Kerberos TGT/TGS anomalies, unusual ticket lifetimes and service access patterns that reveal Golden Ticket-style abuse.',
    defenderFocus:
      'Domain controller security logs, Kerberos TGS events, account baselines and tiering.',
    overallMitreTechniques: [
      { id: 'T1558.001', name: 'Steal or Forge Kerberos Tickets (Golden Ticket)' },
      { id: 'T1078', name: 'Valid Accounts' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'Suspicious Replication-Style Access to Directory',
        description:
          'A privileged account performs directory replication-style access outside of backup windows, which may indicate DCSync or similar credential theft.',
        sampleLogs: (vars = {}) => {
          const backupSvc = vars.backupSvc || 'DOMAIN\\backup-svc';
          const adIp = vars.adIp || '10.50.4.30';
          return [
            `[Windows Security] 2025-10-15T02:13:22Z EventID=4662 SubjectUserName="${backupSvc}" ObjectType="domainDNS" Properties="Replicating Directory Changes, Replicating Directory Changes All" AccessMask="0x100"`,
            `[Windows Security] 2025-10-15T02:13:25Z EventID=4624 LogonType=3 TargetUserName="${backupSvc}" IpAddress="${adIp}" LogonProcessName="NtLmSsp" AuthenticationPackageName="NTLM"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1558.001', name: 'Steal or Forge Kerberos Tickets (Golden Ticket)' },
        ],
        defenderPerspective:
          'Legitimate backup accounts may have replication rights, but out-of-schedule use from unusual source hosts is a strong precursor to ticket forgery.',
        defenderActions: [
          'Baseline when and from where backup / replication accounts perform directory replication.',
          'Alert when `Replicating Directory Changes` rights are exercised outside maintenance windows or from new IPs.',
        ],
        keySignals: [
          'Directory replication-related events by service accounts at odd hours.',
          'Replication traffic originating from non-backup hosts.',
        ],
      },
      {
        id: 'step-2',
        title: 'Anomalous Kerberos TGT / TGS Activity',
        description:
          'Shortly afterwards, the same account (or a forged principal) starts requesting tickets with unusually long lifetimes and from unexpected hosts.',
        sampleLogs: (vars = {}) => {
          const adminSvc = vars.adminSvc || 'DOMAIN\\svc-admin';
          const adIp = vars.adIp || '10.50.4.30';
          const fileServer = vars.fileServer || 'FSRV-01';
          return [
            `[Windows Security] 2025-10-15T02:20:01Z EventID=4768 TargetUserName="${adminSvc}" IpAddress="${adIp}" TicketOptions="0x40810000" TicketEncryptionType="0x12"`,
            `[Windows Security] 2025-10-15T02:20:15Z EventID=4769 ServiceName="cifs/${fileServer}.domain.local" TargetUserName="${adminSvc}" IpAddress="${adIp}" TicketOptions="0x40810000" TicketEncryptionType="0x12" TicketStatus="0x0" TicketLifeTime="20:00:00"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1558.001', name: 'Steal or Forge Kerberos Tickets (Golden Ticket)' },
        ],
        defenderPerspective:
          'Golden Tickets often show up as tickets with abnormal lifetimes or issued to accounts/services that do not normally use Kerberos in that way.',
        defenderActions: [
          'Establish normal Kerberos ticket lifetimes and alert on unusually long TGT/TGS lifetimes.',
          'Alert on Tier-0 / admin accounts requesting tickets from workstations or application servers where they are not normally used.',
        ],
        keySignals: [
          'TGS requests for high-value services (`cifs/FSRV-01`, `ldap/DC1`) by accounts not normally associated with them.',
          'Kerberos tickets with unusual lifetimes or encryption types compared to baseline.',
        ],
      },
      {
        id: 'step-3',
        title: 'Lateral Movement & Containment',
        description:
          'The forged tickets are used to access file servers and potentially other Tier-0 assets, prompting emergency response.',
        sampleLogs: (vars = {}) => {
          const adminSvc = vars.adminSvc || 'DOMAIN\\svc-admin';
          const adIp = vars.adIp || '10.50.4.30';
          const fileServer = vars.fileServer || 'FSRV-01';
          return [
            `[Windows Security] 2025-10-15T02:22:40Z EventID=4624 LogonType=3 TargetUserName="${adminSvc}" WorkstationName="${fileServer}" IpAddress="${adIp}" AuthenticationPackageName="Kerberos"`,
            `[SecurityPlatform] 2025-10-15T02:24:10Z IncidentID=INC-2025-1015 Category="Identity" Summary="Possible Golden Ticket activity for ${adminSvc}" Severity=Critical Status=Open`,
          ];
        },
        mitreTechniques: [{ id: 'T1078', name: 'Valid Accounts' }],
        defenderPerspective:
          'At this stage, you treat the domain as potentially compromised. Containment focuses on breaking ticket trust and rebuilding safely.',
        defenderActions: [
          'Rotate the `krbtgt` account password (twice) following established recovery procedures.',
          'Isolate and rebuild potentially compromised admin workstations and DCs.',
          'Harden tiering models and restrict where administrative accounts can log on.',
        ],
        keySignals: [
          'Kerberos-authenticated access to Tier-0 assets from previously unseen admin logon paths.',
          'High-severity identity incidents tied specifically to Kerberos ticket anomalies.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 12) CI Pipeline Secret Abuse → Cloud Account Manipulation (Advanced)
  // ---------------------------------------------------------------------------
  {
    id: 'ci-secret-abuse-cloud',
    title: 'CI Pipeline Secret Abuse → Cloud Account Manipulation',
    difficulty: 'advanced',
    tags: ['ci/cd', 'cloud', 'secrets'],
    summary:
      'A CI pipeline token is abused from outside the normal build environment to modify cloud resources and access data.',
    objective:
      'Show how CI audit logs, runner IPs and cloud audit trails combine to reveal abused pipeline secrets.',
    defenderFocus:
      'CI/CD platform audit logs, runner IP allowlists, cloud audit (CloudTrail / Activity Logs).',
    overallMitreTechniques: [
      { id: 'T1552', name: 'Unsecured Credentials' },
      { id: 'T1078', name: 'Valid Accounts (Cloud)' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'Pipeline Token Used from Unusual Runner / IP',
        description:
          'A personal access token or CI job token associated with a repo is used from an IP range that does not match your normal runners.',
        sampleLogs: (vars = {}) => {
          const ciIp = vars.ciIp || '185.220.101.35';
          const repo = vars.repoName || 'org/app-service';
          return [
            `[CI Audit] 2025-11-02T09:10:11Z actor="ci-bot" action="job_token_auth" repo="${repo}" ip="${ciIp}" runnerId="unknown" userAgent="git/2.44.0"`,
            `[CI Audit] 2025-11-02T09:10:14Z actor="ci-bot" action="clone" repo="${repo}" ref="main" ip="${ciIp}"`,
          ];
        },
        mitreTechniques: [{ id: 'T1552', name: 'Unsecured Credentials' }],
        defenderPerspective:
          'CI tokens should normally be used only by your own runners. A new runnerId and internet IP is a strong signal of token theft.',
        defenderActions: [
          'Allowlist runner IP ranges and alert on CI access from IPs outside those ranges.',
          'Alert when new, unregistered runner identifiers appear for sensitive projects.',
        ],
        keySignals: [
          'CI bot identities used from IPs that do not belong to your runners or VPN.',
          'Clone / fetch operations on sensitive repos from unknown runners.',
        ],
      },
      {
        id: 'step-2',
        title: 'Cloud API Calls from the Same Identity',
        description:
          'Shortly after the suspicious CI activity, cloud audit logs show API calls using credentials issued to the same pipeline identity.',
        sampleLogs: (vars = {}) => {
          const ciIp = vars.ciIp || '185.220.101.35';
          const roleName = vars.ciRoleName || 'ci-bot-app-service';
          const bucket = vars.secretsBucket || 'prod-secrets-backups';
          return [
            `[CloudTrail] 2025-11-02T09:11:30Z eventName="AssumeRole" userIdentity.sessionContext.sessionIssuer.userName="${roleName}" sourceIPAddress="${ciIp}" userAgent="aws-sdk-go/1.50"`,
            `[CloudTrail] 2025-11-02T09:11:41Z eventName="DescribeInstances" userIdentity.arn="arn:aws:sts::123456789012:assumed-role/${roleName}/attack-session" sourceIPAddress="${ciIp}"`,
            `[CloudTrail] 2025-11-02T09:11:55Z eventName="GetObject" requestParameters.bucketName="${bucket}" requestParameters.key="env/prod/.env.enc" sourceIPAddress="${ciIp}"`,
          ];
        },
        mitreTechniques: [{ id: 'T1078', name: 'Valid Accounts (Cloud)' }],
        defenderPerspective:
          'The same IP that touched your repo is now using a CI-bound role to enumerate infrastructure and pull sensitive objects.',
        defenderActions: [
          'Tie CI identities (roles, service principals) back to specific repos and runners and alert on their use from non-runner IPs.',
          'Require short-lived credentials and strict scoping for CI roles, especially around secrets backends and backup buckets.',
        ],
        keySignals: [
          'AssumeRole events where the session name or issuer maps to CI, but the source IP does not.',
          'Direct access to backup / secrets buckets using CI identities.',
        ],
      },
      {
        id: 'step-3',
        title: 'Token Revocation & Hardening',
        description:
          'The security team revokes the compromised CI credentials, rotates affected secrets and tightens both pipeline and cloud policies.',
        sampleLogs: (vars = {}) => {
          const roleName = vars.ciRoleName || 'ci-bot-app-service';
          return [
            `[CI Audit] 2025-11-02T09:20:05Z actor="SecurityAdmin" action="revoke_token" tokenId="${roleName}" reason="suspected compromise"`,
            `[CloudTrail] 2025-11-02T09:21:10Z eventName="DeleteAccessKey" userIdentity.userName="${roleName}" requestParameters.status="Inactive"`,
            `[CloudTrail] 2025-11-02T09:22:30Z eventName="PutRolePolicy" userIdentity.userName="SecurityAdmin" requestParameters.roleName="${roleName}" requestParameters.policyName="Restrict-CI-ProdAccess"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1552', name: 'Unsecured Credentials (contained)' },
        ],
        defenderPerspective:
          'Fixing the immediate compromise is only part of the work; you also want durable guardrails on how CI can reach production.',
        defenderActions: [
          'Revoke the compromised CI token and rotate any secrets it could reach.',
          'Review all CI roles / service principals and enforce least-privilege, short-lived access.',
          'Instrument detections that correlate CI audit logs with cloud audit logs on IP/identity.',
        ],
        keySignals: [
          'CI token revocation events followed by tightened IAM policies.',
          'No further cloud API calls from the previously suspicious IP after remediation.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 13) Password Spray Against IdP → Account Lockout (Beginner)
  // ---------------------------------------------------------------------------
  {
    id: 'idp-password-spray-lockout',
    title: 'Password Spray Against IdP → Account Lockout',
    difficulty: 'beginner',
    tags: ['identity', 'idp', 'bruteforce'],
    summary:
      'An attacker performs a password spray against a cloud identity provider, causing multiple failed sign-ins and account lockouts.',
    objective:
      'See how IdP sign-in logs and simple correlation reveal password spray attempts.',
    defenderFocus:
      'Identity provider logs, risky sign-ins and account lockout events.',
    overallMitreTechniques: [
      { id: 'T1110.003', name: 'Password Spraying' },
      { id: 'T1078', name: 'Valid Accounts' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'Low-and-Slow Spray from Single IP',
        description:
          'An attacker uses a common-password list against many users at the cloud IdP, keeping the rate low enough to avoid basic rate limits.',
        sampleLogs: (vars = {}) => {
          const ip = vars.sprayIp || '198.51.100.23';
          const u1 = vars.sprayUser1 || 'user01';
          const u2 = vars.sprayUser2 || 'user35';
          const u3 = vars.sprayUser3 || 'user78';
          return [
            `[IdP] 2025-03-05T08:02:10Z user="${u1}" result=failed failureReason="Invalid username or password" ip="${ip}" location="Unknown" userAgent="Mozilla/5.0" riskLevel=medium`,
            `[IdP] 2025-03-05T08:02:18Z user="${u2}" result=failed failureReason="Invalid username or password" ip="${ip}" location="Unknown" userAgent="Mozilla/5.0" riskLevel=medium`,
            `[IdP] 2025-03-05T08:02:27Z user="${u3}" result=failed failureReason="Invalid username or password" ip="${ip}" location="Unknown" userAgent="Mozilla/5.0" riskLevel=medium`,
          ];
        },
        mitreTechniques: [
          { id: 'T1110.003', name: 'Password Spraying' },
        ],
        defenderPerspective:
          'Each failure looks harmless in isolation, but the pattern of many users, same IP and common user agent is classic password spray.',
        defenderActions: [
          'Alert when the same IP generates failures for many distinct accounts within a short window.',
          'Baseline typical failure rates and flag spikes sourced from internet IPs rather than VPN/corporate ranges.',
        ],
        keySignals: [
          'Many different usernames failing from the same source IP.',
          'Risk level elevated for sign-ins from unknown or anonymized locations.',
        ],
      },
      {
        id: 'step-2',
        title: 'Built-in Risk Detection & Lockouts',
        description:
          'The IdP raises a risky sign-in / password spray alert and some accounts hit lockout thresholds.',
        sampleLogs: (vars = {}) => {
          const ip = vars.sprayIp || '198.51.100.23';
          const u1 = vars.sprayUser1 || 'user01';
          const u2 = vars.sprayUser2 || 'user35';
          return [
            `[IdP] 2025-03-05T08:03:05Z user="${u1}" result=failed failureReason="Account locked" ip="${ip}" location="Unknown" riskLevel=high`,
            `[IdP] 2025-03-05T08:03:07Z user="${u2}" result=failed failureReason="Account locked" ip="${ip}" location="Unknown" riskLevel=high`,
            `[SecurityPlatform] 2025-03-05T08:03:15Z IncidentID="INC-2025-0305-01" Category="Identity" Summary="Possible password spray from ${ip}" Severity=High Status=Open`,
          ];
        },
        mitreTechniques: [
          { id: 'T1110.003', name: 'Password Spraying' },
        ],
        defenderPerspective:
          'Lockout errors and a single IP tied to multiple accounts push this into clear brute-force territory.',
        defenderActions: [
          'Confirm whether targeted usernames follow a pattern (e.g., common firstnames or service accounts).',
          'Proactively review sign-ins from the same IP over a longer time range for stealthier spray activity.',
        ],
        keySignals: [
          'Account lockouts clustered around the same IP or ASN.',
          'Security platform incidents naming password spray or suspicious sign-in patterns.',
        ],
      },
      {
        id: 'step-3',
        title: 'Blocking Source IP & Hardening Sign-in',
        description:
          'The SOC blocks the offending IP range, resets impacted accounts and adjusts IdP policies to reduce future spray risk.',
        sampleLogs: (vars = {}) => {
          const ip = vars.sprayIp || '198.51.100.23';
          return [
            `[Firewall] 2025-03-05T08:10:00Z rule="Block-Password-Spray-IP" srcIp="${ip}" action=Block actor="SocTier2"`,
            '[IdP] 2025-03-05T08:12:30Z policyChange="SmartLockout" newSettings="Stronger lockout for common passwords; IP-based throttling enabled" actor="IdpAdmin"',
          ];
        },
        mitreTechniques: [
          { id: 'T1110.003', name: 'Password Spraying (contained)' },
        ],
        defenderPerspective:
          'The immediate attacker IP may change, but lockout and throttling settings make future sprays more expensive.',
        defenderActions: [
          'Reset passwords for any accounts that showed borderline-success activity during the spray.',
          'Enable or tighten smart lockout, common-password blocklists and conditional access for risky sign-ins.',
          'Add detections that explicitly look for many users failing from the same IP over 5-15 minute windows.',
        ],
        keySignals: [
          'Network or WAF rules blocking the previously abusive IP or ASN.',
          'IdP policy changes around lockout / throttling after a spray incident.',
        ],
      },
    ],
  },

  // ---------------------------------------------------------------------------
  // 14) SaaS File Download Spike → Potential Data Leak (Beginner)
  // ---------------------------------------------------------------------------
  {
    id: 'saas-download-anomaly',
    title: 'SaaS File Download Spike → Potential Data Leak',
    difficulty: 'beginner',
    tags: ['saas', 'cloud', 'exfiltration'],
    summary:
      'A legitimate user account suddenly downloads an unusually large volume of files from a SaaS storage app.',
    objective:
      'Understand how SaaS audit logs and CASB/DLP events highlight risky download behaviour.',
    defenderFocus:
      'SaaS audit logs, UEBA / CASB alerts and basic volume/behaviour baselines.',
    overallMitreTechniques: [
      { id: 'T1530', name: 'Data from Cloud Storage Object' },
      { id: 'T1119', name: 'Automated Collection' },
    ],
    steps: [
      {
        id: 'step-1',
        title: 'Normal Sign-in to SaaS Storage',
        description:
          'A user signs in to the corporate SaaS storage app from their usual location and device.',
        sampleLogs: (vars = {}) => {
          const user = vars.saasUser || 'user20';
          const ip = vars.saasIp || '203.0.113.44';
          const app = vars.saasAppName || 'CloudDrive Pro';
          return [
            `[SaaS] 2025-04-12T13:00:10Z user="${user}" action="Login" app="${app}" ip="${ip}" location="Montreal, CA" device="Windows 11" result="success"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1078', name: 'Valid Accounts' },
        ],
        defenderPerspective:
          'Nothing looks suspicious yet: location, device and app are typical for this user.',
        defenderActions: [
          'Ensure SaaS sign-ins are integrated into central logging / UEBA.',
          'Baseline normal login times and locations for sensitive users.',
        ],
        keySignals: [
          'Standard, successful SaaS sign-in from expected geo and device.',
        ],
      },
      {
        id: 'step-2',
        title: 'Burst of Downloads from Sensitive Folders',
        description:
          'Shortly after sign-in, the user downloads a large number of files from a sensitive folder, far above their usual volume.',
        sampleLogs: (vars = {}) => {
          const user = vars.saasUser || 'user20';
          const ip = vars.saasIp || '203.0.113.44';
          const app = vars.saasAppName || 'CloudDrive Pro';
          return [
            `[SaaS] 2025-04-12T13:05:22Z user="${user}" action="Download" app="${app}" resource="/Finance/Q1-2025/Budget.xlsx" bytesOut=842311 ip="${ip}"`,
            `[SaaS] 2025-04-12T13:05:35Z user="${user}" action="Download" app="${app}" resource="/Finance/Q1-2025/Forecast.xlsx" bytesOut=932144 ip="${ip}"`,
            `[SaaS] 2025-04-12T13:05:51Z user="${user}" action="Download" app="${app}" resource="/Finance/Q1-2025/Board-Pack.pdf" bytesOut=5021931 ip="${ip}"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1530', name: 'Data from Cloud Storage Object' },
          { id: 'T1119', name: 'Automated Collection' },
        ],
        defenderPerspective:
          'For some roles, bursty downloads are expected; for others, this is a red flag, especially when focused on finance/board materials.',
        defenderActions: [
          'Baseline per-user daily download volumes and alert on unusual spikes from sensitive folders.',
          'Tag high-sensitivity folders (finance, legal, HR) and feed those tags into DLP / CASB policies.',
        ],
        keySignals: [
          'Multiple downloads of high-sensitivity files in a tight time window.',
          'Bytes out significantly above the user’s normal baseline for that app.',
        ],
      },
      {
        id: 'step-3',
        title: 'CASB / DLP Alert & Session Control',
        description:
          'A CASB/DLP policy flags the behaviour as anomalous and optionally terminates the session or requires justification.',
        sampleLogs: (vars = {}) => {
          const user = vars.saasUser || 'user20';
          const ip = vars.saasIp || '203.0.113.44';
          const app = vars.saasAppName || 'CloudDrive Pro';
          return [
            `[CASB] 2025-04-12T13:06:10Z IncidentID="DLP-2025-0412-01" user="${user}" app="${app}" policy="Unusual download volume - Finance" severity="High" ip="${ip}" action="Alert"`,
            `[SaaS] 2025-04-12T13:06:20Z user="${user}" action="SessionTerminated" app="${app}" reason="CASB high-risk activity"`,
          ];
        },
        mitreTechniques: [
          { id: 'T1530', name: 'Data from Cloud Storage Object (contained)' },
        ],
        defenderPerspective:
          'Whether this is an insider, a compromised account or just a bulk export, strong policy-based controls reduce the chances of silent data leakage.',
        defenderActions: [
          'Investigate the user’s intent (business need vs. malicious activity) and confirm endpoint posture.',
          'Refine CASB/DLP thresholds to balance noise and missed true positives.',
          'Add hunting queries for similar patterns across other users and apps.',
        ],
        keySignals: [
          'CASB/DLP incident tied to anomalous SaaS download behaviour.',
          'Session termination or step-up controls enforced after the alert.',
        ],
      },
    ],
  },
];

export function getScenarioById(id) {
  return SCENARIOS.find((s) => s.id === id) || null;
}
