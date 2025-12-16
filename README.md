# Security Webtools

### Local-first security tools for developers & defenders

> _Security Webtools is a growing collection of **browser-based security utilities** designed for developers, DevOps engineers and defenders.
> All tools run **100% locally in your browser**. No servers, no uploads, no telemetry. Sensitive inputs never leave your machine.
> This suite aims to make common security checks **fast, private and easy**, directly in your browser._

## Why local-first?

Most online “security scanners” require you to upload configuration files, secrets or application metadata. Security Webtools avoids this entirely:

- No backend
- No servers or API calls
- No data ever leaves your device
- File uploads are processed **locally in your browser only**
- Everything runs client-side

Perfect for enterprise environments, red/blue teams and developers who cannot upload internal files to external services.

## Current Tools

### **1. Docker Image Security Analyzer (v0.1)**

Analyze any Dockerfile for common security flaws and hardening issues.

**Features:**

- Checks for insecure patterns (777, root user, exposed admin ports, unpinned images, secrets in `ENV`, unsafe downloads)
- Multi-stage build optimization hints
- apt/apk best-practice linting
- Jump-to-line: clicking a finding highlights the matching line in the editor
- Severity filters (High / Warning / Info)
- Export findings as JSON or Markdown
- Clean UI with scrollable findings panel
- Runs fully in-browser

### **2. Local Network Exposure Map (v0.2)**

Visualize Nmap XML or generic JSON scan results to see exposed hosts, risky services and subnet-level clusters.

**Features:**

- Parses Nmap XML output (-oX) and generic JSON ({ hosts: [...] })
- Assigns Low / Medium / High risk per host with explanatory risk notes
- Detects high-risk services (RDP, SMB, SSH, MySQL, VNC, HTTP, etc.)
- Host view: cards with open ports, services and risk badges
- Subnet view: /24 cluster map with color-coded host dots
- Filters: search by IP/hostname, only-up hosts, high+medium only
- Shows top exposed services in the current view
- Export current view as JSON, Markdown, CSV or copy a Markdown report
- All parsing and analysis runs fully in-browser

### 3. **Cloud Misconfiguration Scanner (v0.3)**

Analyze AWS, Azure or GCP JSON exports for common network, storage and IAM misconfigurations locally in the browser.

**Features:**

- Automatically detects platform (AWS / Azure / GCP) from the JSON structure
- Network checks: 0.0.0.0/0 on SSH/RDP/admin ports, broad “allow all ports” rules, Azure NSG Internet rules
- Storage checks: public read/write buckets, encryption disabled, versioning disabled
- IAM checks: wildcard actions/resources, public members (allUsers/allAuthenticatedUsers), highly-privileged roles
- Severity filters (High / Warning / Info)
- Search box to filter by title, description, resource or rule id
- Category chips and summary for network / storage / IAM issues
- Export the current view as JSON or Markdown or copy a Markdown report
- All analysis is performed client-side on the provided file/text

### 4. **Threat Simulation Playground (v0.4)**

Step through realistic multi-stage attack scenarios, analyze static logs and build detection skills - all running completely in your browser.

**Features:**

- 14 realistic attacker scenarios across phishing, cloud abuse, credential attacks, EDR evasion, lateral movement, crypto-mining, SaaS abuse & more
- Step-by-step timelines with MITRE ATT&CK mappings
- Static sample logs across multiple log sources (IDP, EDR, proxy, cloud, auth logs, container logs, etc.)
- Defender-perspective notes + key detection signals
- Interview Mode: hide hints to test your detection skills
- Tag filtering (EDR, Cloud, AD, Identity, Network, SaaS, etc.)
- Deterministic per-visit randomization for IPs, users, hosts, request IDs
- Export full scenario or individual step as Markdown
- Notes panel stored locally in your browser

### 5. **Web Surface Analyzer (v0.5)**

Analyze a website’s browser-side posture from pasted responses: security headers, tech-stack fingerprints and client-side HTML issues - all without making network requests.

**Features:**

- Security header analysis: CSP, HSTS, XFO, XCTO, Referrer-Policy, COOP/COEP/CORP, Permissions-Policy & cookie flags
- Tech-stack fingerprinting from raw HTML (CMS, JS frameworks, CDNs, hosting hints, analytics, rendering mode)
- Client-side HTML review for risky patterns (inline JS, mixed content, unsafe forms, javascript: URLs, inline event handlers, sensitive comments and more)
- Severity badges and filtering controls
- Export results as Markdown or copy summaries
- Fully static: no fetching, scanning or external requests

### **6. Mini SIEM (v0.6)**

Upload security and authentication logs, normalize events into a unified schema, run local correlation rules and explore alerts through time-windowed analytics - all running entirely in your browser.

**Features:**

- **_Multi-format log ingestion (auto-detection):_**
  - JSON/JSONL (generic, Azure AD , CloudTrail, Okta, etc.)
  - CSV (generic timestamp/IP/user exports, Mini SIEM format round-trip)
  - Linux SSH/`auth.log` syslog
  - Apache/Nginx access logs
  - Windows Security (auth-focused exports)
- **_Canonical event normalization:_**
  - Timestamp parsing (ISO strings, epoch seconds/ms, numeric strings)
  - Normalized outcomes (success/fail) across auth, HTTP, cloud and syslog sources
  - Unified event model (IP, user, event type, outcome, protocol-specific fields)
  - Preserves raw log lines for inspection and export
- **_Parsing quality indicators:_**
  - Parsed vs total records
  - Coverage metrics and dataset time span
- **_Time-windowed analytics:_**
  - Presets: All time, last 1h/6h/12h/24h/7d/30d/12 months
  - Adaptive event-density histogram with automatic or manual bucket sizing
- **_Authentication analytics:_**
  - Auth outcomes over time (success vs failure)
  - Auth distribution (success/fail split)
  - Failed authentication attempts by username
- **_Entity & activity analytics:_**
  - Top noisy source IPs
  - Top usernames
  - Event type breakdown
  - Top destinations (IP/host)
- **_Detection & alerting (local correlation rules):_**
  - Bruteforce, password spray, suspicious success, noisy IPs, isolated failures
  - Optional geo-anomaly detections via user-provided IP-to-region mappings
  - Configurable "Home" regions and enable/disable geo logic
  - Alert severity levels (high/medium/low)
  - Alerts grouped by severity and rule category
- **_Investigation workflow:_**
  - Free-text search across normalized fields
  - Alert-to-logs pivot ("view related events")
  - Highlighted matches with raw log context
- **_Overview dashboard:_**
  - Statistics scoped to the selected time window
  - Events, IPs, users, auth outcomes and alert counts
- **_Export capabilities:_**
  - Parsed events and alerts as JSON or CSV
  - Alerts also export as Markdown or copy-to-clipboard
  - Per-chart PNG exports with time window + bucket context
  - Full overview PNG export (stats, charts, alerts, metadata)
- **_Fully local execution:_**
  - All parsing, correlation and visualization runs client-side in the browser

## Upcoming Tools & Roadmap

Security Webtools will expand into a full suite of privacy-first analysis utilities:

### **Planned tools:**

- Cyber Hygiene Planner (automated security roadmap)
- Docker Image Security Analyzer (extended version)

_These will be rolled out incrementally._

## Architecture

Security Webtools is a **React + Vite** single-page application with:

- TailwindCSS
- Pure client-side JavaScript analysis modules
- No backend of any kind
- In-memory state for tool inputs and results

_Every tool is isolated with its own rules & UI._

## Website

> Current live version: v0.6.0 - _Mini SIEM release_

## License

This project is licensed under the **Apache License 2.0**.

_See [`LICENSE`](LICENSE) for full terms._

## Author

Created and maintained by [`dmtkfs`](https://github.com/dmtkfs).
Security researcher & engineer focused on practical, privacy-first tooling.

_Feedback, ideas and bug reports are welcome._

## Support & Updates

If you find this project interesting or useful, consider starring the repository. It helps with visibility and motivates further development.
