# Security Webtools  
### Local-first security tools for developers & defenders

> *Security Webtools is a growing collection of **browser-based security utilities** designed for developers, DevOps engineers and defenders.*
> *All tools run **100% locally in your browser**. No servers, no uploads, no telemetry. Sensitive inputs never leave your machine.*
> *This suite aims to make common security checks **fast, private, and easy**, directly in your browser.*

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

## Upcoming Tools & Roadmap

Security Webtools will expand into a full suite of privacy-first analysis utilities:

### **Planned tools:**
- Cloud Misconfiguration Scanner
- Threat Simulation Playground
- Website Risk Reporter (TLS / Header / Tech-stack analyzer)
- Mini SIEM (Log parsing + detection rules + alerting)
- Cyber Hygiene Planner (automated security roadmap)
- Docker Image Security Analyzer (extended version)
- Network Exposure Map (Nmap / JSON visual graph)

*These will be rolled out incrementally.*

## Architecture
Security Webtools is a **React + Vite** single-page application with:

- TailwindCSS  
- Pure client-side JavaScript analysis modules  
- No backend of any kind  
- LocalStorage for preferences only  

*Every tool is isolated with its own rules & UI.*

## Live Website
**Coming soon: v1.0 public launch.**  

## License
This project is licensed under the **Apache License 2.0**.  

*See [`LICENSE`](LICENSE) for full terms.*

## Author
Created and maintained by [`dmtkfs`](https://github.com/dmtkfs).
Security researcher & engineer focused on practical, privacy-first tooling.

*Feedback, ideas, and bug reports are welcome.*

## Support & Updates
If you find this project interesting or useful, consider starring the repository. It helps with visibility and motivates further development.
