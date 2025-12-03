// src/tools/network-exposure-map/scanParsers.js

export const HIGH_RISK_PORTS = [21, 23, 3389, 445, 1433, 3306, 5900]

export const HIGH_RISK_SERVICES = [
  'telnet',
  'ftp',
  'rdp',
  'ms-wbt-server',
  'vnc',
  'smb',
  'microsoft-ds',
  'cifs',
  'mysql',
  'mssql',
  'ms-sql-s',
  'postgres',
  'postgresql',
  'winrm',
  'http-proxy',
]

// Per-port / per-service hint metadata used by the UI
export const PORT_RISK_HINTS = {
  // --- SSH ---
  22: {
    title: 'SSH exposed',
    summary:
      'SSH is a remote administration protocol. Exposing it broadly increases brute-force and key-theft risk.',
    remediation:
      'Restrict SSH to admin subnets/VPN, use key-based auth, disable password logins, and consider fail2ban or equivalent.',
  },
  ssh: {
    title: 'SSH service detected',
    summary:
      'SSH is commonly targeted for credential stuffing and key abuse when exposed to wide networks or the internet.',
    remediation:
      'Limit exposure, enforce strong auth (keys + MFA where possible), and monitor for suspicious login attempts.',
  },

  // --- RDP ---
  3389: {
    title: 'RDP (Remote Desktop) exposed',
    summary:
      'RDP is a prime target for ransomware operators and credential attacks when reachable from untrusted networks.',
    remediation:
      'Avoid exposing RDP directly. Put it behind VPN or a jump host, require MFA, and monitor failed logins.',
  },
  rdp: {
    title: 'RDP service detected',
    summary:
      'RDP endpoints are frequently scanned on the internet and abused for lateral movement inside networks.',
    remediation:
      'Restrict access to trusted admin paths only and ensure strong authentication and patching.',
  },

  // --- SMB / file sharing ---
  445: {
    title: 'SMB file sharing exposed',
    summary:
      'SMB has a long history of critical bugs (like EternalBlue) and is a common lateral-movement channel.',
    remediation:
      'Limit SMB exposure to internal segments, disable legacy protocols, and tightly control shares and permissions.',
  },
  smb: {
    title: 'SMB service detected',
    summary:
      'Open SMB can leak file shares and be abused for credential relay or malware spreading.',
    remediation:
      'Segment file servers, restrict who can reach them, and monitor for unusual file access patterns.',
  },

  // --- Databases ---
  1433: {
    title: 'MSSQL database port exposed',
    summary:
      'Directly exposed database ports increase the chance of brute-force, injection, and exploit attempts.',
    remediation:
      'Place databases on internal-only segments and expose them via app tiers or bastion hosts rather than directly.',
  },
  mssql: {
    title: 'MSSQL service detected',
    summary:
      'Databases rarely need broad network exposure; compromise often leads to large data exfiltration.',
    remediation:
      'Restrict who can reach this DB, enforce strong auth, and use TLS plus least privilege for DB accounts.',
  },

  // --- VNC / remote consoles ---
  5900: {
    title: 'VNC remote desktop exposed',
    summary:
      'VNC often has weak or missing encryption and is frequently left with guessable passwords.',
    remediation:
      'Avoid exposing VNC directly; tunnel it over SSH/VPN, enforce strong credentials, or replace with more secure tooling.',
  },
  vnc: {
    title: 'VNC service detected',
    summary:
      'VNC endpoints are easy to brute-force and sometimes lack proper access controls.',
    remediation:
      'Lock down reachability, harden credentials, or migrate to a more secure remote access solution.',
  },

  // --- HTTP / generic web ---
  80: {
    title: 'Unencrypted HTTP exposed',
    summary:
      'Plain HTTP leaks credentials and session data in transit and is easy to intercept on hostile networks.',
    remediation:
      'Prefer HTTPS with modern TLS, redirect HTTP to HTTPS, and disable legacy ciphers and protocols.',
  },
  8080: {
    title: 'Alternate HTTP port exposed',
    summary:
      'Web services on high/alternate ports are often forgotten and left unpatched, but still reachable.',
    remediation:
      'Inventory and review all web services; apply the same hardening and patching as your main sites.',
  },
  http: {
    title: 'HTTP service detected',
    summary:
      'Web services are a primary attack surface for injection, auth bypass, and deserialization bugs.',
    remediation:
      'Review the app behind this service, apply patches, enable HTTPS, and run regular web security testing.',
  },
}


// Sample Nmap-style XML so you can test the UI immediately
export const SAMPLE_SCAN_XML = `<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -p 22,80,443,3389 192.168.1.1-3 10.0.0.5-6" start="1234567890">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="router.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
    </ports>
  </host>

  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
    <hostnames>
      <hostname name="rdp-host" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open" reason="syn-ack"/>
        <service name="ms-wbt-server"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>

  <host>
    <status state="down" reason="host-unreach"/>
    <address addr="192.168.1.3" addrtype="ipv4"/>
  </host>

  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="dev-box" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>

  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="db-server" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>
`

// Sample generic JSON format
export const SAMPLE_SCAN_JSON = JSON.stringify(
  {
    hosts: [
      {
        ip: '192.168.1.10',
        hostname: 'workstation-01',
        status: 'up',
        ports: [
          { port: 80, protocol: 'tcp', state: 'open', service: 'http' },
          { port: 443, protocol: 'tcp', state: 'open', service: 'https' },
        ],
      },
      {
        ip: '192.168.1.20',
        hostname: 'file-server',
        status: 'up',
        ports: [
          { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds' },
        ],
      },
      {
        ip: '10.0.0.5',
        hostname: 'dev-box',
        status: 'up',
        ports: [
          { port: 22, protocol: 'tcp', state: 'open', service: 'ssh' },
          { port: 8080, protocol: 'tcp', state: 'open', service: 'http-proxy' },
        ],
      },
      {
        ip: '10.0.0.10',
        hostname: 'db-server',
        status: 'up',
        ports: [
          { port: 3306, protocol: 'tcp', state: 'open', service: 'mysql' },
        ],
      },
    ],
  },
  null,
  2
)


// Used by both risk scoring and the UI
export function isHighRiskPortOrService(port) {
  if (!port) return false

  const isHighPort = HIGH_RISK_PORTS.includes(port.port)

  const svc = (port.service || '').toString().toLowerCase()
  const isHighService =
    svc &&
    HIGH_RISK_SERVICES.some((marker) => svc.includes(marker.toLowerCase()))

  return isHighPort || isHighService
}

function assessRisk(ports) {
  if (!ports || ports.length === 0) {
    return {
      riskLevel: 'low',
      riskReasons: [
        'No open ports detected from this scan vantage point.',
        'Host appears minimally exposed over the scanned ports.',
      ],
    }
  }

  const highPorts = ports.filter(isHighRiskPortOrService)

  if (highPorts.length > 0) {
    const labels = highPorts.map((p) => {
      const base = p.port ? String(p.port) : 'unknown-port'
      return p.service ? `${base} (${p.service})` : base
    })

    return {
      riskLevel: 'high',
      riskReasons: [
        `High-risk services or ports exposed: ${labels.join(', ')}.`,
        'These services are frequently targeted for remote access, brute-force attempts, and lateral movement.',
        'Consider restricting exposure (firewalling, VPN access only, or internal-only access).',
      ],
    }
  }

  return {
    riskLevel: 'medium',
    riskReasons: [
      'Open ports detected – verify that each service is required and hardened.',
      'Ensure access is restricted to trusted networks and strong authentication is enforced.',
    ],
  }
}

// ---------- Nmap XML parser (minimal subset) ----------

export function parseNmapXml(xmlString) {
  if (!xmlString || typeof xmlString !== 'string') {
    throw new Error('No XML content provided')
  }

  const parser = new DOMParser()
  const xmlDoc = parser.parseFromString(xmlString, 'application/xml')

  const parserError = xmlDoc.getElementsByTagName('parsererror')[0]
  if (parserError) {
    throw new Error('Invalid XML – unable to parse scan file')
  }

  const hostNodes = Array.from(xmlDoc.getElementsByTagName('host'))
  if (hostNodes.length === 0) {
    throw new Error('No <host> entries found in XML')
  }

  const hosts = hostNodes.map((hostEl, idx) => {
    // Status
    const statusEl = hostEl.getElementsByTagName('status')[0]
    const status = statusEl?.getAttribute('state') || 'unknown'

    // IP
    const addrEl = Array.from(
      hostEl.getElementsByTagName('address')
    ).find((a) => a.getAttribute('addrtype') === 'ipv4')
    const ip = addrEl?.getAttribute('addr') || 'unknown'

    // Hostname
    const hostnameEl = hostEl.getElementsByTagName('hostname')[0]
    const hostname = hostnameEl?.getAttribute('name') || null

    // Ports
    const portEls = hostEl.getElementsByTagName('port')
    const ports = Array.from(portEls)
      .map((portEl) => {
        const portId = parseInt(portEl.getAttribute('portid') || '0', 10)
        const protocol = portEl.getAttribute('protocol') || 'tcp'

        const stateEl = portEl.getElementsByTagName('state')[0]
        const state = stateEl?.getAttribute('state') || 'unknown'

        const serviceEl = portEl.getElementsByTagName('service')[0]
        const service = serviceEl?.getAttribute('name') || null

        return {
          port: portId,
          protocol,
          state,
          service,
        }
      })
      // We only care about open ports for now
      .filter((p) => p.state === 'open')

    const { riskLevel, riskReasons } = assessRisk(ports)

    return {
      id: `${ip}-${idx}`,
      ip,
      hostname,
      status,
      ports,
      riskLevel,
      riskReasons,
    }
  })

  return hosts
}

// ---------- Generic JSON parser ----------

export function parseGenericJson(jsonString) {
  if (!jsonString || typeof jsonString !== 'string') {
    throw new Error('No JSON content provided')
  }

  let data
  try {
    data = JSON.parse(jsonString)
  } catch {
    throw new Error('Invalid JSON – unable to parse scan file')
  }

  // Accept either { hosts: [...] } or [...] directly
  const hostArray = Array.isArray(data) ? data : data.hosts
  if (!Array.isArray(hostArray) || hostArray.length === 0) {
    throw new Error('JSON does not contain a "hosts" array')
  }

  const hosts = hostArray.map((host, idx) => {
    const ip = host.ip || 'unknown'
    const hostname = host.hostname || null
    const status = host.status || 'unknown'

    const ports = Array.isArray(host.ports)
      ? host.ports
          .map((p) => ({
            port:
              typeof p.port === 'number'
                ? p.port
                : parseInt(p.port || '0', 10),
            protocol: p.protocol || 'tcp',
            state: p.state || 'open',
            service: p.service || null,
          }))
          .filter((p) => p.state === 'open')
      : []

    const { riskLevel, riskReasons } = assessRisk(ports)

    return {
      id: `${ip}-${idx}`,
      ip,
      hostname,
      status,
      ports,
      riskLevel,
      riskReasons,
    }
  })

  return hosts
}

// ---------- Dispatcher ----------

/**
 * Detects XML vs JSON and uses the right parser.
 * Currently supports:
 *  - Nmap-style XML
 *  - Generic JSON { hosts: [...] } or [...]
 */
export function parseScanFile(rawContent) {
  if (!rawContent || typeof rawContent !== 'string') {
    throw new Error('File is empty')
  }

  const trimmed = rawContent.trim()

  if (!trimmed) {
    throw new Error('File is empty')
  }

  // Simple detection: if it starts with { or [, treat as JSON
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return parseGenericJson(trimmed)
  }

  // Fallback to XML
  return parseNmapXml(trimmed)
}
