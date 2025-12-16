import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import AboutSection from '../../components/AboutSection.jsx'
import { downloadTextFile } from '../../utils/exportUtils.js'
import {
  getTemp,
  setTemp,
} from '../../utils/storage.js'
import { runDetections } from './detections.js'
import MiniSiemOverviewTab from './MiniSiemOverviewTab.jsx'
import {
  parseTimestampValue,
  normalizeOutcome,
  toNumberOrNull,
  finalizeCanonicalEvent,
} from './normalizeEvent.js'

const TEMP_ADAPTER_KEY = 'sw_mini_adapter'
const TEMP_TTL_MS = 30 * 60 * 1000

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_LINES = 20_000;
const MAX_SEARCH_EVENTS = 10_000;

const TEMP_HOME_PREFIXES_KEY = 'sw_mini_homePrefixes'
const TEMP_GEO_MAPPING_KEY = 'sw_mini_geoMapping'
const TEMP_GEO_ENABLED_KEY = 'sw_mini_geoEnabled'

const TEMP_MIN_SEVERITY_KEY = 'sw_mini_minSeverity';

const TEMP_DETECTION_PRESET_KEY = 'sw_mini_detectionPreset'

// Utility
function qualityFromCoverage(coverage) {
  if (!coverage) {
    return { label: 'No data yet', level: 'none' }
  }

  const unit = coverage.coverageUnit || 'lines'

  const total =
    unit === 'records'
      ? Number(coverage.totalRecords || 0)
      : Number(coverage.totalLines || 0)

  const parsed =
    unit === 'records'
      ? Number(coverage.parsedRecords || 0)
      : Number(coverage.parsedLines || 0)

  if (!total) {
    return { label: 'No data yet', level: 'none' }
  }

  const parsedPct = (parsed / total) * 100

  if (parsedPct >= 80) return { label: 'Good', level: 'good' }
  if (parsedPct >= 50) return { label: 'Fair', level: 'fair' }
  return { label: 'Poor', level: 'poor' }
}

// ---------------- Geo mapping helpers ----------------

// Prefix-based IPv4 mapping
function parseGeoMapping(raw) {
  const trimmed = (raw || '').trim()
  if (!trimmed) {
    return { entries: [], error: null }
  }

  // JSON
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    try {
      const data = JSON.parse(trimmed)
      const arr = Array.isArray(data) ? data : [data]
      const entries = arr
        .map((item) => ({
          prefix: String(item.prefix || item.ipPrefix || '').trim(),
          country: String(item.country || item.geoCountry || '').trim(),
        }))
        .filter((e) => e.prefix && e.country)
      if (!entries.length) {
        return {
          entries: [],
          error:
            'Geo mapping JSON did not contain usable "prefix" and "country/geoCountry" fields.',
        }
      }
      return { entries, error: null }
    } catch (err) {
      return {
        entries: [],
        error: 'Failed to parse geo mapping JSON: ' + err.message,
      }
    }
  }

  // CSV-like
  const lines = trimmed.split(/\r?\n/)
  if (lines.length === 0) {
    return { entries: [], error: null }
  }

  const header = lines[0].split(',').map((h) => h.trim().toLowerCase())
  const ipIdx =
    header.indexOf('ipprefix') >= 0
      ? header.indexOf('ipprefix')
      : header.indexOf('prefix')
  const countryIdx =
    header.indexOf('geocountry') >= 0
      ? header.indexOf('geocountry')
      : header.indexOf('country')

  if (ipIdx < 0 || countryIdx < 0) {
    return {
      entries: [],
      error:
        'Geo mapping CSV must have "ipPrefix" and "geoCountry" (or "country") headers.',
    }
  }

  const entries = []
  for (let i = 1; i < lines.length; i++) {
    const row = lines[i].trim()
    if (!row) continue
    const cols = row.split(',').map((c) => c.trim())
    const prefix = cols[ipIdx]
    const country = cols[countryIdx]
    if (prefix && country) {
      entries.push({ prefix, country })
    }
  }

  if (!entries.length) {
    return {
      entries: [],
      error: 'Geo mapping CSV did not contain any valid rows.',
    }
  }

  return { entries, error: null }
}

function ipToCountry(ip, entries) {
  if (!ip || !Array.isArray(entries) || !entries.length) return null
  const ipStr = String(ip)

  let best = null
  let bestLen = -1

  for (const entry of entries) {
    const pref = String(entry?.prefix || '').trim()
    if (!pref) continue
    if (ipStr.startsWith(pref) && pref.length > bestLen) {
      best = entry.country
      bestLen = pref.length
    }
  }

  return best || null
}

// ---------------- Ingestion adapters ----------------

// JSONL/JSON adapter
const jsonlAdapter = {
  id: 'jsonl',
  label: 'JSON Lines / JSON array',
  detectScore(sampleLines) {
    let score = 0;
    let considered = 0;

    for (const line of sampleLines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      considered++;
      try {
        const obj = JSON.parse(trimmed);
        if (
          obj &&
          (
            obj.timestamp ||
            obj.time ||
            obj['@timestamp'] ||
            obj.ts ||
            obj.datetime ||
            obj.date ||
            obj.created_at ||
            obj.createdAt ||
            obj.event_timestamp ||
            obj.eventTimestamp
          )
        ) {
          score++;
        }
      } catch {
        // ignore
      }
    }

    if (!considered) return 0;
    const ratio = score / considered;
    // Cap
    return ratio * 0.5;
  },
  parse(lines, originId) {
    const events = [];
    const errors = [];
    const coverage = {
      coverageUnit: 'records',   
      totalLines: 0,
      parsedLines: 0,
      totalRecords: 0,
      parsedRecords: 0,
      withTimestamp: 0,
      withAuthCore: 0,
    }

    const allText = lines.join('\n');
    const trimmedAll = allText.trim();

    const isOktaOrigin = originId === 'okta'
    const isCloudTrail = originId === 'cloudtrail'
    const isAzureSignin = originId === 'azure-ad-signin'
    
    function buildDetails(obj) {
      if (!obj || typeof obj !== 'object') return ''

      // http
      if (obj.http && typeof obj.http === 'object') {
        const m = obj.http.method || obj.http.verb
        const p = obj.http.path || obj.http.uri
        const s = obj.http.status ?? obj.http.statusCode
        const lat = obj.http.latency_ms ?? obj.http.latency
        return [m, p, s != null ? `status=${s}` : null, lat != null ? `lat=${lat}ms` : null]
          .filter(Boolean)
          .join(' ')
      }

      // dns
      if (obj.dns && typeof obj.dns === 'object') {
        const q = obj.dns.qname
        const t = obj.dns.qtype
        const r = obj.dns.rcode
        return ['dns', q, t, r != null ? `rcode=${r}` : null].filter(Boolean).join(' ')
      }

      // network
      if (obj.network && typeof obj.network === 'object') {
        const proto = obj.network.proto
        const dp = obj.network.dst_port ?? obj.network.dest_port
        const bi = obj.network.bytes_in
        const bo = obj.network.bytes_out
        return ['net', proto, dp != null ? `dport=${dp}` : null, bi != null ? `in=${bi}` : null, bo != null ? `out=${bo}` : null]
          .filter(Boolean)
          .join(' ')
      }

      // process
      if (obj.process && typeof obj.process === 'object') {
        const n = obj.process.name
        const c = obj.process.cmdline
        return ['proc', n, c].filter(Boolean).join(' ')
      }

      // file
      if (obj.file && typeof obj.file === 'object') {
        const p = obj.file.path
        const b = obj.file.bytes
        return ['file', p, b != null ? `bytes=${b}` : null].filter(Boolean).join(' ')
      }

      return ''
    }

    function buildEventFromObj(obj, raw, index, kindLabel, defaultProfile) {
      if (!obj || typeof obj !== 'object') {
        return {
          event: null,
          error: `${kindLabel} ${index}: not a JSON object`,
        };
      }

      const tsRaw =
        obj.timestamp ||
        obj.time ||
        obj['@timestamp'] ||
        obj.ts ||
        obj.published ||
        obj.eventTime ||
        obj.TimeGenerated ||
        obj.timeGenerated ||
        obj.creationTime ||
        obj.datetime ||
        obj.date ||
        obj.created_at ||
        obj.createdAt ||
        obj.event_timestamp ||
        obj.eventTimestamp ||
        null;

      const ts = parseTimestampValue(tsRaw)

      if (!ts || Number.isNaN(ts.getTime())) {
        return {
          event: null,
          error: `${kindLabel} ${index}: missing or invalid timestamp "${tsRaw}"`,
        };
      }

      coverage.parsedRecords++
      coverage.withTimestamp++

      const sourceIp =
        obj.sourceIp ||
        obj.srcIp ||
        obj.src_ip ||
        obj.clientIp ||
        obj.client_ip ||
        obj.remoteIp ||
        obj.remote_ip ||
        obj.ip ||
        obj.ipAddress ||
        obj.ip_address ||
        (obj.client && (obj.client.ipAddress || 
          obj.client.ip || obj.client.ip_address)) ||
        (obj.request && (obj.request.ipAddress || 
          obj.request.ip || obj.request.ip_address)) ||
        obj.sourceIPAddress ||
        obj.sourceIpAddress ||
        obj.source_ip ||
        '';

      const destIp =
        obj.destIp ||
        obj.dstIp ||
        obj.dst_ip ||
        obj.destinationIp ||
        obj.destination_ip ||
        obj.dest_ip ||
        ''

      const destPort =
        (obj.network && (obj.network.dst_port ?? obj.network.dest_port)) ??
        obj.dst_port ??
        obj.dest_port ??
        obj.destinationPort ??
        obj.destination_port ??
        null

      const destPortNum = toNumberOrNull(destPort)

      const username =
        obj.username ||
        obj.user ||
        obj.account ||
        obj.accountName ||
        obj.principal ||
        // Okta
        (obj.actor &&
          (obj.actor.alternateId ||
           obj.actor.displayName ||
           obj.actor.login)) ||
        (Array.isArray(obj.target) &&
          obj.target.length > 0 &&
          (obj.target[0].alternateId ||
           obj.target[0].displayName ||
           obj.target[0].id)) ||
        // CloudTrail 
        (obj.userIdentity &&
          (obj.userIdentity.userName ||
           obj.userIdentity.arn ||
           obj.userIdentity.principalId)) ||
        // Azure 
        obj.UserPrincipalName ||
        obj.Identity ||
        '';

      const eventTypeRaw =
        obj.eventType ||
        obj.event_type || 
        obj.action ||
        obj.event ||
        obj.type ||
        obj.category ||
        obj.eventName || // CloudTrail
        obj.OperationName || // Azure
        '';
      const eventType = eventTypeRaw || 'event';

      const baseOutcome = obj.outcome || obj.result || '';
      const outcome = normalizeOutcome(baseOutcome, obj);

      if ((sourceIp || username) && outcome) {
        coverage.withAuthCore++;
      }

      const details = buildDetails(obj)

      // ---- Canonical field extraction (JSONL generic + structured telemetry) ----

      // http.*
      const httpObj = obj.http && typeof obj.http === 'object' ? obj.http : null
      const httpMethod = httpObj ? (httpObj.method || httpObj.verb || '') : ''
      const httpPath = httpObj ? (httpObj.path || httpObj.uri || httpObj.url || '') : ''
      const httpStatusRaw = httpObj ? (httpObj.status ?? httpObj.statusCode) : null
      const httpStatus = toNumberOrNull(httpStatusRaw)
      const latencyRaw = httpObj ? (httpObj.latency_ms ?? httpObj.latency) : null
      const latencyMs = toNumberOrNull(latencyRaw)

      // dns.*
      const dnsObj = obj.dns && typeof obj.dns === 'object' ? obj.dns : null
      const dnsQname = dnsObj ? (dnsObj.qname || dnsObj.query || '') : ''
      const dnsQtype = dnsObj ? (dnsObj.qtype || dnsObj.type || '') : ''
      const dnsRcode = dnsObj ? (dnsObj.rcode || dnsObj.response_code || '') : ''

      // network.*
      const netObj = obj.network && typeof obj.network === 'object' ? obj.network : null
      const bytesInRaw = netObj ? (netObj.bytes_in ?? netObj.bytesIn) : null
      const bytesOutRaw = netObj ? (netObj.bytes_out ?? netObj.bytesOut) : null
      const bytesIn = toNumberOrNull(bytesInRaw)
      const bytesOut = toNumberOrNull(bytesOutRaw)

      // process.*
      const procObj = obj.process && typeof obj.process === 'object' ? obj.process : null
      const processName = procObj ? (procObj.name || procObj.process_name || '') : ''
      const processCmd = procObj ? (procObj.cmdline || procObj.command || '') : ''

      // file.*
      const fileObj = obj.file && typeof obj.file === 'object' ? obj.file : null
      const filePath = fileObj ? (fileObj.path || fileObj.filepath || '') : ''
      const fileBytesRaw = fileObj ? (fileObj.bytes ?? fileObj.size) : null
      const fileBytes = toNumberOrNull(fileBytesRaw)

      // auth.*
      const authObj = obj.auth && typeof obj.auth === 'object' ? obj.auth : null
      const mfa = authObj && typeof authObj.mfa === 'boolean' ? authObj.mfa : null

      const ev = {
        // Prefer event_id if present
        id:
          (obj.event_id != null && String(obj.event_id).trim())
            ? String(obj.event_id).trim()
            : (obj.eventId != null && String(obj.eventId).trim())
            ? String(obj.eventId).trim()
            : (obj.id != null && String(obj.id).trim())
            ? String(obj.id).trim()
            : '',

        timestamp: ts,

        // Canonical identity-ish fields
        sourceIp: sourceIp || '',
        destIp: destIp || '',
        destPort: destPortNum,
        username: username || '',
        outcome,
        eventType,

        // Canonical telemetry fields
        httpMethod: httpMethod || '',
        httpPath: httpPath || '',
        httpStatus: Number.isFinite(httpStatus) ? httpStatus : null,
        latencyMs: Number.isFinite(latencyMs) ? latencyMs : null,

        dnsQname: dnsQname || '',
        dnsQtype: dnsQtype || '',
        dnsRcode: dnsRcode || '',

        bytesIn: Number.isFinite(bytesIn) ? bytesIn : null,
        bytesOut: Number.isFinite(bytesOut) ? bytesOut : null,

        processName: processName || '',
        processCmd: processCmd || '',

        filePath: filePath || '',
        fileBytes: Number.isFinite(fileBytes) ? fileBytes : null,

        mfa,

        raw,
        sourceApp: obj.sourceApp || obj.app || obj.tool || '',
        host: obj.host || obj.hostname || '',
        environment: obj.environment || obj.env || '',
        authMethod: obj.authMethod || '',
        geoCountry: obj.geoCountry || '',
        contextProfile: obj.contextProfile || defaultProfile,
        details,
      };      

      return { event: ev, error: null };
    }

    if (!trimmedAll) {
      return {
        events,
        errors,
        coverage,
        originGuess: 'JSON Lines / generic structured logs',
      };
    }

    const arrayProfile = isOktaOrigin
      ? 'okta-audit'
      : isCloudTrail
      ? 'aws-cloudtrail'
      : isAzureSignin
      ? 'azure-signin'
      : 'json-array';

    const jsonlProfile = isOktaOrigin
      ? 'okta-audit'
      : isCloudTrail
      ? 'aws-cloudtrail'
      : isAzureSignin
      ? 'azure-signin'
      : 'jsonl-generic';

    // Path 1: JSON array
    if (trimmedAll.startsWith('[')) {
      try {
        const data = JSON.parse(trimmedAll);
        if (Array.isArray(data)) {
          coverage.totalRecords = data.length

          for (let idx = 0; idx < data.length; idx++) {
            const obj = data[idx];
            const { event, error } = buildEventFromObj(
              obj,
              JSON.stringify(obj),
              idx + 1,
              'Item',
              arrayProfile,
            );
            if (error) errors.push(error);
            if (event) events.push(event);
          }

          return {
            events,
            errors,
            coverage,
            originGuess: 'JSON array / structured logs',
          };
        }
      } catch (err) {
        errors.push('Top-level JSON parse error: ' + err.message);
      }
    }

    // Path 2: JSON Lines
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (!trimmed) continue;

      coverage.totalRecords++;
      coverage.totalLines++;

      let obj;
      try {
        obj = JSON.parse(trimmed);
      } catch (err) {
        errors.push(`Line ${i + 1}: ${err.message}`);
        continue;
      }

      const { event, error } = buildEventFromObj(
        obj,
        line,
        i + 1,
        'Line',
        jsonlProfile,
      );
      if (error) errors.push(error);
      if (event) events.push(event);
    }

    coverage.parsedLines = coverage.parsedRecords;

    return {
      events,
      errors,
      coverage,
      originGuess: 'JSON Lines / generic structured logs',
    };
  },
};

// Okta (JSONL)
const oktaAdapter = {
  id: 'okta',
  label: 'Okta System Log (JSONL)',
  detectScore(sampleLines) {
    if (!sampleLines || !sampleLines.length) return 0;

    let considered = 0;
    let strongHits = 0;

    for (const line of sampleLines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) continue;

      considered++;
      try {
        const obj = JSON.parse(trimmed);
        if (!obj || typeof obj !== 'object') continue;

        const hasEventType = typeof obj.eventType === 'string';

        const actor = obj.actor || {};
        const hasActor =
          actor.alternateId ||
          actor.displayName ||
          actor.login ||
          actor.id;

        const client = obj.client || {};
        const request = obj.request || {};

        const hasClientIp =
          typeof client.ipAddress === 'string';

        const hasRequestIpAddress =
          typeof request.ipAddress === 'string';

        const ipChain = request.ipChain;
        const hasRequestIpChain =
          Array.isArray(ipChain) &&
          ipChain.length > 0 &&
          typeof ipChain[0].ip === 'string';

        const hasAnyIp = hasClientIp || hasRequestIpAddress || hasRequestIpChain;

        let scorePieces = 0;
        if (hasEventType) scorePieces++;
        if (hasActor) scorePieces++;
        if (hasAnyIp) scorePieces++;

        if (scorePieces >= 2) {
          strongHits++;
        }
      } catch {
        // ignore
      }
    }

    if (!considered) return 0;

    const ratio = strongHits / considered;

    // Push Okta
    if (ratio === 0) return 0;
    return 0.8 + 0.2 * ratio;
  },
  parse(lines) {
    // Reuse JSONL, label as Okta
    const base = jsonlAdapter.parse(lines);
    return {
      ...base,
      originGuess: 'Okta System Log (JSONL)',
    };
  },
};

// CloudTrail (JSONL/JSON array-ish)
const cloudtrailAdapter = {
  id: 'cloudtrail',
  label: 'AWS CloudTrail (JSON)',
  detectScore(sampleLines) {
    if (!sampleLines || !sampleLines.length) return 0;

    const joined = sampleLines.join('\n').trim();
    if (joined.startsWith('{') || joined.startsWith('[')) {
      try {
        const parsed = JSON.parse(joined);

        const records = Array.isArray(parsed)
          ? parsed
          : Array.isArray(parsed.Records)
          ? parsed.Records
          : null;

        if (records && records.length > 0 && typeof records[0] === 'object') {
          const first = records[0];

          const hasEventTime = typeof first.eventTime === 'string';
          const hasEventName = typeof first.eventName === 'string';
          const hasEventSource = typeof first.eventSource === 'string';
          const hasSourceIp = typeof first.sourceIPAddress === 'string';
          const hasUserIdentity = !!first.userIdentity;

          const pieces = [
            hasEventTime,
            hasEventName,
            hasEventSource,
            hasSourceIp,
            hasUserIdentity,
          ].filter(Boolean).length;

          if (pieces >= 3) {
            return 0.9;
          }
        }
      } catch {
        // ignore
      }
    }

    // Fallback
    let hits = 0;
    let considered = 0;

    for (const line of sampleLines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) continue;

      considered++;
      try {
        const obj = JSON.parse(trimmed);
        if (!obj || typeof obj !== 'object') continue;

        const hasEventTime = typeof obj.eventTime === 'string';
        const hasEventName = typeof obj.eventName === 'string';
        const hasEventSource = typeof obj.eventSource === 'string';
        const hasSourceIp = typeof obj.sourceIPAddress === 'string';
        const hasUserIdentity = !!obj.userIdentity;

        const scorePieces = [
          hasEventTime,
          hasEventName,
          hasEventSource,
          hasSourceIp,
          hasUserIdentity,
        ].filter(Boolean).length;

        if (scorePieces >= 3) {
          hits++;
        }
      } catch {
        // ignore
      }
    }

    if (!considered) return 0;
    const ratio = hits / considered;

    return ratio * 0.9;
  },
  parse(lines) {
    const base = jsonlAdapter.parse(lines);
    return {
      ...base,
      originGuess: 'AWS CloudTrail (JSON)',
    };
  },
};

// Azure (JSONL)
const azureAdAdapter = {
  id: 'azure-ad-signin',
  label: 'Azure AD sign-ins (JSON)',
  detectScore(sampleLines) {
    if (!sampleLines || !sampleLines.length) return 0;

    const joined = sampleLines.join('\n').trim();
    if (joined.startsWith('{') || joined.startsWith('[')) {
      try {
        const parsed = JSON.parse(joined);

        const records = Array.isArray(parsed)
          ? parsed
          : Array.isArray(parsed.value)
          ? parsed.value
          : null;

        if (records && records.length > 0 && typeof records[0] === 'object') {
          const first = records[0];

          const hasTime =
            typeof first.TimeGenerated === 'string' ||
            typeof first.timeGenerated === 'string';

          const hasUser =
            typeof first.UserPrincipalName === 'string' ||
            typeof first.userPrincipalName === 'string' ||
            typeof first.Identity === 'string';

          const hasIp =
            typeof first.IPAddress === 'string' ||
            typeof first.ipAddress === 'string';

          const hasResult =
            typeof first.ResultType === 'string' ||
            typeof first.ResultDescription === 'string';

          const pieces = [hasTime, hasUser, hasIp, hasResult].filter(Boolean).length;

          if (pieces >= 3) {
            return 0.9;
          }
        }
      } catch {
        // ignore
      }
    }

    // Fallback
    let hits = 0;
    let considered = 0;

    for (const line of sampleLines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) continue;

      considered++;
      try {
        const obj = JSON.parse(trimmed);
        if (!obj || typeof obj !== 'object') continue;

        const hasTime =
          typeof obj.TimeGenerated === 'string' ||
          typeof obj.timeGenerated === 'string';

        const hasUser =
          typeof obj.UserPrincipalName === 'string' ||
          typeof obj.userPrincipalName === 'string' ||
          typeof obj.Identity === 'string';

        const hasIp =
          typeof obj.IPAddress === 'string' ||
          typeof obj.ipAddress === 'string';

        const hasResult =
          typeof obj.ResultType === 'string' ||
          typeof obj.ResultDescription === 'string';

        const scorePieces = [hasTime, hasUser, hasIp, hasResult].filter(Boolean).length;

        if (scorePieces >= 3) {
          hits++;
        }
      } catch {
        // ignore
      }
    }

    if (!considered) return 0;
    const ratio = hits / considered;

    return ratio > 0 ? 0.8 + 0.2 * ratio : 0;
  },
  parse(lines) {
    const base = jsonlAdapter.parse(lines);
    return {
      ...base,
      originGuess: 'Azure AD sign-ins (JSON)',
    };
  },
};

// Linux auth/syslog (sshd-like)
const linuxAuthAdapter = {
  id: 'linux-auth',
  label: 'Linux SSH / auth.log',
  detectScore(sampleLines) {
    let hits = 0
    let considered = 0
    for (const line of sampleLines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      considered++
      if (
        /sshd/.test(trimmed) &&
        /(Failed password|Accepted (password|publickey|keyboard-interactive))/i.test(trimmed)
      ) {
        hits++
      }
    }
    if (!considered) return 0
    return hits / considered
  },

  parse(lines) {
    const events = []
    const errors = []
    const coverage = {
      coverageUnit: 'lines',
      totalLines: 0,
      parsedLines: 0,
      withTimestamp: 0,
      withAuthCore: 0,
    }

    const monthMap = {
      Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
      Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
    }

    // --- minimal monotonic year handling (LOCAL TIME) ---
    const now = new Date()
    let currentYear = now.getFullYear()
    let lastTs = null
    const ROLLOVER_GUARD_MS = 12 * 60 * 60 * 1000 // 12 hours
    // ----------------------------------------------------

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      const trimmed = line.trim()
      if (!trimmed) continue
      coverage.totalLines++

      const m = trimmed.match(
        /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)(?:\[\d+\])?:\s+(.*)$/,
      )
      if (!m) continue

      const [, monStr, dayStr, timeStr, host, , msg] = m
      if (!(monStr in monthMap)) continue

      const monthIdx = monthMap[monStr]
      const day = Number(dayStr)
      if (!Number.isFinite(day) || day < 1 || day > 31) continue

      const hh = Number(timeStr.slice(0, 2))
      const mm = Number(timeStr.slice(3, 5))
      const ss = Number(timeStr.slice(6, 8))
      if (![hh, mm, ss].every(Number.isFinite)) continue

      // Build timestamp in LOCAL time (not UTC)
      let ts = new Date(currentYear, monthIdx, day, hh, mm, ss)
      if (Number.isNaN(ts.getTime())) continue

      // If time goes "backwards" a lot, assume year rollover (Dec -> Jan)
      if (lastTs && ts.getTime() + ROLLOVER_GUARD_MS < lastTs.getTime()) {
        currentYear += 1
        ts = new Date(currentYear, monthIdx, day, hh, mm, ss)
        if (Number.isNaN(ts.getTime())) continue
      }
      lastTs = ts

      coverage.parsedLines++
      coverage.withTimestamp++

      let eventType = 'login'
      let outcome = ''
      let username = ''
      let sourceIp = ''

      let mmatch =
        msg.match(/Failed password for (invalid user )?(\S+) from ([\d.:a-fA-F]+) /) ||
        msg.match(/Failed password for (\S+) from ([\d.:a-fA-F]+) port /)

      if (mmatch) {
        outcome = 'fail'
        username = mmatch[2] || mmatch[1] || ''
        sourceIp = mmatch[3] || mmatch[2] || ''
      } else {
        mmatch = msg.match(
          /Accepted (password|publickey|keyboard-interactive\/pam) for (\S+) from ([\d.:a-fA-F]+) /,
        )
        if (mmatch) {
          outcome = 'success'
          username = mmatch[2] || ''
          sourceIp = mmatch[3] || ''
        }
      }

      if (!outcome) continue

      if ((sourceIp || username) && outcome) {
        coverage.withAuthCore++
      }

      events.push({
        id: '',
        timestamp: ts,
        sourceIp: sourceIp || '',
        username: username || '',
        eventType,
        outcome,
        raw: line,
        sourceApp: 'sshd',
        host,
        environment: '',
        authMethod: '',
        geoCountry: '',
        contextProfile: 'linux-ssh',
      })
    }

    return {
      events,
      errors,
      coverage,
      originGuess: 'Linux SSH / auth.log-style syslog',
    }
  },
}


// Apache/Nginx (approximate)
const apacheAccessAdapter = {
  id: 'apache-access',
  label: 'Web server access logs (Apache/Nginx)',
  detectScore(sampleLines) {
    let hits = 0
    let considered = 0
    const httpMethodRe =
      /^(\S+) \S+ \S+ \[[^\]]+\] "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^"]*" (\d{3}) /
    for (const line of sampleLines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      considered++
      if (httpMethodRe.test(trimmed)) hits++
    }
    if (!considered) return 0
    return hits / considered
  },
  parse(lines) {
    const events = []
    const errors = []
    const coverage = {
      coverageUnit: 'lines',
      totalLines: 0,
      parsedLines: 0,
      withTimestamp: 0,
      withAuthCore: 0,
    }

    const re =
      /^(\S+) \S+ (\S+) \[([^\]]+)] "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^"]*)" (\d{3}) [^ ]*(?: "([^"]*)" "([^"]*)")?/

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      const trimmed = line.trim()
      if (!trimmed) continue
      coverage.totalLines++

      const m = trimmed.match(re)
      if (!m) continue

      const [
        ,
        ip,
        userField,
        dateStr,
        method,
        path,
        statusStr,
        referrer,
        ua,
      ] = m

      let ts = new Date(dateStr.replace(/:/, ' '))
      if (Number.isNaN(ts.getTime())) {
        // fallback
        ts = new Date(dateStr)
      }
      if (Number.isNaN(ts.getTime())) {
        errors.push(
          `Line ${i + 1}: could not parse timestamp "${dateStr}"`,
        )
        continue
      }

      coverage.parsedLines++
      coverage.withTimestamp++

      const status = Number(statusStr)
      const outcome =
        Number.isFinite(status) && status >= 200 && status < 400
          ? 'success'
          : 'fail'

      const username = userField !== '-' ? userField : ''
      if ((ip || username) && outcome) {
        coverage.withAuthCore++
      }

      const ev = {
        id: '',
        timestamp: ts,
        sourceIp: ip || '',
        username,
        eventType: 'web_access',
        outcome,
        raw: line,
        sourceApp: 'apache-nginx',
        host: '',
        environment: '',
        authMethod: '',
        geoCountry: '',
        contextProfile: 'web-server',
        userAgent: ua || '',
        referrer: referrer || '',
        method,
        path,
        status,
        // Canonical fields
        httpMethod: method || '',
        httpPath: path || '',
        httpStatus: Number.isFinite(status) ? status : null,
      }

      events.push(ev)
    }

    return {
      events,
      errors,
      coverage,
      originGuess: 'Apache/Nginx-style web access logs',
    }
  },
}

// Generic CSV
const genericCsvAdapter = {
  id: 'csv-generic',
  label: 'Generic CSV (timestamp/ip/user)',
  detectScore(sampleLines) {
    if (!sampleLines || !sampleLines.length) return 0;

    const first = sampleLines.find((l) => l.trim());
    if (!first) return 0;

    const header = first.trim();
    if (header.startsWith('{') || header.startsWith('[')) return 0;
    if (!header.includes(',')) return 0;

    const cols = header.split(',').map((c) => c.trim().toLowerCase());
    const hasTs = cols.some((c) =>
      ['timestamp', 'time', 'ts', '@timestamp', 'datetime'].includes(c),
    );
    const hasUser = cols.some((c) =>
      ['user', 'username', 'account', 'principal'].includes(c),
    );
    const hasIp = cols.some((c) =>
      ['ip', 'sourceip', 'srcip', 'clientip', 'remote_addr'].includes(c),
    );

    let score = 0;
    if (hasTs) score += 0.5;
    if (hasUser) score += 0.2;
    if (hasIp) score += 0.2;

    // Cap
    return score * 0.6;
  },
  parse(lines) {
    const events = [];
    const errors = [];
    const coverage = {
      coverageUnit: 'lines',
      totalLines: 0,
      parsedLines: 0,
      withTimestamp: 0,
      withAuthCore: 0,
    };

    if (!lines || !lines.length) {
      return {
        events,
        errors,
        coverage,
        originGuess: 'Generic CSV',
      };
    }

    const headerLine = lines[0].trim();
    const headerCols = headerLine.split(',').map((h) => h.trim());
    const headerLower = headerCols.map((h) => h.toLowerCase());

    const idxTs = headerLower.findIndex((h) =>
      ['timestamp', 'time', 'ts', '@timestamp', 'datetime'].includes(h),
    );
    const idxIp = headerLower.findIndex((h) =>
      ['ip', 'sourceip', 'srcip', 'clientip', 'remote_addr'].includes(h),
    );
    const idxUser = headerLower.findIndex((h) =>
      ['user', 'username', 'account', 'principal'].includes(h),
    );
    const idxType = headerLower.findIndex((h) =>
      ['event', 'eventtype', 'action', 'type'].includes(h),
    );
    const idxStatus = headerLower.findIndex((h) =>
      ['status', 'result', 'outcome', 'http_status'].includes(h),
    );

    if (idxTs < 0) {
      return {
        events,
        errors: [
          'Generic CSV adapter could not find a timestamp/time column in the header.',
        ],
        coverage,
        originGuess: 'Generic CSV',
      };
    }

    for (let i = 1; i < lines.length; i++) {
      const row = lines[i].trim();
      if (!row) continue;
      coverage.totalLines++;

      const cols = row.split(',').map((c) =>
        c.replace(/^"|"$/g, '').replace(/""/g, '"').trim(),
      );

      const tsRaw = cols[idxTs];
      let ts = tsRaw ? new Date(tsRaw) : null;

      // Epoch fallback
      if ((!ts || Number.isNaN(ts.getTime())) && tsRaw && /^\d+$/.test(tsRaw)) {
        const num = Number(tsRaw);
        if (tsRaw.length === 10) ts = new Date(num * 1000);
        else if (tsRaw.length === 13) ts = new Date(num);
      }

      if (!ts || Number.isNaN(ts.getTime())) {
        errors.push(
          `Line ${i + 1}: missing or invalid timestamp "${tsRaw}"`,
        );
        continue;
      }

      coverage.parsedLines++;
      coverage.withTimestamp++;

      const sourceIp = idxIp >= 0 ? cols[idxIp] : '';
      const username = idxUser >= 0 ? cols[idxUser] : '';
      const eventType =
        idxType >= 0 ? cols[idxType] || 'event' : 'event';

      let outcome = '';
      if (idxStatus >= 0) {
        const rawStatus = cols[idxStatus];
        const statusNum = Number(rawStatus);
        if (Number.isFinite(statusNum)) {
          outcome =
            statusNum >= 200 && statusNum < 400 ? 'success' : 'fail';
        } else if (
          /success/i.test(rawStatus || '')
        ) {
          outcome = 'success';
        } else if (
          /(fail|error|denied|unauthorized)/i.test(rawStatus || '')
        ) {
          outcome = 'fail';
        }
      }

      if ((sourceIp || username) && outcome) {
        coverage.withAuthCore++;
      }

      const ev = {
        id: '',
        timestamp: ts,
        sourceIp: sourceIp || '',
        username: username || '',
        eventType,
        outcome: outcome || '',
        raw: row,
        host: '',
        sourceApp: '',
        environment: '',
        authMethod: '',
        geoCountry: '',
        contextProfile: 'csv-generic',
      };

      events.push(ev);
    }

    return {
      events,
      errors,
      coverage,
      originGuess: 'Generic CSV (timestamp/ip/user)',
    };
  },
};

// Generic key=value
const kvPairAdapter = {
  id: 'kv-generic',
  label: 'Key=value log lines',
  detectScore(sampleLines) {
    if (!sampleLines || !sampleLines.length) return 0;

    let hits = 0;
    let considered = 0;

    const kvRe = /(\w+)=("[^"]*"|\S+)/g;

    for (const line of sampleLines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) continue; // likely JSON

      considered++;
      let matchCount = 0;
      while (kvRe.exec(trimmed) !== null) {
        matchCount++;
        if (matchCount >= 3) break;
      }
      if (matchCount >= 3) hits++;
    }

    if (!considered) return 0;
    const ratio = hits / considered;

    // Cap
    return ratio * 0.6;
  },
  parse(lines) {
    const events = [];
    const errors = [];
    const coverage = {
      coverageUnit: 'lines',
      totalLines: 0,
      parsedLines: 0,
      withTimestamp: 0,
      withAuthCore: 0,
    };

    if (!lines || !lines.length) {
      return {
        events,
        errors,
        coverage,
        originGuess: 'Key=value logs',
      };
    }

    const kvRe = /(\w+)=("[^"]*"|\S+)/g;

    function parseTimestamp(raw) {
      if (!raw) return null;
      let ts = new Date(raw);
      if (!Number.isNaN(ts.getTime())) return ts;

      if (/^\d+$/.test(raw)) {
        const num = Number(raw);
        if (raw.length === 10) ts = new Date(num * 1000);
        else if (raw.length === 13) ts = new Date(num);
        if (!Number.isNaN(ts.getTime())) return ts;
      }

      return null;
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (!trimmed) continue;
      coverage.totalLines++

      const obj = {};
      let m;
      while ((m = kvRe.exec(trimmed)) !== null) {
        const key = m[1];
        let value = m[2];
        if (value.startsWith('"') && value.endsWith('"')) {
          value = value.slice(1, -1).replace(/""/g, '"');
        }
        obj[key] = value;
      }

      if (Object.keys(obj).length === 0) continue;

      const tsRaw =
        obj.timestamp ||
        obj.time ||
        obj.ts ||
        obj['@timestamp'] ||
        obj.datetime ||
        obj.date ||
        null;

      const ts = parseTimestamp(tsRaw);
      if (!ts || Number.isNaN(ts.getTime())) {
        errors.push(
          `Line ${i + 1}: missing or invalid timestamp "${tsRaw ?? ''}"`,
        );
        continue;
      }

      coverage.parsedLines++;
      coverage.withTimestamp++;

      const sourceIp =
        obj.sourceIp ||
        obj.srcIp ||
        obj.clientIp ||
        obj.ip ||
        obj.remote_addr ||
        '';
      const username =
        obj.username ||
        obj.user ||
        obj.account ||
        obj.accountName ||
        obj.principal ||
        '';
      const eventType =
        obj.eventType ||
        obj.action ||
        obj.event ||
        obj.type ||
        'event';

      let outcome = obj.outcome || '';
      if (!outcome && obj.status) {
        const statusNum = Number(obj.status);
        if (Number.isFinite(statusNum)) {
          outcome =
            statusNum >= 200 && statusNum < 400 ? 'success' : 'fail';
        } else if (/success/i.test(obj.status)) {
          outcome = 'success';
        } else if (/(fail|error|denied|unauthorized)/i.test(obj.status)) {
          outcome = 'fail';
        }
      }

      if ((sourceIp || username) && outcome) {
        coverage.withAuthCore++;
      }

      const ev = {
        id: '',
        timestamp: ts,
        sourceIp: sourceIp || '',
        username: username || '',
        eventType: String(eventType),
        outcome: String(outcome || ''),
        raw: line,
        sourceApp: obj.app || obj.service || '',
        host: obj.host || obj.hostname || '',
        environment: obj.env || obj.environment || '',
        authMethod: obj.authMethod || '',
        geoCountry: obj.geoCountry || '',
        contextProfile: 'kv-generic',
      };

      events.push(ev);
    }

    return {
      events,
      errors,
      coverage,
      originGuess: 'Key=value style logs',
    };
  },
};

// Windows Security (JSON/CSV-ish, 4624/4625 focus)
const windowsSecurityAdapter = {
  id: 'windows-security',
  label: 'Windows Security (4624/4625)',
  detectScore(sampleLines) {
    let hits = 0
    let considered = 0
    if (!sampleLines || !sampleLines.length) return 0

    const first = sampleLines[0].trim().toLowerCase()
    if (first.includes('eventid') && (first.includes('timecreated') || first.includes('timegenerated'))) {
      return 1
    }

    for (const line of sampleLines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      considered++
      if (
        /"EventID"\s*:\s*462[45]/.test(trimmed) ||
        /\b462[45]\b/.test(trimmed) ||
        /An account (was successfully logged on|failed to log on)/i.test(
          trimmed,
        )
      ) {
        hits++
      }
    }
    if (!considered) return 0
    return hits / considered
  },
  parse(lines) {
    const events = []
    const errors = []
    const coverage = {
      coverageUnit: 'lines',
      totalLines: 0,
      parsedLines: 0,
      withTimestamp: 0,
      withAuthCore: 0,
    }

    const allText = lines.join('\n').trim()
    if (!allText) {
      return {
        events,
        errors,
        coverage,
        originGuess: 'Windows Security logs',
      }
    }

    // Helper
    function fromWinObj(obj, indexHint) {
      const tsRaw =
        obj.TimeCreated ||
        obj.timeCreated ||
        obj.TimeGenerated ||
        obj.timestamp ||
        obj['@timestamp'] ||
        null
      const ts = tsRaw ? new Date(tsRaw) : null
      if (!ts || Number.isNaN(ts.getTime())) {
        return null
      }

      let eventId =
        obj.EventID ||
        obj.eventId ||
        obj.event_id ||
        obj.Id ||
        obj.id ||
        ''
      if (eventId == null) eventId = ''
      const eventIdStr = String(eventId).trim()

      const username =
        obj.TargetUserName ||
        obj.AccountName ||
        obj.account ||
        obj.user ||
        obj.username ||
        ''
      const sourceIp =
        obj.IpAddress ||
        obj.ipAddress ||
        obj.IpAddr ||
        obj.sourceIp ||
        obj.srcIp ||
        obj.client_ip ||
        ''

      let eventType = 'login'
      let outcome = ''
      if (eventIdStr === '4624') {
        outcome = 'success'
      } else if (eventIdStr === '4625') {
        outcome = 'fail'
      } else if (
        /An account was successfully logged on/i.test(obj.Message || '') ||
        /An account failed to log on/i.test(obj.Message || '')
      ) {
        // Fallback
        outcome = /successfully/.test(obj.Message || '')
          ? 'success'
          : 'fail'
      }

      if (!outcome && !username && !sourceIp) {
        return null
      }

      coverage.parsedLines++
      coverage.withTimestamp++
      if ((username || sourceIp) && outcome) {
        coverage.withAuthCore++
      }

      return {
        id: '',
        index: indexHint,
        timestamp: ts,
        sourceIp: sourceIp || '',
        username: username || '',
        eventType,
        outcome,
        raw: JSON.stringify(obj),
        sourceApp: obj.ProviderName || obj.provider || 'windows-security',
        host:
          obj.Computer ||
          obj.computer ||
          obj.MachineName ||
          obj.host ||
          '',
        environment: '',
        authMethod:
          obj.LogonType != null
            ? `LogonType=${obj.LogonType}`
            : '',
        geoCountry: obj.geoCountry || '',
        contextProfile: 'windows-security',
        eventId: eventIdStr,
      }
    }

    // Path 1: JSON (array or single object/wrapper)
    if (allText.startsWith('{') || allText.startsWith('[')) {
      try {
        const parsed = JSON.parse(allText)
        let arr = []
        if (Array.isArray(parsed)) {
          arr = parsed
        } else if (Array.isArray(parsed.Records)) {
          arr = parsed.Records
        } else if (Array.isArray(parsed.events)) {
          arr = parsed.events
        } else {
          arr = [parsed]
        }

        for (let i = 0; i < arr.length; i++) {
          const obj = arr[i]
          if (!obj || typeof obj !== 'object') {
            coverage.totalLines++
            continue
          }
          coverage.totalLines++
          const ev = fromWinObj(obj, i + 1)
          if (ev) events.push(ev)
        }

        return {
          events,
          errors,
          coverage,
          originGuess: 'Windows Security JSON',
        }
        } catch (err) {
          errors.push('Windows JSON parse error: ' + err.message)

          // Fallback
          const jsonLines = allText.split(/\r?\n/).filter((l) => l.trim())

          for (let i = 0; i < jsonLines.length; i++) {
            const line = jsonLines[i]
            coverage.totalLines++
            try {
              const obj = JSON.parse(line)
              const ev = fromWinObj(obj, i + 1)
              if (ev) events.push(ev)
            } catch (e2) {
              errors.push(`Line ${i + 1}: ${e2.message}`)
            }
          }

          if (events.length > 0) {
            return {
              events,
              errors,
              coverage,
              originGuess: 'Windows Security JSON',
            }
          }
        }
    }

    // Path 2: CSV-like Windows export
    const csvLines = allText.split(/\r?\n/)
    if (!csvLines.length) {
      return {
        events,
        errors,
        coverage,
        originGuess: 'Windows Security logs',
      }
    }

    const headerLine = csvLines[0].trim()
    const headerCols = headerLine.split(',').map((h) => h.trim())
    const headerLower = headerCols.map((h) => h.toLowerCase())

    const idxTime =
      headerLower.indexOf('timecreated') >= 0
        ? headerLower.indexOf('timecreated')
        : headerLower.indexOf('timegenerated') >= 0
        ? headerLower.indexOf('timegenerated')
        : headerLower.indexOf('timestamp')
    const idxEventId =
      headerLower.indexOf('eventid') >= 0
        ? headerLower.indexOf('eventid')
        : headerLower.indexOf('id')
    const idxUser =
      headerLower.indexOf('targetusername') >= 0
        ? headerLower.indexOf('targetusername')
        : headerLower.indexOf('accountname') >= 0
        ? headerLower.indexOf('accountname')
        : headerLower.indexOf('user') >= 0
        ? headerLower.indexOf('user')
        : headerLower.indexOf('username')
    const idxIp =
      headerLower.indexOf('ipaddress') >= 0
        ? headerLower.indexOf('ipaddress')
        : headerLower.indexOf('sourceip') >= 0
        ? headerLower.indexOf('sourceip')
        : headerLower.indexOf('srcip')

    for (let i = 1; i < csvLines.length; i++) {
      const row = csvLines[i].trim()
      if (!row) continue
      coverage.totalLines++

      const cols = row.split(',').map((c) => c.trim())
      const tsRaw =
        idxTime != null && idxTime >= 0 ? cols[idxTime] : null
      const ts = tsRaw ? new Date(tsRaw) : null
      if (!ts || Number.isNaN(ts.getTime())) {
        continue
      }

      let eventId =
        idxEventId != null && idxEventId >= 0
          ? cols[idxEventId]
          : ''
      if (eventId == null) eventId = ''
      const eventIdStr = String(eventId).trim()

      const username =
        idxUser != null && idxUser >= 0 ? cols[idxUser] : ''
      const sourceIp =
        idxIp != null && idxIp >= 0 ? cols[idxIp] : ''

      let outcome = ''
      let eventType = 'login'
      if (eventIdStr === '4624') {
        outcome = 'success'
      } else if (eventIdStr === '4625') {
        outcome = 'fail'
      }

      if (!outcome && !username && !sourceIp) {
        continue
      }

      coverage.parsedLines++
      coverage.withTimestamp++
      if ((username || sourceIp) && outcome) {
        coverage.withAuthCore++
      }

      const ev = {
        id: '',
        index: i,
        timestamp: ts,
        sourceIp: sourceIp || '',
        username: username || '',
        eventType,
        outcome,
        raw: row,
        sourceApp: 'windows-security',
        host: '',
        environment: '',
        authMethod: '',
        geoCountry: '',
        contextProfile: 'windows-security',
        eventId: eventIdStr,
      }

      events.push(ev)
    }

    return {
      events,
      errors,
      coverage,
      originGuess: 'Windows Security CSV',
    }
  },
}

// Mini SIEM CSV (round-trip)
const miniSiemCsvAdapter = {
  id: 'mini-siem-csv',
  label: 'Mini SIEM CSV export',
  detectScore(sampleLines) {
    if (!sampleLines || !sampleLines.length) return 0
    const first = sampleLines[0].trim().toLowerCase()
    const cols = first.split(',').map((s) => s.trim())

    const hasCore =
      cols.includes('id') &&
      cols.includes('timestamp') &&
      cols.includes('sourceip') &&
      cols.includes('eventtype') &&
      cols.includes('outcome')

    return hasCore ? 1 : 0
  },
  parse(lines) {
    const events = []
    const errors = []
    const coverage = {
      coverageUnit: 'lines',
      totalLines: 0,
      parsedLines: 0,
      withTimestamp: 0,
      withAuthCore: 0,
    }

    if (!lines || !lines.length) {
      return {
        events,
        errors,
        coverage,
        originGuess: 'Mini SIEM CSV',
      }
    }

    const headerLine = lines[0].trim()
    const headerCols = headerLine.split(',').map((h) => h.trim())
    const headerLower = headerCols.map((h) => h.toLowerCase())

    const idxId = headerLower.indexOf('id')
    const idxTs = headerLower.indexOf('timestamp')
    const idxIp = headerLower.indexOf('sourceip')
    const idxUser = headerLower.indexOf('username')
    const idxType = headerLower.indexOf('eventtype')
    const idxOutcome = headerLower.indexOf('outcome')
    const idxHost = headerLower.indexOf('host')
    const idxApp = headerLower.indexOf('sourceapp')
    const idxGeo = headerLower.indexOf('geocountry')

    const idxDestIp = headerLower.indexOf('destip')
    const idxDestPort = headerLower.indexOf('destport')
    const idxMfa = headerLower.indexOf('mfa')

    const idxHttpMethod = headerLower.indexOf('httpmethod')
    const idxHttpPath = headerLower.indexOf('httppath')
    const idxHttpStatus = headerLower.indexOf('httpstatus')
    const idxLatencyMs = headerLower.indexOf('latencyms')

    const idxDnsQname = headerLower.indexOf('dnsqname')
    const idxDnsQtype = headerLower.indexOf('dnsqtype')
    const idxDnsRcode = headerLower.indexOf('dnsrcode')

    const idxBytesIn = headerLower.indexOf('bytesin')
    const idxBytesOut = headerLower.indexOf('bytesout')

    const idxProcessName = headerLower.indexOf('processname')
    const idxProcessCmd = headerLower.indexOf('processcmd')

    const idxFilePath = headerLower.indexOf('filepath')
    const idxFileBytes = headerLower.indexOf('filebytes')

    const idxEnv = headerLower.indexOf('environment')
    const idxAuth = headerLower.indexOf('authmethod')
    const idxProfile = headerLower.indexOf('contextprofile')
    const idxDetails = headerLower.indexOf('details')

    for (let i = 1; i < lines.length; i++) {
      const row = lines[i].trim()
      if (!row) continue
      coverage.totalLines++

      const cols = row.split(',').map((c) =>
        c.replace(/^"|"$/g, '').replace(/""/g, '"').trim(),
      )

      const tsRaw =
        idxTs != null && idxTs >= 0 ? cols[idxTs] : null
      const ts = tsRaw ? new Date(tsRaw) : null
      if (!ts || Number.isNaN(ts.getTime())) {
        continue
      }

      coverage.parsedLines++
      coverage.withTimestamp++

      const id =
        idxId != null && idxId >= 0 ? cols[idxId] : ''
      const sourceIp =
        idxIp != null && idxIp >= 0 ? cols[idxIp] : ''
      const username =
        idxUser != null && idxUser >= 0 ? cols[idxUser] : ''
      const eventType =
        idxType != null && idxType >= 0 ? cols[idxType] : 'event'
      const outcome =
        idxOutcome != null && idxOutcome >= 0 ?
          cols[idxOutcome] :
          ''
          
      const destIp = idxDestIp >= 0 ? cols[idxDestIp] : ''
      const destPortRaw = idxDestPort >= 0 ? cols[idxDestPort] : ''
      const destPort = toNumberOrNull(destPortRaw)

      const mfaRaw = idxMfa >= 0 ? cols[idxMfa] : ''
      const mfa =
        mfaRaw === 'true' ? true : mfaRaw === 'false' ? false : null

      const httpStatus = toNumberOrNull(idxHttpStatus >= 0 ? cols[idxHttpStatus] : null)
      const latencyMs = toNumberOrNull(idxLatencyMs >= 0 ? cols[idxLatencyMs] : null)

      const bytesIn = toNumberOrNull(idxBytesIn >= 0 ? cols[idxBytesIn] : null)
      const bytesOut = toNumberOrNull(idxBytesOut >= 0 ? cols[idxBytesOut] : null)

      const fileBytes = toNumberOrNull(idxFileBytes >= 0 ? cols[idxFileBytes] : null)    

      if ((sourceIp || username) && outcome) {
        coverage.withAuthCore++
      }

      const ev = {
        id: id || '',
        timestamp: ts,

        sourceIp: sourceIp || '',
        destIp: destIp || '',
        destPort,

        username: username || '',
        eventType,
        outcome,

        mfa,

        httpMethod: idxHttpMethod >= 0 ? cols[idxHttpMethod] : '',
        httpPath: idxHttpPath >= 0 ? cols[idxHttpPath] : '',
        httpStatus: Number.isFinite(httpStatus) ? httpStatus : null,
        latencyMs: Number.isFinite(latencyMs) ? latencyMs : null,

        dnsQname: idxDnsQname >= 0 ? cols[idxDnsQname] : '',
        dnsQtype: idxDnsQtype >= 0 ? cols[idxDnsQtype] : '',
        dnsRcode: idxDnsRcode >= 0 ? cols[idxDnsRcode] : '',

        bytesIn: Number.isFinite(bytesIn) ? bytesIn : null,
        bytesOut: Number.isFinite(bytesOut) ? bytesOut : null,

        processName: idxProcessName >= 0 ? cols[idxProcessName] : '',
        processCmd: idxProcessCmd >= 0 ? cols[idxProcessCmd] : '',

        filePath: idxFilePath >= 0 ? cols[idxFilePath] : '',
        fileBytes: Number.isFinite(fileBytes) ? fileBytes : null,

        host: idxHost >= 0 ? cols[idxHost] : '',
        sourceApp: idxApp >= 0 ? cols[idxApp] : '',
        environment: idxEnv >= 0 ? cols[idxEnv] : '',
        authMethod: idxAuth >= 0 ? cols[idxAuth] : '',
        geoCountry: idxGeo >= 0 ? cols[idxGeo] : '',
        contextProfile: idxProfile >= 0 ? cols[idxProfile] : 'mini-siem-csv',
        details: idxDetails >= 0 ? cols[idxDetails] : '',

        raw: row,
      }

      events.push(ev)
    }

    return {
      events,
      errors,
      coverage,
      originGuess: 'Mini SIEM CSV export',
    }
  },
}

const ADAPTERS = [
  oktaAdapter,
  cloudtrailAdapter,
  azureAdAdapter,
  jsonlAdapter,
  linuxAuthAdapter,
  apacheAccessAdapter,
  windowsSecurityAdapter,
  genericCsvAdapter,
  kvPairAdapter,
  miniSiemCsvAdapter,
];

const ORIGIN_OPTIONS = [
  {
    group: 'Auto',
    options: [{ id: 'auto', label: 'Auto-detect' }],
  },
  {
    group: 'Structured JSON',
    options: [
      { id: 'jsonl', label: 'Generic structured JSON (JSONL / array)' },
    ],
  },
  {
    group: 'Cloud / IdP JSON',
    options: [
      { id: 'okta', label: 'Okta System Log (JSONL)' },
      { id: 'azure-ad-signin', label: 'Azure AD sign-ins (JSON)' },
      { id: 'cloudtrail', label: 'AWS CloudTrail (JSON)' },
    ],
  },
  {
    group: 'Text logs',
    options: [
      { id: 'linux-auth', label: 'Linux SSH / auth.log (syslog)' },
      { id: 'apache-access', label: 'Web access logs (Apache/Nginx)' },
    ],
  },
  {
    group: 'Windows',
    options: [{ id: 'windows-security', label: 'Windows Security (4624/4625)' }],
  },
  {
    group: 'Generic delimited',
    options: [
      { id: 'csv-generic', label: 'Generic CSV (timestamp / ip / user / outcome)' },
      { id: 'kv-generic', label: 'Key=value lines' },
      { id: 'mini-siem-csv', label: 'Mini SIEM CSV export (round-trip)' },
    ],
  },
]

function splitLinesPreserveMiddle(text) {
  if (!text) return []
  const lines = text.split(/\r?\n/)
  if (lines.length && lines[lines.length - 1].trim() === '') lines.pop()
  return lines
}

function computeLineStats(text, maxLines) {
  const all = splitLinesPreserveMiddle(text)
  const physical = all.length
  const nonEmpty = all.reduce((acc, l) => acc + (l.trim() ? 1 : 0), 0)

  const truncated = physical > maxLines
  const window = truncated ? all.slice(0, maxLines) : all
  const processedPhysical = window.length
  const processedNonEmpty = window.reduce((acc, l) => acc + (l.trim() ? 1 : 0), 0)

  return {
    physical,
    nonEmpty,
    processedPhysical,
    processedNonEmpty,
    truncated,
    droppedPhysical: truncated ? physical - maxLines : 0,
  }
}

// ---------------- MiniSiem Component ----------------

function severityRank(s) {
  if (s === 'high') return 3
  if (s === 'medium') return 2
  if (s === 'low') return 1
  return 0
}

function minSeverityThreshold(min) {
  if (min === 'high') return 3
  if (min === 'medium') return 2
  return 0 // 'all'
}

function MiniSiem({ onBack }) {

  const [rawInput, setRawInput] = useState('')
  const [lastLoadedFileName, setLastLoadedFileName] = useState('')
  const [events, setEvents] = useState([])
  const [parseErrors, setParseErrors] = useState([])
  const [coverage, setCoverage] = useState(null)
  const [originGuess, setOriginGuess] = useState('')
  const [selectedOriginId, setSelectedOriginId] = useState(() =>
    getTemp(TEMP_ADAPTER_KEY, 'auto'),
  )
  const [activeTab, setActiveTab] = useState('logs')

  const [filterIp, setFilterIp] = useState('')
  const [filterUsername, setFilterUsername] = useState('')
  const [filterEventType, setFilterEventType] = useState('')
  const [searchTerm, setSearchTerm] = useState('')

  const [alertsRaw, setAlertsRaw] = useState([])

  const [homePrefixes, setHomePrefixes] = useState(() =>
    getTemp(TEMP_HOME_PREFIXES_KEY, []),
  )
  const [geoMappingRaw, setGeoMappingRaw] = useState(() =>
    getTemp(TEMP_GEO_MAPPING_KEY, ''),
  )
  const [geoMappingEntries, setGeoMappingEntries] = useState(() =>
    parseGeoMapping(getTemp(TEMP_GEO_MAPPING_KEY, '')).entries,
  )
  const [geoMappingError, setGeoMappingError] = useState(null)
  const [geoEnabled, setGeoEnabled] = useState(() =>
    getTemp(TEMP_GEO_ENABLED_KEY, false),
  )

  const [minSeverity, setMinSeverity] = useState(() =>
    getTemp(TEMP_MIN_SEVERITY_KEY, 'all')
  );

  const [clipboardMessage, setClipboardMessage] = useState('')

  const [focusedEventIds, setFocusedEventIds] = useState([])
  const [showAllDuringFocus, setShowAllDuringFocus] = useState(false)

  const [pageIndex, setPageIndex] = useState(0)
  const [pageSize, setPageSize] = useState(200)

  const [expandedEventId, setExpandedEventId] = useState(null)

  const [showRawInput, setShowRawInput] = useState(true)
  const [ingestStats, setIngestStats] = useState(null)
  const [lastLoadedFileStats, setLastLoadedFileStats] = useState(null)

  const [alertSearch, setAlertSearch] = useState('')
  const [groupAlertsByType, setGroupAlertsByType] = useState(true)
  const [expandedAlertTypes, setExpandedAlertTypes] = useState(() => new Set())

  const [detectionPreset, setDetectionPreset] = useState(() =>
    getTemp(TEMP_DETECTION_PRESET_KEY, 'balanced')
  )

  const isFocusActive =
    Array.isArray(focusedEventIds) && focusedEventIds.length > 0

  const fileInputRef = useRef(null)

  const hasEvents = events && events.length > 0

  const alerts = useMemo(() => {
    const threshold = minSeverityThreshold(minSeverity)
    if (!alertsRaw || threshold === 0) return alertsRaw || []
    return (alertsRaw || []).filter((a) => severityRank(a?.severity) >= threshold)
  }, [alertsRaw, minSeverity])

  const hasAlerts = alerts && alerts.length > 0

  const highestSeverity = useMemo(() => {
    if (!alerts || !alerts.length) return null
    if (alerts.some((a) => a.severity === 'high')) return 'high'
    if (alerts.some((a) => a.severity === 'medium')) return 'medium'
    return 'low'
  }, [alerts])

  const alertsByType = useMemo(() => {
    if (!alerts || !alerts.length) return []
    const counts = new Map()
    alerts.forEach((a) => {
      const key = a.type || 'unknown'
      counts.set(key, (counts.get(key) || 0) + 1)
    })
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1])
  }, [alerts])

  const visibleAlerts = useMemo(() => {
    const q = alertSearch.trim().toLowerCase()
    if (!q) return alerts || []
    return (alerts || []).filter((a) => {
      const blob = [
        a.type,
        a.severity,
        a.description,
        a.remediation,
        Array.isArray(a.relatedEventIds) ? a.relatedEventIds.join(' ') : '',
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return blob.includes(q)
    })
  }, [alerts, alertSearch])

  const groupedAlerts = useMemo(() => {
    if (!groupAlertsByType) return null
    const m = new Map()
    for (const a of visibleAlerts) {
      const k = a.type || 'unknown'
      if (!m.has(k)) m.set(k, [])
      m.get(k).push(a)
    }
    return Array.from(m.entries()).sort((a, b) => b[1].length - a[1].length)
  }, [visibleAlerts, groupAlertsByType])

    const eventStats = useMemo(() => {
    if (!events || !events.length) {
      return {
        totalEvents: 0,
        uniqueIps: 0,
        uniqueUsers: 0,
        successCount: 0,
        failCount: 0,
        failRate: null,
      };
    }

    const ips = new Set();
    const users = new Set();
    let success = 0;
    let fail = 0;

    events.forEach((e) => {
      if (e.sourceIp) ips.add(e.sourceIp);
      if (e.username) users.add(e.username);
      if (e.outcome === 'success') success += 1;
      else if (e.outcome === 'fail') fail += 1;
    });

    const totalAuth = success + fail;
    const failRate =
      totalAuth > 0 ? Math.round((fail / totalAuth) * 100) : null;

    return {
      totalEvents: events.length,
      uniqueIps: ips.size,
      uniqueUsers: users.size,
      successCount: success,
      failCount: fail,
      failRate,
    };
  }, [events]);

  // Persistence
  useEffect(() => {
    setTemp(TEMP_ADAPTER_KEY, selectedOriginId, TEMP_TTL_MS)
  }, [selectedOriginId])

  useEffect(() => {
    setTemp(TEMP_HOME_PREFIXES_KEY, homePrefixes, TEMP_TTL_MS)
  }, [homePrefixes])
  useEffect(() => {
    setTemp(TEMP_GEO_MAPPING_KEY, geoMappingRaw, TEMP_TTL_MS)
  }, [geoMappingRaw])
  useEffect(() => {
    setTemp(TEMP_GEO_ENABLED_KEY, geoEnabled, TEMP_TTL_MS)
  }, [geoEnabled])

  useEffect(() => {
    const { entries, error } = parseGeoMapping(geoMappingRaw)
    setGeoMappingEntries(entries)
    setGeoMappingError(error)

    // Keep selected home prefixes if they exist
    const valid = new Set(
      (entries || [])
        .map((e) => String(e?.prefix || '').trim())
        .filter(Boolean),
    )

    setHomePrefixes((prev) =>
      Array.isArray(prev)
        ? prev.filter((p) => valid.has(String(p || '').trim()))
        : [],
    )
  }, [geoMappingRaw])

  useEffect(() => {
    setPageIndex(0)
    setExpandedEventId(null)
  }, [filterIp, filterUsername, filterEventType, searchTerm, focusedEventIds, showAllDuringFocus])

  useEffect(() => {
    setTemp(TEMP_MIN_SEVERITY_KEY, minSeverity, TEMP_TTL_MS);
  }, [minSeverity]);

  useEffect(() => {
    setTemp(TEMP_DETECTION_PRESET_KEY, detectionPreset, TEMP_TTL_MS)
  }, [detectionPreset])

  const homePrefixList = useMemo(
    () => (Array.isArray(homePrefixes) ? homePrefixes : []),
    [homePrefixes],
  )

  const hasGeoMapping = Array.isArray(geoMappingEntries) && geoMappingEntries.length > 0

  const detectionContext = useMemo(
      () => ({
        preset: detectionPreset, 
        homeIpPrefixes: homePrefixList,

        enableGeo: !!geoEnabled && hasGeoMapping && homePrefixList.length > 0,
        geo: {
          entries: geoMappingEntries || [],
          resolveCountry: (ip) => ipToCountry(ip, geoMappingEntries || []),
          isHome: (ip) => homePrefixList.some((p) => String(ip || '').startsWith(String(p || ''))),
        },
      }),
      [detectionPreset, geoEnabled, homePrefixList, geoMappingEntries, hasGeoMapping],
    )

  const availablePrefixes = useMemo(() => {
    return (geoMappingEntries || [])
      .map((e) => ({
        prefix: String(e.prefix || '').trim(),
        label: String(e.country || '').trim(), // label
      }))
      .filter((x) => x.prefix)
  }, [geoMappingEntries])

  useEffect(() => {
    if (!events || !events.length) {
      setAlertsRaw([])
      return
    }
    const updated = runDetections(events, detectionContext)
    setAlertsRaw(updated)
  }, [events, detectionContext])

  const chooseAdapter = useCallback((lines, preferredId) => {
    if (preferredId && preferredId !== 'auto') {
      const adapter = ADAPTERS.find((a) => a.id === preferredId)
      return adapter || jsonlAdapter
    }

    const nonEmpty = lines.filter((l) => l.trim())
    const sample = nonEmpty.slice(0, 50)

    let best = jsonlAdapter
    let bestScore = 0

    for (const adapter of ADAPTERS) {
      const score = adapter.detectScore(sample)
      if (score > bestScore) {
        bestScore = score
        best = adapter
      }
    }

    return best
  }, [])

  const ingestLogs = useCallback(
    (text, originId, opts = { mutateRaw: false, fileOriginalStats: null }) => {
      const stats = computeLineStats(text || '', MAX_LINES)
      setIngestStats(stats)

      if (opts.fileOriginalStats) {
        setLastLoadedFileStats(opts.fileOriginalStats)
      } else {
        setLastLoadedFileStats(null)
      }

      // empty
      if (!text || !text.trim()) {
        setEvents([])
        setParseErrors([])
        setCoverage(null)
        setOriginGuess('')
        return
      }

      const allLines = splitLinesPreserveMiddle(text)
      const processedLines = stats.truncated ? allLines.slice(0, MAX_LINES) : allLines

      if (opts.mutateRaw) {
        setRawInput(processedLines.join('\n'))
      }

      const extraIssues = []
      if (stats.truncated) {
        extraIssues.push(
          `Input is ${stats.physical.toLocaleString()} lines. Processing first ${MAX_LINES.toLocaleString()} lines for performance.`,
        )
      }

      const adapter = chooseAdapter(processedLines, originId)
      const result = adapter.parse(processedLines, originId)

      const normalizedCoverage = result.coverage
        ? (() => {
            const c = { ...result.coverage }
            const unit = c.coverageUnit || 'lines'

            if ((c.coverageUnit || 'lines') === 'lines') {
              c.totalLines = stats.processedNonEmpty
            }

            if (unit === 'lines') {
              c.totalLines = stats.processedNonEmpty
            } else if (unit === 'records') {
              if (!c.totalRecords) c.totalRecords = stats.processedNonEmpty
            }

            c.processedNonEmptyLines = stats.processedNonEmpty
            c.processedPhysicalLines = stats.processedPhysical

            return c
          })()
        : null

      const enrichedEvents = (result.events || []).map((ev, idx) => {
      // 1) Canonicalize
      let canon = finalizeCanonicalEvent(ev || {})

      // 2) Ensure stable ID
      const id =
        canon.id && String(canon.id).trim()
          ? String(canon.id).trim()
          : `e${idx + 1}`

      // 3) Build search blob
      const blob = [
        canon.sourceIp, canon.destIp, canon.destPort,
        canon.username, canon.eventType, canon.outcome,
        canon.host, canon.sourceApp, canon.environment, canon.authMethod, canon.geoCountry,

        // Canonical telemetry fields
        canon.httpMethod, canon.httpPath, canon.httpStatus, canon.latencyMs,
        canon.dnsQname, canon.dnsQtype, canon.dnsRcode,
        canon.bytesIn, canon.bytesOut,
        canon.processName, canon.processCmd,
        canon.filePath, canon.fileBytes,
        canon.mfa,

        // UI string + raw fallback
        canon.details,
        typeof canon.raw === 'string' ? canon.raw : '',
      ]
        .filter((v) => v !== null && v !== undefined && String(v).trim() !== '')
        .join(' ')
        .toLowerCase()

      // Keep original fields
      return { ...ev, ...canon, id, _searchBlob: blob }
    })

      enrichedEvents.sort((a, b) => {
        const ta = a.timestamp instanceof Date ? a.timestamp.getTime() : 0
        const tb = b.timestamp instanceof Date ? b.timestamp.getTime() : 0
        return ta - tb
      })

      setEvents(enrichedEvents)
      setParseErrors([...(extraIssues || []), ...((result.errors || []))])
      setCoverage(normalizedCoverage)
      setOriginGuess(result.originGuess || adapter.label || '')
    },
    [chooseAdapter]
  )

  const handleFileChange = (event) => {
    const file = event.target.files?.[0]
    if (!file) return

    if (file.size > MAX_FILE_BYTES) {
      setParseErrors([
        `File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum allowed is 10 MB.`,
      ])
      return
    }

    setLastLoadedFileName(file.name)
    setShowRawInput(false)

    const reader = new FileReader()
    reader.onload = (e) => {
      const text = String(e.target?.result || '')
      const originalStats = computeLineStats(text, MAX_LINES)

      setLastLoadedFileName(file.name)
      setShowRawInput(false)

      ingestLogs(text, selectedOriginId, {
        mutateRaw: true,
        fileOriginalStats: originalStats,
      })

      setActiveTab('logs')
    }
    reader.readAsText(file)
  }

  const handleRawChange = (e) => {
    const next = e.target.value
    const wasEmpty = !rawInput
    setRawInput(next)
    setLastLoadedFileName('')
    if (wasEmpty && next) setShowRawInput(true)
    ingestLogs(next, selectedOriginId)
    setActiveTab('logs')
  }

  const handleOriginChange = (id) => {
    setSelectedOriginId(id)
    if (rawInput.trim()) {
      ingestLogs(rawInput, id)
    }
  }

  const handleReset = () => {
    setRawInput('')
    setEvents([])
    setParseErrors([])
    setCoverage(null)
    setOriginGuess('')
    setAlertsRaw([])
    setFilterIp('')
    setFilterUsername('')
    setFilterEventType('')
    setSearchTerm('')
    setLastLoadedFileName('')
    setShowRawInput(true)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const filteredEvents = useMemo(() => {
    if (!hasEvents) return []

    let list = events

    const focusSet = new Set(focusedEventIds || [])

    if (isFocusActive && !showAllDuringFocus) {
      list = list.filter((e) => focusSet.has(e.id))
    }

    if (filterIp.trim()) {
      const q = filterIp.trim().toLowerCase()
      list = list.filter(
        (e) =>
          e.sourceIp && e.sourceIp.toLowerCase().includes(q),
      )
    }

    if (filterUsername.trim()) {
      const q = filterUsername.trim().toLowerCase()
      list = list.filter(
        (e) =>
          e.username && e.username.toLowerCase().includes(q),
      )
    }

    if (filterEventType.trim()) {
      const q = filterEventType.trim().toLowerCase()
      list = list.filter(
        (e) =>
          e.eventType && e.eventType.toLowerCase().includes(q),
      )
    }

    let searchableList = list
    if (list.length > MAX_SEARCH_EVENTS) {
      searchableList = list.slice(-MAX_SEARCH_EVENTS)
    }

    if (searchTerm.trim()) {
      const q = searchTerm.trim().toLowerCase()
      list = searchableList.filter((e) =>
        (e._searchBlob || '').includes(q)
      )
    }

    return list
  }, [
    events,
    hasEvents,
    filterIp,
    filterUsername,
    filterEventType,
    searchTerm,
    focusedEventIds,
    isFocusActive,
    showAllDuringFocus,
  ])

  const totalFiltered = filteredEvents.length
  const totalPages = Math.max(1, Math.ceil(totalFiltered / pageSize))
  const safePageIndex = Math.min(pageIndex, totalPages - 1)

  const pagedEvents = useMemo(() => {
    const start = safePageIndex * pageSize
    return filteredEvents.slice(start, start + pageSize)
  }, [filteredEvents, safePageIndex, pageSize])

  const focusedTotalCount = useMemo(() => {
    if (!isFocusActive) return 0
    const focusSet = new Set(focusedEventIds || [])
    return events.filter((e) => focusSet.has(e.id)).length
  }, [events, focusedEventIds, isFocusActive])

  const rawLineCount = useMemo(
    () => computeLineStats(rawInput, MAX_LINES).physical,
    [rawInput],
  )

  const timeSpanLabel = useMemo(() => {
    if (!events || !events.length) return null

    const tsList = events
      .map((e) =>
        e.timestamp instanceof Date && !Number.isNaN(e.timestamp.getTime())
          ? e.timestamp.getTime()
          : null,
      )
      .filter((t) => t !== null);

    if (!tsList.length) return null;

    const min = new Date(Math.min(...tsList));
    const max = new Date(Math.max(...tsList));

    const formatIso = (d) => d.toLocaleString();

    if (min.getTime() === max.getTime()) {
      return `Time span: ${formatIso(min)}`;
    }

    const diffMs = max.getTime() - min.getTime();
    const diffMinutes = Math.round(diffMs / 60000);

    let spanText;
    if (diffMinutes < 60) {
      spanText = `${diffMinutes} min`;
    } else {
      const hours = diffMinutes / 60;
      spanText = `${hours.toFixed(hours % 1 === 0 ? 0 : 1)} h`;
    }

    return `Time span: ${formatIso(min)} → ${formatIso(max)} (${spanText})`
  }, [events]);

  const quality = useMemo(() => qualityFromCoverage(coverage), [coverage])

  const clearFocus = useCallback(() => {
    setFocusedEventIds([])
    setShowAllDuringFocus(false)
  }, [])

  const handleFocusFromAlert = useCallback(
    (alert) => {
      if (!alert || !Array.isArray(alert.relatedEventIds) || !alert.relatedEventIds.length) {
        return
      }

      setFilterIp('')
      setFilterUsername('')
      setFilterEventType('')
      setSearchTerm('')

      setFocusedEventIds(alert.relatedEventIds)
      setShowAllDuringFocus(false)
      setActiveTab('logs')
    },
    [
      setFilterIp,
      setFilterUsername,
      setFilterEventType,
      setSearchTerm,
    ],
  )

  // ---------- Export helpers ----------

  const serializeEventsForJson = () =>
    events.map((e) => ({
      id: e.id,
      timestamp:
        e.timestamp instanceof Date && !Number.isNaN(e.timestamp.getTime())
          ? e.timestamp.toLocaleString()
          : null,

      // identity/core
      sourceIp: e.sourceIp || '',
      destIp: e.destIp || '',
      destPort: e.destPort ?? null,
      username: e.username || '',
      eventType: e.eventType || 'event',
      outcome: e.outcome || '',
      mfa: typeof e.mfa === 'boolean' ? e.mfa : null,

      // telemetry
      httpMethod: e.httpMethod || '',
      httpPath: e.httpPath || '',
      httpStatus: e.httpStatus ?? null,
      latencyMs: e.latencyMs ?? null,

      dnsQname: e.dnsQname || '',
      dnsQtype: e.dnsQtype || '',
      dnsRcode: e.dnsRcode || '',

      bytesIn: e.bytesIn ?? null,
      bytesOut: e.bytesOut ?? null,

      processName: e.processName || '',
      processCmd: e.processCmd || '',

      filePath: e.filePath || '',
      fileBytes: e.fileBytes ?? null,

      // context/ui
      host: e.host || '',
      sourceApp: e.sourceApp || '',
      environment: e.environment || '',
      authMethod: e.authMethod || '',
      geoCountry: e.geoCountry || '',
      contextProfile: e.contextProfile || null,
      details: e.details || '',

      // raw
      raw: e.raw,
    }))

  const buildEventsCsv = (evts) => {
    const headers = [
      'id',
      'timestamp',

      // identity/core
      'sourceIp',
      'destIp',
      'destPort',
      'username',
      'eventType',
      'outcome',
      'mfa',

      // telemetry
      'httpMethod',
      'httpPath',
      'httpStatus',
      'latencyMs',

      'dnsQname',
      'dnsQtype',
      'dnsRcode',

      'bytesIn',
      'bytesOut',

      'processName',
      'processCmd',

      'filePath',
      'fileBytes',

      // context/ui
      'host',
      'sourceApp',
      'environment',
      'authMethod',
      'geoCountry',
      'contextProfile',
      'details',
    ]
    const rows = evts.map((e) => {
      const values = headers.map((h) => {
        let v
        if (h === 'timestamp') {
          v =
            e.timestamp instanceof Date &&
            !Number.isNaN(e.timestamp.getTime())
              ? e.timestamp.toLocaleString()
              : ''
        } else {
          v = e[h] ?? ''
        }
        const s = String(v).replace(/"/g, '""')
        return `"${s}"`
      })
      return values.join(',')
    })
    return [headers.join(','), ...rows].join('\n')
  }

  const buildAlertsCsv = (alist) => {
    const headers = [
      'id',
      'type',
      'severity',
      'description',
      'remediation',
      'relatedEventIds',
    ]
    const rows = alist.map((a) => {
      const values = headers.map((h) => {
        let v = a[h]
        if (h === 'relatedEventIds' && Array.isArray(v)) {
          v = v.join(' ')
        }
        const s = String(v ?? '').replace(/"/g, '""')
        return `"${s}"`
      })
      return values.join(',')
    })
    return [headers.join(','), ...rows].join('\n')
  }

  const buildAlertsMarkdown = (alist) => {
    const lines = ['# Security Webtools - Mini SIEM Alerts', '']

    if (!alist.length) {
      lines.push('_No alerts generated for the current dataset._')
      return lines.join('\n')
    }

    for (const a of alist) {
      lines.push(
        `- **[${a.severity.toUpperCase()}] ${a.type}** - ${a.description.replace(
          /\n/g,
          ' ',
        )}`,
      )
      if (Array.isArray(a.relatedEventIds) && a.relatedEventIds.length) {
        lines.push(
          `  - Related events: ${a.relatedEventIds.join(', ')}`,
        )
      }
      if (a.remediation) {
        lines.push(
          `  - Suggested response: ${a.remediation.replace(/\n/g, ' ')}`,
        );
      }
    }

    return lines.join('\n')
  }

  const copyToClipboard = async (text) => {
    try {
      if (
        typeof navigator === 'undefined' ||
        !navigator.clipboard ||
        !navigator.clipboard.writeText
      ) {
        throw new Error('Clipboard API not available.')
      }
      await navigator.clipboard.writeText(text)
      setClipboardMessage('Copied to clipboard.')
    } catch (err) {
      console.error(err)
      setClipboardMessage(
        'Failed to copy to clipboard (browser may block clipboard access).',
      )
    } finally {
      setTimeout(() => setClipboardMessage(''), 3000)
    }
  }

  const handleExportEventsJson = () => {
    const json = JSON.stringify(serializeEventsForJson(), null, 2)
    downloadTextFile('mini-siem-events.json', json)
  }

  const handleExportEventsCsv = () => {
    const csv = buildEventsCsv(events)
    downloadTextFile('mini-siem-events.csv', csv)
  }

  const handleExportAlertsJson = () => {
    const json = JSON.stringify(visibleAlerts, null, 2)
    downloadTextFile('mini-siem-alerts.json', json)
  }

  const handleExportAlertsCsv = () => {
    const csv = buildAlertsCsv(visibleAlerts)
    downloadTextFile('mini-siem-alerts.csv', csv)
  }

  const handleExportAlertsMarkdown = () => {
    const md = buildAlertsMarkdown(visibleAlerts)
    downloadTextFile('mini-siem-alerts.md', md)
  }

  const handleCopyAlertsMarkdown = () => {
    const md = buildAlertsMarkdown(visibleAlerts)
    copyToClipboard(md)
  }

  // ---------- Render helpers ----------

  const renderAlertCard = (a) => (
    <div
      key={a.id}
      className="rounded-2xl border border-slate-800 bg-slate-950/80 p-3 text-xs text-slate-100"
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="text-[0.75rem] font-semibold text-slate-100">
            {a.type}
          </div>
        </div>

        <span
          className={
            a.severity === 'high'
              ? 'inline-flex rounded-full bg-rose-500/10 px-2 py-0.5 text-[0.65rem] font-semibold text-rose-300'
              : a.severity === 'medium'
              ? 'inline-flex rounded-full bg-amber-500/10 px-2 py-0.5 text-[0.65rem] font-semibold text-amber-300'
              : 'inline-flex rounded-full bg-slate-700/60 px-2 py-0.5 text-[0.65rem] font-semibold text-slate-200'
          }
        >
          {a.severity}
        </span>
      </div>

      <pre className="mt-1 whitespace-pre-wrap text-[0.7rem] text-slate-200">
        {a.description}
      </pre>

      {a.remediation && (
        <div className="mt-2 text-[0.7rem] text-slate-300">
          <span className="font-semibold text-slate-100">
            Suggested response:
          </span>{' '}
          {a.remediation}
        </div>
      )}

      {Array.isArray(a.relatedEventIds) && a.relatedEventIds.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-2 text-[0.7rem] text-slate-400">
          <span>Related events:</span>
          <button
            type="button"
            onClick={() => handleFocusFromAlert(a)}
            className="rounded-full border border-emerald-400/70 bg-emerald-500/10 px-2.5 py-0.5 text-[0.7rem] font-medium text-emerald-100 hover:bg-emerald-500/20"
          >
            View in Logs
          </button>
        </div>
      )}
    </div>
  )

  const renderFilters = () => (
    <div className="mt-4 grid gap-3 md:grid-cols-4">
      <div>
        <label className="block text-xs font-medium text-slate-400 mb-1">
          Filter by IP
        </label>
        <input
          type="text"
          value={filterIp}
          onChange={(e) => setFilterIp(e.target.value)}
          className="w-full rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
          placeholder="e.g. 10.0.0.5"
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-slate-400 mb-1">
          Filter by username
        </label>
        <input
          type="text"
          value={filterUsername}
          onChange={(e) => setFilterUsername(e.target.value)}
          className="w-full rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
          placeholder="e.g. alice"
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-slate-400 mb-1">
          Event type
        </label>
        <input
          type="text"
          value={filterEventType}
          onChange={(e) => setFilterEventType(e.target.value)}
          className="w-full rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
          placeholder="e.g. login"
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-slate-400 mb-1">
          Free-text search
        </label>
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
          placeholder="Search domain, path, process, file, port..."
        />
      </div>
    </div>
  )

  const originIndicator = (
    <div className="mt-2 space-y-0.5 text-[0.7rem] text-slate-400">
      {/* Line 1: Origin */}
      <div>
        Origin (auto-detected):{' '}
        <span className="text-slate-300">{originGuess || 'None'}</span>
      </div>

      {/* Line 2: Processing + parsing */}
      <div>
        {ingestStats && ingestStats.processedPhysical > 0 && (
          <>
            Processed{' '}
            <span className="text-slate-300">
              {ingestStats.processedPhysical.toLocaleString()}
            </span>
            {ingestStats.truncated ? ` (windowed to ${MAX_LINES.toLocaleString()})` : ''}

            <span className="ml-2 text-slate-500">
              • Non-empty: <span className="text-slate-300">{ingestStats.processedNonEmpty.toLocaleString()}</span>
            </span>
            {ingestStats.truncated
              ? ` (windowed to ${MAX_LINES.toLocaleString()})`
              : ''}
          </>
        )}

        {coverage && (
          <>
            <span className="mx-1 text-slate-600">•</span>
            Parsed{' '}
            <span className="text-slate-300">
              {(coverage.coverageUnit || 'lines') === 'records'
                ? `${coverage.parsedRecords || 0}/${coverage.totalRecords || 0} records`
                : `${coverage.parsedLines || 0}/${coverage.totalLines || 0}`}
            </span>{' '}
            (
            {(coverage.coverageUnit || 'lines') === 'records'
              ? (coverage.totalRecords > 0
                  ? Math.round((coverage.parsedRecords / coverage.totalRecords) * 100)
                  : 0)
              : (coverage.totalLines > 0
                  ? Math.round((coverage.parsedLines / coverage.totalLines) * 100)
                  : 0)}
            %)
          </>
        )}

      </div>

      {/* Line 3: Quality + time span */}
      <div>
        {quality?.label && (
          <span
            className={
              quality.level === 'good'
                ? 'text-emerald-400'
                : quality.level === 'fair'
                ? 'text-amber-300'
                : quality.level === 'poor'
                ? 'text-rose-300'
                : 'text-slate-400'
            }
          >
            Parsing quality: {quality.label}
          </span>
        )}

        {timeSpanLabel && (
          <>
            <span className="mx-1 text-slate-600">•</span>
            <span>{timeSpanLabel.replace(/^Time span:\s*/, '')}</span>
          </>
        )}
      </div>
    </div>
  )

  const renderLogsTab = () => (
    <div className="mt-4 space-y-4">
      {/* Alerts banner if alerts exist */}
      {hasAlerts && (
        <div className="rounded-2xl border border-rose-600/60 bg-rose-500/5 px-3 py-2 text-[0.7rem] text-rose-100 flex flex-wrap items-center justify-between gap-2">
          <div>
            <span className="font-semibold">
              {alerts.length} alert{alerts.length === 1 ? '' : 's'} generated
            </span>
            {highestSeverity && (
              <span className="ml-2 text-rose-300">
                (Highest severity: {highestSeverity})
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={() => setActiveTab('alerts')}
            className="text-[0.7rem] rounded-full border border-rose-500/70 bg-rose-500/10 px-3 py-1 hover:bg-rose-500/20"
          >
            View in Alerts tab →
          </button>
        </div>
      )}

      {/* Ingestion controls */}
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex cursor-pointer items-center rounded-xl border border-dashed border-slate-700/80 bg-slate-950/40 px-3 py-2 text-xs font-medium text-slate-300 hover:border-emerald-500/60 hover:bg-slate-900/60">
              <span className="mr-2 rounded-md bg-emerald-500/10 px-2 py-1 text-[0.6rem] font-semibold uppercase tracking-wide text-emerald-300">
                Upload
              </span>
              <span>
                Select log file for analysis
              </span>
              <input
                ref={fileInputRef}
                type="file"
                accept=".log,.txt,.jsonl,.json,.out,.csv"
                className="hidden"
                onChange={handleFileChange}
              />
            </label>
            <button
              type="button"
              onClick={handleReset}
              className="text-[0.7rem] px-3 py-1.5 rounded-full border border-slate-700 text-slate-300 hover:border-slate-500 hover:text-slate-100"
            >
              Reset
            </button>
          </div>
          <p className="text-[0.7rem] text-slate-400 italic">
            Mini SIEM auto-detects common log formats. 
            Use “Log type hint” if you know the format family (JSON, web access, Windows, etc.)
          </p>

          <div className="flex flex-wrap items-center gap-2 text-[0.7rem]">
            <span className="text-slate-400">Log Type:</span>
            <select
              value={selectedOriginId}
              onChange={(e) => handleOriginChange(e.target.value)}
              className="rounded-full border border-slate-700 bg-slate-950/60 px-3 py-1 text-[0.7rem] text-slate-100 focus:outline-none focus:ring-1 focus:ring-emerald-500/60"
            >
              {ORIGIN_OPTIONS.map((g) => (
                <optgroup key={g.group} label={g.group}>
                  {g.options.map((opt) => (
                    <option key={opt.id} value={opt.id}>
                      {opt.label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </div>

          {originIndicator}
        </div>

        {/* Exports */}
        <div className="flex flex-col items-start gap-2 md:items-end">
          <span className="text-[0.7rem] text-slate-400">
            Logs exports operate on the current parsed dataset.
          </span>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={handleExportEventsJson}
              disabled={!hasEvents}
              className="rounded-full border border-slate-700 bg-slate-950/60 px-3 py-1.5 text-[0.7rem] text-slate-100 hover:border-emerald-500/70 hover:bg-slate-900/80 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Export logs (JSON)
            </button>
            <button
              type="button"
              onClick={handleExportEventsCsv}
              disabled={!hasEvents}
              className="rounded-full border border-slate-700 bg-slate-950/60 px-3 py-1.5 text-[0.7rem] text-slate-100 hover:border-emerald-500/70 hover:bg-slate-900/80 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Export logs (CSV)
            </button>
          </div>
        </div>
      </div>

      {/* Raw input */}
      <div>
        <div className="flex items-center justify-between gap-2">
          <label className="block text-xs font-medium text-slate-400">
            Raw input
            {rawLineCount > 0 ? (
              <span className="ml-2 text-[0.7rem] text-slate-500">
                ({rawLineCount.toLocaleString()} lines)
              </span>
            ) : null}
          </label>

          {(rawInput.trim() || lastLoadedFileName) && (
            <button
              type="button"
              onClick={() => setShowRawInput((v) => !v)}
              className="text-[0.7rem] rounded-full border border-slate-700 bg-slate-950/50 px-3 py-1 text-slate-200 hover:border-slate-500 hover:bg-slate-900/70"
            >
              {showRawInput ? 'Hide raw input' : 'Show raw input'}
            </button>
          )}
        </div>

        {lastLoadedFileName && (
          <div className="mt-1 text-[0.7rem] text-slate-500">
            Loaded file:{' '}
            <span className="text-slate-300">{lastLoadedFileName}</span>

            {lastLoadedFileStats ? (
              <>
                {' '}
                (<span className="text-slate-300">
                  {lastLoadedFileStats.physical.toLocaleString()}
                </span>{' '}
                lines
                {lastLoadedFileStats.truncated ? (
                  <>
                    ; showing first{' '}
                    <span className="text-slate-300">
                      {MAX_LINES.toLocaleString()}
                    </span>
                  </>
                ) : null}
                )
              </>
            ) : ingestStats ? (
              <>
                {' '}
                (<span className="text-slate-300">
                  {ingestStats.physical.toLocaleString()}
                </span>{' '}
                lines
                {ingestStats.truncated ? (
                  <>
                    ; showing first{' '}
                    <span className="text-slate-300">
                      {MAX_LINES.toLocaleString()}
                    </span>
                  </>
                ) : null}
                )
              </>
            ) : null}
          </div>
        )}

        {showRawInput ? (
            <textarea
              value={rawInput}
              onChange={handleRawChange}
              rows={8}
              className="mt-2 w-full rounded-2xl border border-slate-800 bg-slate-950/70 px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
              placeholder={`Examples:
        {"timestamp":"2024-02-01T12:43:21Z","sourceIp":"10.1.2.3","username":"alice","eventType":"login","outcome":"fail"}
        Feb  1 12:43:21 bastion sshd[1234]: Failed password for alice from 10.1.2.3 port 22 ssh2
        203.0.113.10 - alice [01/Feb/2024:12:43:21 +0000] "GET /login HTTP/1.1" 401 512 "-" "curl/7.68.0"
        "TimeCreated","EventID","TargetUserName","IpAddress"
        "2024-02-01T12:43:21Z","4625","alice","10.1.2.3"
        "ts=2024-02-01T12:43:21Z app=app1 user=alice ip=10.1.2.3 action=login outcome=fail"`}
            />
          ) : (
            <div className="mt-2 rounded-2xl border border-slate-800 bg-slate-950/40 px-3 py-2 text-[0.7rem] text-slate-400 italic">
              Raw input hidden for performance. Use “Show raw input” if you need to inspect the original lines.
            </div>
          )}
        </div>

      {/* Parse issues */}
      {parseErrors.length > 0 && (
        <div className="rounded-xl border border-rose-600/60 bg-rose-950/40 px-3 py-2 text-[0.7rem] text-rose-100">
          <div className="font-semibold mb-1">
            Parse issues (some lines could not be interpreted)
          </div>
          <ul className="list-disc pl-4 space-y-0.5 max-h-40 overflow-auto">
            {parseErrors.map((err, idx) => (
              <li key={idx}>{err}</li>
            ))}
          </ul>
          <p className="mt-1 text-[0.65rem] text-rose-200">
            Detection results are heuristic and based only on successfully
            parsed lines. Consider exporting more structured logs if the
            coverage is poor.
          </p>
        </div>
      )}

      {/* Filters + Events table */}
      {hasEvents ? (
        <>
          {renderFilters()}

          {isFocusActive && (
            <div className="mt-3 rounded-xl border border-emerald-500/40 bg-emerald-500/5 px-3 py-2 text-[0.7rem] text-emerald-100 flex flex-wrap items-center gap-3 justify-between">
              <div>
                Showing{' '}
                <span className="font-semibold">
                  {filteredEvents.length}
                </span>{' '}
                event{filteredEvents.length === 1 ? '' : 's'} related to the
                selected alert
                {focusedTotalCount > 0 &&
                  filteredEvents.length !== focusedTotalCount && (
                    <>
                      {' '}
                      (out of{' '}
                      <span className="font-semibold">
                        {focusedTotalCount}
                      </span>{' '}
                      related events)
                    </>
                  )}
                .
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <label className="inline-flex items-center gap-1 text-[0.7rem]">
                  <input
                    type="checkbox"
                    className="h-3 w-3 rounded border-emerald-400 bg-slate-900"
                    checked={showAllDuringFocus}
                    onChange={(e) =>
                      setShowAllDuringFocus(e.target.checked)
                    }
                  />
                  <span>Show all events (keep highlights)</span>
                </label>
                <button
                  type="button"
                  onClick={clearFocus}
                  className="text-[0.7rem] rounded-full border border-emerald-400/60 px-2.5 py-1 text-emerald-100 hover:bg-emerald-500/15"
                >
                  Clear focus
                </button>
              </div>
            </div>
          )}

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[0.7rem] text-slate-400">
            <div>
              Showing{' '}
              <span className="font-semibold text-slate-100">
                {Math.min(safePageIndex * pageSize + 1, totalFiltered)}
              </span>
              -
              <span className="font-semibold text-slate-100">
                {Math.min((safePageIndex + 1) * pageSize, totalFiltered)}
              </span>{' '}
              of <span className="font-semibold text-slate-100">{totalFiltered}</span>{' '}
              filtered events
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPageIndex((p) => Math.max(0, p - 1))}
                disabled={safePageIndex === 0}
                className="rounded-full border border-slate-700 bg-slate-950/60 px-2.5 py-1 disabled:opacity-50"
              >
                Prev
              </button>
              <span>
                Page <span className="text-slate-100">{safePageIndex + 1}</span> /{' '}
                <span className="text-slate-100">{totalPages}</span>
              </span>
              <button
                type="button"
                onClick={() => setPageIndex((p) => Math.min(totalPages - 1, p + 1))}
                disabled={safePageIndex >= totalPages - 1}
                className="rounded-full border border-slate-700 bg-slate-950/60 px-2.5 py-1 disabled:opacity-50"
              >
                Next
              </button>

              <select
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value))}
                className="rounded-full border border-slate-700 bg-slate-950/60 px-2.5 py-1"
              >
                {[100, 200, 500, 1000].map((n) => (
                  <option key={n} value={n}>
                    {n}/page
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="mt-3 max-h-96 overflow-auto rounded-2xl border border-slate-800 bg-slate-950/60">
            <table className="min-w-full text-left text-[0.7rem] text-slate-200">
              <thead className="sticky top-0 bg-slate-900/90">
                <tr>
                  <th className="px-3 py-2 font-semibold">ID</th>
                  <th className="px-3 py-2 font-semibold">Timestamp</th>
                  <th className="px-3 py-2 font-semibold">Source IP</th>
                  <th className="px-3 py-2 font-semibold">Username</th>
                  <th className="px-3 py-2 font-semibold">Event</th>
                  <th className="px-3 py-2 font-semibold">Outcome</th>
                  <th className="px-3 py-2 font-semibold">Host/App</th>
                </tr>                                         
              </thead>
              <tbody>
                {pagedEvents.map((e) => {
                  const isFocused =
                    isFocusActive &&
                    Array.isArray(focusedEventIds) &&
                    focusedEventIds.includes(e.id)

                  return (
                    <React.Fragment key={e.id}>
                      <tr
                        className={[
                          'border-t border-slate-800/80 odd:bg-slate-950/40 even:bg-slate-950/10',
                          isFocused ? 'bg-emerald-950/50' : '',
                        ].join(' ')}
                      >
                        <td className="px-3 py-1.5 align-top font-mono text-[0.65rem] text-slate-400">
                          {e.id || <span className="text-slate-600">-</span>}
                        </td>

                        <td className="px-3 py-1.5 align-top">
                          {e.timestamp instanceof Date && !Number.isNaN(e.timestamp.getTime())
                            ? e.timestamp.toLocaleString()
                            : ''}
                        </td>

                        <td className="px-3 py-1.5 align-top font-mono">
                          {e.sourceIp || <span className="text-slate-600">-</span>}
                        </td>

                        <td className="px-3 py-1.5 align-top">
                          {e.username || <span className="text-slate-600">-</span>}
                        </td>

                        <td className="px-3 py-1.5 align-top">
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedEventId((cur) => (cur === e.id ? null : e.id))
                            }
                            className="inline-flex rounded-full bg-slate-800/70 px-2 py-0.5 text-[0.65rem] hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
                            title="Toggle event details"
                          >
                            {e.eventType || 'event'}
                            <span className="ml-1 text-slate-400">
                              {expandedEventId === e.id ? '▾' : '▸'}
                            </span>
                          </button>
                        </td>

                        <td className="px-3 py-1.5 align-top">
                          <span
                            className={
                              e.outcome === 'success'
                                ? 'inline-flex rounded-full bg-emerald-500/10 px-2 py-0.5 text-[0.65rem] font-semibold text-emerald-300'
                                : e.outcome === 'fail'
                                ? 'inline-flex rounded-full bg-amber-500/10 px-2 py-0.5 text-[0.65rem] font-semibold text-amber-300'
                                : 'inline-flex rounded-full bg-slate-700/40 px-2 py-0.5 text-[0.65rem] font-semibold text-slate-200'
                            }
                          >
                            {e.outcome || 'n/a'}
                          </span>
                        </td>

                        <td className="px-3 py-1.5 align-top text-slate-300">
                          <div className="flex flex-col gap-0.5">
                            <span>{e.host || <span className="text-slate-600">-</span>}</span>
                            {e.sourceApp && (
                              <span className="text-[0.6rem] text-slate-500">{e.sourceApp}</span>
                            )}
                            {!!e.geoCountry && (
                              <span className="text-[0.6rem] text-slate-500">
                                Geo: {e.geoCountry}
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>

                      {expandedEventId === e.id && (
                        <tr className="border-t border-slate-800/80 bg-slate-950/70">
                          <td colSpan={7} className="px-3 py-2">
                            <div className="grid gap-2 md:grid-cols-2">
                              <div>
                                <div className="text-[0.65rem] font-semibold text-slate-300">
                                  Parsed details
                                </div>
                                <div className="mt-1 rounded-xl border border-slate-800 bg-slate-950/40 px-3 py-2 text-[0.7rem] text-slate-200">
                                  {e.details ? (
                                    <span className="font-mono">{e.details}</span>
                                  ) : (
                                    <span className="text-slate-500 italic">
                                      No structured details extracted.
                                    </span>
                                  )}
                                </div>

                                {(e.destIp || e.destPort != null) && (
                                  <div className="mt-2 text-[0.7rem] text-slate-300">
                                    <span className="text-slate-500">Dest:</span>{' '}
                                    <span className="font-mono">{e.destIp || '-'}</span>
                                    {e.destPort != null && (
                                      <>
                                        :<span className="font-mono">{e.destPort}</span>
                                      </>
                                    )}
                                  </div>
                                )}
                              </div>

                              <div>
                                <div className="text-[0.65rem] font-semibold text-slate-300">
                                  Raw line
                                </div>
                                <pre className="mt-1 max-h-40 overflow-auto rounded-xl border border-slate-800 bg-slate-950/40 px-3 py-2 text-[0.65rem] text-slate-200 whitespace-pre-wrap">
                                  {typeof e.raw === 'string' ? e.raw : JSON.stringify(e.raw, null, 2)}
                                </pre>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })}
                {filteredEvents.length === 0 && (
                  <tr>
                    <td
                      colSpan={6}
                      className="px-3 py-3 text-center text-slate-500 italic"
                    >
                      No events match the current filters.
                    </td>
                  </tr>                  
                )}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <p className="mt-2 text-xs text-slate-400">
          No events parsed yet. Upload a log file or paste log lines above to
          see normalized events and derived alerts.
        </p>
      )}
    </div>
  )

  const renderAlertsTab = () => (
    <div className="mt-4 space-y-4">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div className="text-xs text-slate-400 space-y-0.5">
          <p>
            Parsed events:{' '}
            <span className="font-semibold text-slate-100">
              {eventStats.totalEvents}
            </span>{' '}
            • Unique IPs:{' '}
            <span className="font-semibold text-slate-100">
              {eventStats.uniqueIps}
            </span>{' '}
            • Unique users:{' '}
            <span className="font-semibold text-slate-100">
              {eventStats.uniqueUsers}
            </span>
          </p>
          <p>
            Auth outcomes:{' '}
            <span className="font-semibold text-amber-200">
              {eventStats.failCount} fails
            </span>{' '}
            /{' '}
            <span className="font-semibold text-emerald-200">
              {eventStats.successCount} successes
            </span>
            {eventStats.failRate !== null && (
              <span className="text-slate-400">
                {' '}
                (fail ratio {eventStats.failRate}%)
              </span>
            )}
          </p>
          <p>
            Generated alerts:{' '}
            <span className="font-semibold text-slate-100">
              {visibleAlerts.length}
            </span>
            {highestSeverity && alerts.length > 0 && (
              <span className="ml-1 text-[0.7rem] text-rose-300">
                (highest severity: {highestSeverity})
              </span>
            )}
          </p>
          {alertsByType.length > 0 && (
            <div className="mt-1 text-[0.7rem] text-slate-400">
              Alerts by rule type:{' '}
              <span className="text-slate-100">
                {alertsByType
                  .map(([type, count]) => `${type} (${count})`)
                  .join(' • ')}
              </span>
            </div>
          )}
          <p className="text-[0.7rem] text-slate-500 italic">
            Mini SIEM uses heuristic rules to surface potential
            patterns. Findings are suggestions, not definitive verdicts. Always
            validate against your own environment and policies.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={handleExportAlertsJson}
            disabled={!hasAlerts}
            className="rounded-full border border-slate-700 bg-slate-950/60 px-3 py-1.5 text-[0.7rem] text-slate-100 hover:border-emerald-500/70 hover:bg-slate-900/80 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Export alerts (JSON)
          </button>
          <button
            type="button"
            onClick={handleExportAlertsCsv}
            disabled={!hasAlerts}
            className="rounded-full border border-slate-700 bg-slate-950/60 px-3 py-1.5 text-[0.7rem] text-slate-100 hover:border-emerald-500/70 hover:bg-slate-900/80 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Export alerts (CSV)
          </button>
          <button
            type="button"
            onClick={handleExportAlertsMarkdown}
            disabled={!hasAlerts}
            className="rounded-full border border-slate-700 bg-slate-950/60 px-3 py-1.5 text-[0.7rem] text-slate-100 hover:border-emerald-500/70 hover:bg-slate-900/80 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Export alerts (.md)
          </button>
          <button
            type="button"
            onClick={handleCopyAlertsMarkdown}
            disabled={!hasAlerts}
            className="rounded-full border border-emerald-500/70 bg-emerald-500/10 px-3 py-1.5 text-[0.7rem] font-medium text-emerald-100 hover:bg-emerald-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Copy alerts (Markdown)
          </button>
        </div>
      </div>

      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-2">
          <label className="text-[0.7rem] text-slate-400">Search alerts</label>
          <input
            value={alertSearch}
            onChange={(e) => setAlertSearch(e.target.value)}
            className="w-72 max-w-full rounded-full border border-slate-700 bg-slate-950/60 px-3 py-1 text-[0.7rem] text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500/60"
            placeholder="type, entity, description..."
          />
        </div>

        <label className="inline-flex items-center gap-2 text-[0.7rem] text-slate-400">
          <input
            type="checkbox"
            checked={groupAlertsByType}
            onChange={(e) => setGroupAlertsByType(e.target.checked)}
            className="h-3 w-3 rounded border-slate-600 bg-slate-900"
          />
          Group by rule type
        </label>
      </div>

      {clipboardMessage && (
        <div className="text-[0.7rem] text-emerald-300">
          {clipboardMessage}
        </div>
      )}

      {alerts.length === 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 text-xs text-slate-300">
          No alerts generated for the current dataset. Upload logs that contain
          failed and successful authentication events (e.g. SSH, Windows
          logons, web login failures) to see brute-force and suspicious-success
          patterns.
        </div>
      ) : (
          groupAlertsByType && groupedAlerts ? (
            <div className="space-y-3">
              {groupedAlerts.map(([type, list]) => {
                const isOpen = expandedAlertTypes.has(type)

                return (
                  <div
                    key={type}
                    className="rounded-2xl border border-slate-800 bg-slate-950/60"
                  >
                    <button
                      type="button"
                      onClick={() => {
                        setExpandedAlertTypes((prev) => {
                          const next = new Set(prev)
                          if (next.has(type)) next.delete(type)
                          else next.add(type)
                          return next
                        })
                      }}
                      className="w-full flex items-center justify-between gap-2 px-3 py-2 text-left"
                    >
                      <div className="text-[0.75rem] font-semibold text-slate-100">
                        {type}{' '}
                        <span className="ml-2 text-[0.7rem] font-normal text-slate-400">
                          ({list.length})
                        </span>
                      </div>
                      <span className="text-slate-400 text-[0.8rem]">
                        {isOpen ? '▾' : '▸'}
                      </span>
                    </button>

                    {isOpen && (
                      <div className="px-3 pb-3 grid gap-3 md:grid-cols-2">
                        {list.map(renderAlertCard)}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {visibleAlerts.map(renderAlertCard)}
            </div>
          )
        )}
    </div>
  )

  const renderOptionsPanel = () => (
    <section className="mt-4 border border-slate-800 rounded-2xl bg-slate-950/70 p-3 space-y-3">
      <h3 className="text-sm font-semibold text-slate-100">
        Options & Environment
      </h3>
      <p className="text-[0.7rem] text-slate-400">
        Configure IP-to-region mapping for geo-based detections. 
        Mark regions as &quot;Home&quot; to enable geo-anomaly rules. All settings are stored locally.
      </p>

      <div className="grid gap-3 md:grid-cols-2">
        <div className="space-y-2">
          <label className="block text-xs font-medium text-slate-400 mb-1">
            Home prefixes (whitelist):
          </label>

          {availablePrefixes.length === 0 ? (
            <p className="text-[0.7rem] text-slate-500">
              Select one or more prefixes as &quot;Home&quot;.
              Requires an IP-to-country mapping.
            </p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {availablePrefixes.map((item) => {
                const isSelected = homePrefixes.includes(item.prefix)

                return (
                  <button
                    key={item.prefix}
                    type="button"
                    onClick={() =>
                      setHomePrefixes((prev) =>
                        prev.includes(item.prefix)
                          ? prev.filter((p) => p !== item.prefix)
                          : [...prev, item.prefix],
                      )
                    }
                    className={[
                      'px-2 py-1 rounded-full border text-[0.7rem]',
                      isSelected
                        ? 'border-emerald-400 bg-emerald-500/10 text-emerald-100'
                        : 'border-slate-700 bg-slate-950/40 text-slate-300 hover:border-slate-500',
                    ].join(' ')}
                  >
                    <span className="font-mono">{item.prefix}</span>
                    {item.label ? (
                      <span className="ml-2 text-slate-400">({item.label})</span>
                    ) : null}
                  </button>
                )
              })}
            </div>
          )}

          <label className="mt-1 flex items-center gap-2 text-[0.7rem] text-slate-400">
            <input
              type="checkbox"
              checked={geoEnabled}
              onChange={(e) => setGeoEnabled(e.target.checked)}
              className="h-3 w-3 rounded border-slate-600 bg-slate-900"
            />
            Enable geo-anomaly detections
          </label>
          {detectionContext.enableGeo ? (
            <p className="text-[0.65rem] text-emerald-300">
              Geo-based rules enabled ({homePrefixList.length} home prefix{homePrefixList.length === 1 ? '' : 'es'})
            </p>
          ) : (
            <p className="text-[0.65rem] text-slate-500">
              Geo rules apply only when enabled and properly configured
            </p>
          )}
        </div>

        <div className="space-y-2">
          <label className="block text-xs font-medium text-slate-400 mb-1">
            IP-to-country mapping (JSON or CSV)
          </label>
          <textarea
            value={geoMappingRaw}
            onChange={(e) => setGeoMappingRaw(e.target.value)}
            rows={5}
            className="w-full rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2 text-[0.7rem] font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500/60"
            placeholder={`Examples:

CSV:
ipPrefix,geoCountry
10.,INTERNAL
203.0.113.,US

JSON:
[
  { "prefix": "10.", "country": "INTERNAL" },
  { "prefix": "203.0.113.", "country": "US" }
]`}
          />
          {geoMappingError ? (
            <p className="text-[0.65rem] text-rose-300">
              {geoMappingError}
            </p>
          ) : (
            <p className="text-[0.65rem] text-slate-500">
              Loaded {geoMappingEntries.length} mapping entries. Matching is
              prefix-based, e.g. <code>10.</code> will match{' '}
              <code>10.0.0.1</code>, <code>10.10.23.5</code>, etc.
            </p>
          )}
        </div>
      </div>
      <div className="mt-4">
        <label className="block text-sm text-slate-300 mb-1">
          Minimum severity to display
        </label>

        <select
          value={minSeverity}
          onChange={(e) => setMinSeverity(e.target.value)}
          className="w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-sm text-slate-100"
        >
          <option value="all">All</option>
          <option value="medium">Medium+</option>
          <option value="high">High only</option>
        </select>

        <p className="mt-1 text-xs text-slate-400 italic">
          Filters alerts after detections run
        </p>
      </div>
      <div>
        <label className="block text-sm text-slate-300 mb-1">
          Detection sensitivity
        </label>
        <select
          value={detectionPreset}
          onChange={(e) => setDetectionPreset(e.target.value)}
          className="w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-sm text-slate-100"
        >
          <option value="relaxed">Relaxed (fewer alerts)</option>
          <option value="balanced">Balanced (default)</option>
          <option value="strict">Strict (more aggressive)</option>
        </select>
        <p className="mt-1 text-xs text-slate-400 italic">
          Changes detection thresholds and severity scoring
        </p>
      </div>
    </section>
  )

  return (
    <div className="space-y-6">
      {/* Header + back */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <button
            type="button"
            onClick={onBack}
            className="text-xs inline-flex items-center gap-1 px-2 py-1 rounded-full border border-slate-700 text-slate-300 hover:border-emerald-400/60 hover:text-emerald-200 mb-2"
          >
            <span className="text-sm">←</span>
            Back to Hub
          </button>

          <h2 className="text-lg sm:text-xl font-semibold">
            Mini SIEM WebApp
          </h2>
          <p className="text-xs sm:text-sm text-slate-300">
            Upload logs, normalize events and run local correlation rules to
            surface brute-force patterns, suspicious login successes and basic
            geo anomalies. All analysis happens in your browser.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800/80 text-xs">
        <button
          type="button"
          onClick={() => setActiveTab('logs')}
          className={[
            'relative px-3 py-2',
            activeTab === 'logs'
              ? 'text-slate-50'
              : 'text-slate-400 hover:text-slate-200',
          ].join(' ')}
        >
          Logs
          {activeTab === 'logs' && (
            <span className="absolute inset-x-2 bottom-0 h-0.5 rounded-full bg-emerald-500" />
          )}
        </button>
        <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={[
            'relative px-3 py-2',
            activeTab === 'overview'
                ? 'text-slate-50'
                : 'text-slate-400 hover:text-slate-200',
            ].join(' ')}
        >
            Overview
            {activeTab === 'overview' && (
            <span className="absolute inset-x-2 bottom-0 h-0.5 rounded-full bg-emerald-500" />
            )}
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('alerts')}
          className={[
            'relative px-3 py-2 flex items-center gap-1 transition-colors',
            activeTab === 'alerts'
              ? 'text-slate-50'
              : hasAlerts
              ? 'text-rose-300 hover:text-rose-200'
              : 'text-slate-400 hover:text-slate-200',
          ].join(' ')}
        >
          <span>
            Alerts{hasAlerts ? ` (${alerts.length})` : ''}
          </span>
          {hasAlerts && (
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-rose-400 animate-pulse" />
          )}
          {activeTab === 'alerts' && (
            <span className="absolute inset-x-2 bottom-0 h-0.5 rounded-full bg-emerald-500" />
          )}
        </button>
      </div>

      {activeTab === 'logs' && renderLogsTab()}
        {activeTab === 'overview' && (
        <MiniSiemOverviewTab events={events} alerts={alerts} />
        )}
        {activeTab === 'alerts' && renderAlertsTab()}

      {renderOptionsPanel()}

      {/* Shared About & Privacy */}
      <section className="mt-4 pt-4 border-t border-slate-800">
        <AboutSection />
      </section>
    </div>
    
  )
}

export default MiniSiem