const DEFAULT_BUCKET_MS = 15 * 60 * 1000;

// ---------- Normalize & sorting ----------

function normalizeEventsForDetection(events) {
  if (!Array.isArray(events)) return [];

  const normalized = events
    .map((ev, idx) => {
      const ts =
        ev && ev.timestamp instanceof Date
          ? ev.timestamp
          : ev && typeof ev.timestamp === 'string'
          ? new Date(ev.timestamp)
          : null;

      const outcomeNorm = safeLower(ev?.outcome);
      const normalizedOutcome =
        outcomeNorm === 'success'
          ? 'success'
          : outcomeNorm === 'fail'
          ? 'fail'
          : ev?.outcome ?? null;

      return {
        ...ev,
        timestamp: ts,
        outcome: normalizedOutcome,
        index:
          typeof ev.index === 'number' && Number.isFinite(ev.index)
            ? ev.index
            : idx + 1,
      };
    })
    .filter(
      (ev) =>
        ev &&
        ev.timestamp instanceof Date &&
        !Number.isNaN(ev.timestamp.getTime()),
    );

  normalized.sort((a, b) => {
    const tDiff = a.timestamp.getTime() - b.timestamp.getTime();
    if (tDiff !== 0) return tDiff;
    return (a.index || 0) - (b.index || 0);
  });

  return normalized;
}

// ---------- Dataset quality signals (always-on) ----------

function detectQualitySignals(rawEvents, normalizedEvents, options = {}) {
  const { preset, qualityThresholds } = options;
  const alerts = [];

  const total = Array.isArray(rawEvents) ? rawEvents.length : 0;
  const kept = Array.isArray(normalizedEvents) ? normalizedEvents.length : 0;
  if (total <= 0) return [];

  const tsCoverage = (kept / total) * 100;
  const minTotal = qualityThresholds?.minTotalEvents ?? 50;
  const minTsCoveragePct = qualityThresholds?.minTimestampCoveragePct ?? 70;

  if (total >= minTotal && tsCoverage < minTsCoveragePct) {
    const dropped = total - kept;

    alerts.push(
      makeAlert({
        type: 'quality.low-timestamp-coverage',
        domain: 'general',
        severity: 'medium',
        confidence: clampConfidence(70 + (preset === 'strict' ? 5 : 0)),
        title: 'Low timestamp parsing coverage',
        description:
          `Only ${Math.round(tsCoverage)}% of events had a valid timestamp (${kept}/${total}). ` +
          `${dropped} event(s) were ignored because they could not be time-ordered. ` +
          `This often happens when timestamps are missing or malformed.`,
        remediation:
          'Ensure your input includes a "timestamp" field (ISO8601 preferred). If your data uses a different field name, map/rename it before importing.',
        events: normalizedEvents.slice(-10),
        evidence: {
          totalEvents: total,
          validTimestampEvents: kept,
          timestampCoveragePct: Math.round(tsCoverage),
        },
      }),
    );
  }

  if (kept >= minTotal) {
    const auth = normalizedEvents.filter(isAuthEvent).length;
    const web = normalizedEvents.filter(isWebEvent).length;
    const dns = normalizedEvents.filter(isDnsEvent).length;
    const net = normalizedEvents.filter(isNetEvent).length;
    const endpoint = normalizedEvents.filter(isEndpointEvent).length;

    // Rough signal
    const anyClassified = auth + web + dns + net + endpoint;
    const coverage = (anyClassified / kept) * 100;
    const minDomainCoveragePct = qualityThresholds?.minDomainCoveragePct ?? 25;

    if (coverage < minDomainCoveragePct) {
      alerts.push(
        makeAlert({
          type: 'quality.low-field-coverage',
          domain: 'general',
          severity: 'low',
          confidence: clampConfidence(55 + (preset === 'strict' ? 5 : 0)),
          title: 'Low structured field coverage',
          description:
            `Only ~${Math.round(coverage)}% of time-parsed events matched any built-in domain classifier. ` +
            `This usually means field names differ or key fields are missing (sourceIp/httpPath/dnsQname/etc).`,
          remediation:
            'If possible, export richer fields (sourceIp, username, httpPath/httpStatus, dnsQname/dnsRcode, destIp/destPort, processName/processCmd) or add a mapping layer before import.',
          events: normalizedEvents.slice(-10),
          evidence: {
            normalizedEvents: kept,
            approxDomainCoveragePct: Math.round(coverage),
            domainCounts: { auth, web, dns, net, endpoint },
          },
        }),
      );
    }
  }

  return alerts;
}

// ---------- Utility helpers ----------

function buildRowRangeDescription(relatedEvents) {
  if (!relatedEvents || relatedEvents.length === 0) return '';
  const indexes = relatedEvents
    .map((e) => e.index)
    .filter((i) => typeof i === 'number' && Number.isFinite(i));

  if (indexes.length === 0) return '';

  const min = Math.min(...indexes);
  const max = Math.max(...indexes);

  if (min === max) return `Row ${min}`;
  return `Rows ${min}-${max}`;
}

function safeLower(v) {
  return (v == null ? '' : String(v)).toLowerCase();
}

function isFiniteNumber(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function hasAnyField(events, fieldName) {
  return (events || []).some(
    (e) => e && e[fieldName] != null && String(e[fieldName]).trim() !== '',
  );
}

function hasAnyNumberField(events, fieldName) {
  return (events || []).some((e) => e && isFiniteNumber(e[fieldName]));
}

function ipMatchesAnyPrefix(ip, prefixes) {
  if (!ip || !Array.isArray(prefixes) || prefixes.length === 0) return false;
  const s = String(ip);
  return prefixes.some((p) => {
    const pref = String(p || '').trim().split(/[,\s]/)[0];
    if (!pref) return false;
    return s.startsWith(pref);
  });
}

function normalizeHomePrefixEntries(input) {
  // Accept:
  // ["203.", "10.0."] (array of strings)
  // [{ ipPrefix:"203.", country:"HOME" }, ...] (table rows)
  // [{ prefix:"203." }, ...], [{ value:"203." }, ...] (fallback shapes)
  if (!Array.isArray(input)) return { prefixes: [], countries: [] };

  const prefixes = [];
  const countries = [];

  input.forEach((item) => {
    if (item == null) return;

    if (typeof item === 'string' || typeof item === 'number') {
      const p = String(item).trim();
      if (p) prefixes.push(p);
      return;
    }

    if (typeof item === 'object') {
      const p =
        item.ipPrefix ??
        item.prefix ??
        item.value ??
        item.ip ??
        item.cidr ??
        null;

      const c =
        item.country ??
        item.label ??
        item.name ??
        null;

      const pref = p != null ? String(p).trim() : '';
      if (pref) prefixes.push(pref);

      const country = c != null ? String(c).trim() : '';
      if (country) countries.push(country);
    }
  });

  return {
    prefixes: prefixes.filter(Boolean),
    countries: countries.filter(Boolean),
  };
}

// ---------- Alert ID + shape ----------

let ALERT_COUNTER = 0;
function nextAlertId(prefix) {
  ALERT_COUNTER += 1;
  return `${prefix || 'alert'}-${ALERT_COUNTER}`;
}

function detectDetectedAt(events) {
  return (
    (events || [])
      .map((e) => (e?.timestamp instanceof Date ? e.timestamp : null))
      .filter(Boolean)
      .sort((a, b) => a.getTime() - b.getTime())
      .at(-1) || null
  );
}

function makeAlert({
  type,
  severity,
  description,
  events,
  remediation,
  domain,
  confidence,
  title,
  evidence,
}) {
  const relatedEventIds = [];
  const relatedEventIndexes = [];

  (events || []).forEach((ev) => {
    if (ev && ev.id) relatedEventIds.push(ev.id);
    if (typeof ev.index === 'number') relatedEventIndexes.push(ev.index);
  });

  return {
    id: nextAlertId(type),
    type,
    severity,
    timestamp: detectDetectedAt(events),
    title: title || type,
    domain: domain || 'general',
    confidence: isFiniteNumber(confidence)
      ? Math.max(0, Math.min(100, Math.round(confidence)))
      : null,
    description,
    remediation: remediation || null,
    relatedEventIds,
    relatedEventIndexes,
    evidence: evidence || null,
  };
}

// ---------- Alert deduplication ----------

function suppressBruteforceIpWhenSpray(alerts, options = {}) {
  const { bucketMs = 15 * 60 * 1000 } = options;

  const sprayBuckets = new Set();

  (alerts || []).forEach((a) => {
    if (!a || a.type !== 'spray.ip') return;
    const ip = a?.evidence?.ip;
    const ts = a.timestamp instanceof Date ? a.timestamp.getTime() : null;
    if (!ip || ts == null) return;
    const bucket = Math.floor(ts / bucketMs);
    sprayBuckets.add(`${ip}::${bucket}`);
  });

  return (alerts || []).filter((a) => {
    if (!a || a.type !== 'bruteforce.ip') return true;
    const ip = a?.evidence?.sourceIp || a?.evidence?.key;
    const ts = a.timestamp instanceof Date ? a.timestamp.getTime() : null;
    if (!ip || ts == null) return true;
    const bucket = Math.floor(ts / bucketMs);

    // If spray fired → drop bruteforce.ip
    return !sprayBuckets.has(`${ip}::${bucket}`);
  });
}

function suppressBruteforceIpWhenUserOverlap(alerts, options = {}) {
  const { bucketMs = 15 * 60 * 1000, minShared = 3, overlapPct = 0.6 } = options;

  // index bruteforce.user by bucket
  const userByBucket = new Map();

  (alerts || []).forEach((a) => {
    if (!a || a.type !== 'bruteforce.user') return;
    const ts = a.timestamp instanceof Date ? a.timestamp.getTime() : null;
    if (ts == null) return;
    const bucket = Math.floor(ts / bucketMs);
    const key = String(bucket);
    if (!userByBucket.has(key)) userByBucket.set(key, []);
    userByBucket.get(key).push(a);
  });

  return (alerts || []).filter((a) => {
    if (!a || a.type !== 'bruteforce.ip') return true;

    const ts = a.timestamp instanceof Date ? a.timestamp.getTime() : null;
    if (ts == null) return true;
    const bucket = Math.floor(ts / bucketMs);
    const candidates = userByBucket.get(String(bucket)) || [];
    if (candidates.length === 0) return true;

    const ipIndexes = new Set(a.relatedEventIndexes || []);
    const ipSize = ipIndexes.size;
    if (ipSize === 0) return true;

    for (const u of candidates) {
      const userIndexes = new Set(u.relatedEventIndexes || []);
      if (userIndexes.size === 0) continue;

      let shared = 0;
      ipIndexes.forEach((idx) => {
        if (userIndexes.has(idx)) shared += 1;
      });

      const pct = shared / Math.min(ipSize, userIndexes.size);

      // If overlap, prefer bruteforce.user and drop bruteforce.ip
      if (shared >= minShared && pct >= overlapPct) {
        return false;
      }
    }

    return true;
  });
}

function dedupeAlerts(alerts, options = {}) {
  const {
    bucketMs = 15 * 60 * 1000,
  } = options;

  const seen = new Map();
  const result = [];

  for (const alert of alerts || []) {
    if (!alert) continue;

    const ts = alert.timestamp instanceof Date ? alert.timestamp.getTime() : null;

    const bucket = ts != null ? Math.floor(ts / bucketMs) : 'no-ts';

    // Εxtract stable "primary key"
    const ev = alert.evidence || {};
    const primaryKey =
      ev.sourceIp ||
      ev.ip ||
      ev.username ||
      ev.user ||
      ev.host ||
      ev.source ||
      ev.key ||
      alert.type ||
      '(unknown)';

    const dedupeKey = [alert.type, alert.domain || 'general', primaryKey, bucket].join(
      '|',
    );

    if (alert.severity === 'low' && seen.has(dedupeKey)) {
      continue;
    }

    seen.set(dedupeKey, true);
    result.push(alert);
  }

  return result;
}

// ---------- Strictness presets ----------

function getPreset(options = {}) {
  const raw = (options.strictness || options.preset || '')
    .toString()
    .toLowerCase()
    .trim();
  if (raw === 'relaxed' || raw === 'lenient') return 'relaxed';
  if (raw === 'strict' || raw === 'aggressive') return 'strict';
  return 'balanced';
}

function thresholds(preset) {

  if (preset === 'relaxed') {
    return {
      quality: {
        minTotalEvents: 60,
        minTimestampCoveragePct: 65,
        minDomainCoveragePct: 20,
      },
      auth: {
        bruteforceMinFails: 7,
        bruteforceWindowMs: 12 * 60 * 1000,
        sprayMinUsers: 7,
        sprayWindowMs: 12 * 60 * 1000,
        noisyMinEvents: 60,
        noisyWindowMs: 10 * 60 * 1000,
        suspiciousSuccessMinFails: 4,
        suspiciousSuccessWindowMs: 12 * 60 * 1000,
      },
      web: {
        adminSensitivePaths: [
          '/admin',
          '/wp-admin',
          '/api/admin',
          '/admin/login',
          '/login',
          '/signin',
        ],
        adminMinEvents: 3,
        authzBurstMin: 12,
        authzBurstWindowMs: 10 * 60 * 1000,
        errors5xxMin: 15,
        errors5xxWindowMs: 15 * 60 * 1000,

        // LOW: rare non-GET/POST methods
        rareMethodsMin: 4,
        rareMethodsWindowMs: 20 * 60 * 1000,
      },
      net: {
        portScanMinPorts: 30,
        portScanWindowMs: 15 * 60 * 1000,

        // LOW: many distinct dest IPs
        destSweepMinHosts: 30,
        destSweepWindowMs: 20 * 60 * 1000,
      },
      dns: {
        nxdomainMin: 40,
        nxdomainWindowMs: 10 * 60 * 1000,

        // LOW: unusual qtypes/many TXT
        unusualQtypeMin: 25,
        unusualQtypeTxtMin: 30,
      },
      endpoint: {
        suspiciousProcMin: 2,
        suspiciousProcWindowMs: 20 * 60 * 1000,
        sensitiveWriteMin: 2,
        sensitiveWriteWindowMs: 30 * 60 * 1000,
        largeWriteBytes: 50 * 1024 * 1024,

        // LOW: exec from temp/downloads
        execTempMin: 3,
        execTempWindowMs: 45 * 60 * 1000,
      },
      geo: {
        newRegionSeverity: 'medium',
        externalRegionSeverity: 'high',
      },
    };
  }

  if (preset === 'strict') {
    return {
      quality: {
        minTotalEvents: 40,
        minTimestampCoveragePct: 80,
        minDomainCoveragePct: 30,
      },
      auth: {
        bruteforceMinFails: 4,
        bruteforceWindowMs: 8 * 60 * 1000,
        sprayMinUsers: 4,
        sprayWindowMs: 8 * 60 * 1000,
        noisyMinEvents: 30,
        noisyWindowMs: 10 * 60 * 1000,
        suspiciousSuccessMinFails: 2,
        suspiciousSuccessWindowMs: 8 * 60 * 1000,
      },
      web: {
        adminSensitivePaths: [
          '/admin',
          '/wp-admin',
          '/api/admin',
          '/admin/login',
          '/login',
          '/signin',
        ],
        adminMinEvents: 2,
        authzBurstMin: 8,
        authzBurstWindowMs: 10 * 60 * 1000,
        errors5xxMin: 10,
        errors5xxWindowMs: 15 * 60 * 1000,

        // LOW
        rareMethodsMin: 3,
        rareMethodsWindowMs: 15 * 60 * 1000,
      },
      net: {
        portScanMinPorts: 20,
        portScanWindowMs: 15 * 60 * 1000,

        // LOW
        destSweepMinHosts: 20,
        destSweepWindowMs: 15 * 60 * 1000,
      },
      dns: {
        nxdomainMin: 25,
        nxdomainWindowMs: 10 * 60 * 1000,

        // LOW
        unusualQtypeMin: 15,
        unusualQtypeTxtMin: 20,
      },
      endpoint: {
        suspiciousProcMin: 1,
        suspiciousProcWindowMs: 20 * 60 * 1000,
        sensitiveWriteMin: 1,
        sensitiveWriteWindowMs: 30 * 60 * 1000,
        largeWriteBytes: 20 * 1024 * 1024,

        // LOW
        execTempMin: 2,
        execTempWindowMs: 30 * 60 * 1000,
      },
      geo: {
        newRegionSeverity: 'medium',
        externalRegionSeverity: 'high',
      },
    };
  }

  // balanced
  return {
    quality: {
      minTotalEvents: 50,
      minTimestampCoveragePct: 70,
      minDomainCoveragePct: 25,
    },
    auth: {
      bruteforceMinFails: 5,
      bruteforceWindowMs: 10 * 60 * 1000,
      sprayMinUsers: 5,
      sprayWindowMs: 10 * 60 * 1000,
      noisyMinEvents: 40,
      noisyWindowMs: 10 * 60 * 1000,
      suspiciousSuccessMinFails: 3,
      suspiciousSuccessWindowMs: 10 * 60 * 1000,
    },
    web: {
      adminSensitivePaths: [
        '/admin',
        '/wp-admin',
        '/api/admin',
        '/admin/login',
        '/login',
        '/signin',
      ],
      adminMinEvents: 3,
      authzBurstMin: 10,
      authzBurstWindowMs: 10 * 60 * 1000,
      errors5xxMin: 12,
      errors5xxWindowMs: 15 * 60 * 1000,

      // LOW
      rareMethodsMin: 3,
      rareMethodsWindowMs: 15 * 60 * 1000,
    },
    net: {
      portScanMinPorts: 25,
      portScanWindowMs: 15 * 60 * 1000,

      // LOW
      destSweepMinHosts: 25,
      destSweepWindowMs: 15 * 60 * 1000,
    },
    dns: {
      nxdomainMin: 30,
      nxdomainWindowMs: 10 * 60 * 1000,

      // LOW
      unusualQtypeMin: 20,
      unusualQtypeTxtMin: 25,
    },
    endpoint: {
      suspiciousProcMin: 2,
      suspiciousProcWindowMs: 20 * 60 * 1000,
      sensitiveWriteMin: 2,
      sensitiveWriteWindowMs: 30 * 60 * 1000,
      largeWriteBytes: 30 * 1024 * 1024,

      // LOW
      execTempMin: 2,
      execTempWindowMs: 30 * 60 * 1000,
    },
    geo: {
      newRegionSeverity: 'medium',
      externalRegionSeverity: 'high',
    },
  };
}

// ---------- Domain classification helpers ----------

function isAuthEvent(ev) {
  if (!ev) return false;

  const t = safeLower(ev.eventType);
  const outcome = safeLower(ev.outcome);

  const looksAuthType =
    t.includes('auth') ||
    t.includes('login') ||
    t.includes('signin') ||
    t.includes('sshd') ||
    t.includes('rdp') ||
    t.includes('vpn') ||
    t.includes('windows') ||
    t.includes('4624') ||
    t.includes('4625');

  const hasOutcome = outcome === 'success' || outcome === 'fail';

  const isWebRequestish =
    t.includes('web.request') ||
    t.includes('web_access') ||
    t.includes('access') ||
    t.includes('http');

  if (isWebRequestish && !looksAuthType) return false;

  return (looksAuthType && hasOutcome) || (ev.mfa != null && hasOutcome);
}

function isWebEvent(ev) {
  const t = safeLower(ev?.eventType);
  if (t.includes('web.request') || t.includes('web_access') || t.includes('http'))
    return true;
  if (ev?.httpMethod || ev?.httpPath || isFiniteNumber(ev?.httpStatus)) return true;
  return false;
}

function isDnsEvent(ev) {
  const t = safeLower(ev?.eventType);
  if (t.includes('dns')) return true;
  if (ev?.dnsQname || ev?.dnsQtype || ev?.dnsRcode) return true;
  return false;
}

function isNetEvent(ev) {
  const t = safeLower(ev?.eventType);
  if (t.includes('net') || t.includes('conn') || t.includes('flow')) return true;
  if (
    isFiniteNumber(ev?.destPort) ||
    isFiniteNumber(ev?.bytesIn) ||
    isFiniteNumber(ev?.bytesOut)
  )
    return true;
  return false;
}

function isEndpointEvent(ev) {
  const t = safeLower(ev?.eventType);
  if (t.includes('process') || t.includes('proc') || t.includes('file')) return true;
  if (
    ev?.processName ||
    ev?.processCmd ||
    ev?.filePath ||
    isFiniteNumber(ev?.fileBytes)
  )
    return true;
  return false;
}

// ---------- Confidence helpers ----------

function baseConfidenceFromCount(count, min) {
  if (!isFiniteNumber(count) || !isFiniteNumber(min) || min <= 0) return 50;
  if (count <= min) return 60;
  const ratio = Math.min(3, count / min);
  return 60 + (ratio - 1) * 20;
}

function clampConfidence(c) {
  if (!isFiniteNumber(c)) return null;
  return Math.max(0, Math.min(100, Math.round(c)));
}

// ---------- Detection rules ----------

// ----- AUTH: brute-force cluster by key -----

function detectBruteforceByKey(authEvents, keyFn, opts) {
  const { minFails, windowMs, typePrefix, severity, preset } = opts || {};

  const alerts = [];
  const groups = new Map();

  // group events by provided key
  for (const ev of authEvents || []) {
    const key = keyFn?.(ev);
    if (!key) continue;
    const arr = groups.get(key);
    if (arr) arr.push(ev);
    else groups.set(key, [ev]);
  }

  const isIpKey = typePrefix === 'bruteforce.ip';
  const label = isIpKey ? 'IP' : 'username';
  const title = isIpKey
    ? 'Brute-force attempts from one IP'
    : 'Brute-force attempts against one user';

  const baseRemediationIp =
    'Rate-limit or block the source IP,and review for credential stuffing or scanning. If legitimate traffic is possible, tighten lockout thresholds and enforce MFA.';
  const baseRemediationUser =
    'Investigate whether the account is being targeted. Consider forcing a password reset, enabling MFA and checking for successful logins from unusual IPs.';

  function emitAlert(streak, key) {
    if (!streak || streak.length < minFails) return;

    const rowsText = buildRowRangeDescription(streak);
    const windowMinutes = Math.round(windowMs / 60000);

    const desc =
      `${rowsText ? rowsText + ' ' : ''}` +
      `Detected ${streak.length} failed logins for ${label} "${key}" within ${windowMinutes} minutes. ` +
      `This pattern is consistent with brute-force attempts.`;

    const confidence = clampConfidence(
      baseConfidenceFromCount(streak.length, minFails) + (preset === 'strict' ? 5 : 0),
    );

    // Populate sourceIp only when key is an IP
    const evidence = {
      key,
      ...(isIpKey ? { sourceIp: key } : { username: key }),
      fails: streak.length,
      windowMinutes,
    };

    alerts.push(
      makeAlert({
        type: typePrefix,
        domain: 'auth',
        severity,
        confidence,
        title,
        description: desc,
        remediation: isIpKey ? baseRemediationIp : baseRemediationUser,
        events: streak,
        evidence,
      }),
    );
  }

  for (const [key, list] of groups.entries()) {
    if (!list || list.length === 0) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let streak = [];
    for (const ev of list) {
      const isFail = ev.outcome === 'fail';

      if (isFail) {
        if (streak.length === 0) {
          streak.push(ev);
        } else {
          const diff = ev.timestamp.getTime() - streak[0].timestamp.getTime();
          if (diff <= windowMs) {
            streak.push(ev);
          } else {
            emitAlert(streak, key);
            streak = [ev];
          }
        }
      } else {
        emitAlert(streak, key);
        streak = [];
      }
    }

    // tail
    emitAlert(streak, key);
  }

  return alerts;
}

// ----- AUTH: suspicious success after failures (IP and user) -----

function detectSuspiciousSuccessAfterFails(authEvents, opts) {
  const { minFailsBeforeSuccess, windowMs, preset } = opts || {};
  const alerts = [];

  const ipFails = new Map();
  const userFails = new Map();

  function pushFail(map, key, ev) {
    if (!key) return;
    if (!map.has(key)) map.set(key, []);
    const arr = map.get(key);
    arr.push(ev);

    const cutoff = ev.timestamp.getTime() - windowMs;
    while (arr.length > 0 && arr[0].timestamp.getTime() < cutoff) arr.shift();
  }

  authEvents.forEach((ev) => {
    const ip = ev.sourceIp || null;
    const user = ev.username || null;

    if (ev.outcome === 'fail') {
      pushFail(ipFails, ip, ev);
      pushFail(userFails, user, ev);
      return;
    }

    if (ev.outcome !== 'success') return;

    const ipArr = ipFails.get(ip) || [];
    const userArr = userFails.get(user) || [];

    const ipFailCount = ipArr.length;
    const userFailCount = userArr.length;

    if (ip && ipFailCount >= minFailsBeforeSuccess) {
      const cluster = [...ipArr, ev];
      const rowsText = buildRowRangeDescription(cluster);

      const desc =
        `${rowsText ? rowsText + ' ' : ''}` +
        `Successful login from IP "${ip}" after ${ipFailCount} failures within ${Math.round(
          windowMs / 60000,
        )} minutes. This can indicate credential stuffing or a compromised account.`;

      const confidence = clampConfidence(
        baseConfidenceFromCount(ipFailCount, minFailsBeforeSuccess) +
          10 +
          (preset === 'strict' ? 5 : 0),
      );

      alerts.push(
        makeAlert({
          type: 'suspicious-success.ip',
          domain: 'auth',
          severity: 'high',
          confidence,
          title: 'Successful login after repeated failures (IP)',
          description: desc,
          remediation:
            'Validate whether this login is expected. If uncertain, reset credentials, revoke active sessions/tokens, enforce MFA and review additional activity from this IP.',
          events: cluster,
          evidence: {
            ip,
            failuresBeforeSuccess: ipFailCount,
            windowMinutes: Math.round(windowMs / 60000),
          },
        }),
      );
    }

    if (user && userFailCount >= minFailsBeforeSuccess) {
      const cluster = [...userArr, ev];
      const rowsText = buildRowRangeDescription(cluster);

      const desc =
        `${rowsText ? rowsText + ' ' : ''}` +
        `Successful login for username "${user}" after ${userFailCount} failures within ${Math.round(
          windowMs / 60000,
        )} minutes. This can indicate a compromised account or guessed credentials.`;

      const confidence = clampConfidence(
        baseConfidenceFromCount(userFailCount, minFailsBeforeSuccess) +
          10 +
          (preset === 'strict' ? 5 : 0),
      );

      alerts.push(
        makeAlert({
          type: 'suspicious-success.user',
          domain: 'auth',
          severity: 'high',
          confidence,
          title: 'Successful login after repeated failures (user)',
          description: desc,
          remediation:
            'Confirm the login with the user. If suspicious, force a password reset, revoke sessions/tokens, enforce MFA and review recent privileged actions.',
          events: cluster,
          evidence: {
            user,
            failuresBeforeSuccess: userFailCount,
            windowMinutes: Math.round(windowMs / 60000),
          },
        }),
      );
    }
  });

  return alerts;
}

// ----- AUTH: password spray -----

function detectPasswordSpray(authEvents, opts) {
  const { minDistinctUsers, windowMs, preset } = opts || {};
  const alerts = [];

  const byIp = new Map();
  authEvents.forEach((ev) => {
    const ip = ev.sourceIp || null;
    if (!ip) return;
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(ev);
  });

  for (const [ip, list] of byIp.entries()) {
    const failures = list.filter((ev) => ev.outcome === 'fail' && ev.username);
    if (failures.length < minDistinctUsers) continue;

    failures.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let start = 0;
    while (start < failures.length) {
      const startEv = failures[start];
      const cutoff = startEv.timestamp.getTime() + windowMs;

      const windowEvents = [];
      const usernames = new Set();

      let end = start;
      while (end < failures.length && failures[end].timestamp.getTime() <= cutoff) {
        const ev = failures[end];
        windowEvents.push(ev);
        if (ev.username) usernames.add(ev.username);
        end += 1;
      }

      if (usernames.size >= minDistinctUsers) {
        const rowsText = buildRowRangeDescription(windowEvents);
        const desc =
          `${rowsText ? rowsText + ' ' : ''}` +
          `IP "${ip}" produced failed logins for ${usernames.size} distinct usernames within ${Math.round(
            windowMs / 60000,
          )} minutes. This pattern matches password spraying.`;

        const confidence = clampConfidence(
          baseConfidenceFromCount(usernames.size, minDistinctUsers) +
            (preset === 'strict' ? 5 : 0),
        );

        alerts.push(
          makeAlert({
            type: 'spray.ip',
            domain: 'auth',
            severity: 'medium',
            confidence,
            title: 'Password spraying pattern from one IP',
            description: desc,
            remediation:
              'Block or throttle the source IP. Consider MFA, CAPTCHA and tighter lockout policies. Review whether targeted usernames are valid accounts and whether any logins succeeded shortly after.',
            events: windowEvents,
            evidence: {
              ip,
              sourceIp: ip,
              distinctUsers: usernames.size,
              windowMinutes: Math.round(windowMs / 60000),
            },
          }),
        );

        start = end;
      } else {
        start += 1;
      }
    }
  }

  return alerts;
}

// ----- AUTH: noisy auth IP -----

function detectNoisyAuthIp(authEvents, opts) {
  const { minEvents, windowMs, preset } = opts || {};
  const alerts = [];
  const byIp = new Map();

  authEvents.forEach((ev) => {
    const ip = ev.sourceIp || null;
    if (!ip) return;
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(ev);
  });

  for (const [ip, list] of byIp.entries()) {
    if (list.length < minEvents) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let start = 0;
    for (let end = 0; end < list.length; end += 1) {
      const evEnd = list[end];
      const cutoff = evEnd.timestamp.getTime() - windowMs;

      while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

      const windowEvents = list.slice(start, end + 1);
      if (windowEvents.length >= minEvents) {
        const rowsText = buildRowRangeDescription(windowEvents);

        const desc =
          `${rowsText ? rowsText + ' ' : ''}` +
          `IP "${ip}" generated ${windowEvents.length} authentication events within ${Math.round(
            windowMs / 60000,
          )} minutes. This may indicate scanning, misconfiguration or automation noise.`;

        const confidence = clampConfidence(
          baseConfidenceFromCount(windowEvents.length, minEvents) +
            (preset === 'strict' ? 5 : 0),
        );

        alerts.push(
          makeAlert({
            type: 'noisy.auth.ip',
            domain: 'auth',
            severity: 'medium',
            confidence,
            title: 'Unusually noisy authentication source IP',
            description: desc,
            remediation:
              'Confirm whether this IP is a known scanner, SSO gateway or automation. If unexpected, rate-limit/block and correlate with web, DNS and network telemetry.',
            events: windowEvents,
            evidence: {
              ip,
              events: windowEvents.length,
              windowMinutes: Math.round(windowMs / 60000),
            },
          }),
        );
        break;
      }
    }
  }

  return alerts;
}

// ----- AUTH (LOW): isolated single failure (likely benign) -----

function detectAuthIsolatedFailureLow(authEvents, opts = {}) {
  const { preset, claimedAuthIndexes, isolationWindowMs = 10 * 60 * 1000 } = opts;
  const alerts = [];
  const failsByIp = new Map();
  authEvents.forEach((ev) => {
    if (ev.outcome !== 'fail' || !ev.sourceIp) return;
    if (!failsByIp.has(ev.sourceIp)) failsByIp.set(ev.sourceIp, []);
    failsByIp.get(ev.sourceIp).push(ev);
  });

  if (!hasAnyField(authEvents, 'username')) return [];

  const byUser = new Map();
  authEvents.forEach((ev) => {
    const user = ev.username || '(unknown)';
    if (!byUser.has(user)) byUser.set(user, []);
    byUser.get(user).push(ev);
  });

  for (const [user, list] of byUser.entries()) {
    const fails = list.filter((e) => e.outcome === 'fail');
    if (fails.length === 0) continue;

    fails.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    for (let i = 0; i < fails.length; i += 1) {
      const failEv = fails[i];

      // If part of another auth alert → not isolated
      if (claimedAuthIndexes && claimedAuthIndexes.has(failEv.index)) continue;

      const prev = i > 0 ? fails[i - 1] : null;
      const next = i < fails.length - 1 ? fails[i + 1] : null;

      const prevClose =
        prev && failEv.timestamp.getTime() - prev.timestamp.getTime() <= isolationWindowMs;
      const nextClose =
        next && next.timestamp.getTime() - failEv.timestamp.getTime() <= isolationWindowMs;

      // Must be "alone" within window
      if (prevClose || nextClose) continue;

      const rowsText = buildRowRangeDescription([failEv]);
      const desc =
        `${rowsText ? rowsText + ' ' : ''}` +
        `Isolated login failure for user "${user}" with no other nearby failures (±${Math.round(
          isolationWindowMs / 60000,
        )} min). ` +
        `This is often benign (typo/timeouts), but may matter for sensitive or service accounts.`;

      // Ensure no nearby failures from same IP
      const ipFails = failsByIp.get(failEv.sourceIp) || [];
      const ts = failEv.timestamp.getTime();
      const ipHasNearby = ipFails.some(
        (e) =>
          e !== failEv &&
          Math.abs(e.timestamp.getTime() - ts) <= isolationWindowMs,
      );

      if (ipHasNearby) continue;      

      alerts.push(
        makeAlert({
          type: 'auth.isolated-failure',
          domain: 'auth',
          severity: 'low',
          confidence: clampConfidence(35 + (preset === 'strict' ? 5 : 0)),
          title: 'Isolated login failure (likely benign)',
          description: desc,
          remediation:
            'If this is a privileged or service account, verify the source and monitor for additional failures. Consider MFA and tighter lockout policies if failures increase.',
          events: [failEv],
          evidence: {
            user,
            sourceIp: failEv.sourceIp || null,
          },
        }),
      );
    }
  }
  return alerts;
}

// ----- AUTH: Success on a new account/service account -----
function detectAuthFirstSeenSuccess(authEvents, opts = {}) {
  const { preset, state, onStateUpdate } = opts;
  const alerts = [];

  const seen = (state && state.seenAuthUsers && typeof state.seenAuthUsers === 'object')
    ? { ...state.seenAuthUsers }
    : {};

  const serviceRe = /(^svc|service|daemon|batch|job|cron|system|testsvc)/i;

  const successes = (authEvents || []).filter((e) => e.outcome === 'success' && e.username);
  if (successes.length === 0) return [];

  successes.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  successes.forEach((ev) => {
    const user = String(ev.username || '').trim();
    if (!user) return;

    const alreadySeen = Boolean(seen[user]);

    if (!alreadySeen) {
      const isServiceLike = serviceRe.test(user);
      const sev = isServiceLike ? 'medium' : 'low';

      const rowsText = buildRowRangeDescription([ev]);
      const desc =
        `${rowsText ? rowsText + ' ' : ''}` +
        `First observed successful login for user "${user}" in the current baseline. ` +
        `This can be normal (new account/service), but can also indicate new access that should be verified.`;

      alerts.push(
        makeAlert({
          type: 'auth.first-seen-success',
          domain: 'auth',
          severity: sev,
          confidence: clampConfidence((isServiceLike ? 55 : 45) + (preset === 'strict' ? 5 : 0)),
          title: 'First-seen successful login',
          description: desc,
          remediation:
            'Confirm whether this account is expected and who owns it. If it’s a service account, ensure MFA/policies are appropriate, privileges are minimal and activity is limited to expected hosts/apps.',
          events: [ev],
          evidence: {
            user,
            sourceIp: ev.sourceIp || null,
            host: ev.host || null,
            serviceLike: isServiceLike,
          },
        }),
      );

      seen[user] = true;
    }
  });

  if (typeof onStateUpdate === 'function') {
    onStateUpdate({ ...(state || {}), seenAuthUsers: seen });
  }

  return alerts;
}

// ----- GEO: anomalies (requires geo enabled) -----

function detectGeoAnomalies(events, homeIpPrefixes, options = {}) {

  // Whitelist-only
  if (!options.enableGeo) return [];
  if (!Array.isArray(homeIpPrefixes) || homeIpPrefixes.length === 0) return [];

  const bucketMs = DEFAULT_BUCKET_MS;
  const alerts = [];

  const seenGeoUserRegions =
    options?.state &&
    typeof options.state === 'object' &&
    options.state.seenGeoUserRegions &&
    typeof options.state.seenGeoUserRegions === 'object'
      ? { ...options.state.seenGeoUserRegions }
      : {};

  const homeCountries = Array.isArray(options.homeCountries)
    ? options.homeCountries.map((c) => String(c).trim()).filter(Boolean)
    : [];

  const dedupe = new Set();

  for (let i = 0; i < (events || []).length; i++) {
    const ev = events[i];
    if (!isAuthEvent(ev)) continue;
    if (ev.outcome !== 'success') continue;
    if (!ev.sourceIp) continue;

    const ip = ev.sourceIp;

    const isHome = ipMatchesAnyPrefix(ip, homeIpPrefixes);
    if (isHome) continue;

    const user = ev.user || ev.username || ev.account || 'unknown';

    // bucket for dedupe stability
    const tsMs = ev.timestamp instanceof Date ? ev.timestamp.getTime() : NaN;
    const bucket = Number.isFinite(tsMs) ? Math.floor(tsMs / bucketMs) : 'na';

    // ---------- Alert 1: geo.external-region ----------
    {
      const key = `external|${user}|${ip}|${bucket}`;
      if (!dedupe.has(key)) {
        dedupe.add(key);

        const severity = options?.geoThresholds?.externalRegionSeverity || 'high';

        alerts.push(
          makeAlert({
            type: 'geo.external-region',
            domain: 'geo',
            severity,
            confidence: clampConfidence(75 + (options.preset === 'strict' ? 5 : 0)),
            title: 'Successful auth from non-home IP',
            description: `Successful authentication for ${user} from ${ip} (not in home whitelist).`,
            remediation:
              'Confirm whether this login is expected for the user. If not, revoke active sessions/tokens, reset credentials, enforce MFA and review other activity from this IP/time window.',
            events: [ev],
            evidence: {
              user,
              sourceIp: ip,
              homeIpPrefixes: homeIpPrefixes.slice(0, 20),
              bucket,

              homeCountries: homeCountries.slice(0, 20),
              geoCountry: ev.geoCountry || null,
            },
          }),
        );
      }
    }

    // ---------- Alert 2: geo.new-region (stateful, optional) ----------
    {
      const regionLabel = ev.geoCountry != null ? String(ev.geoCountry).trim() : '';
      if (!regionLabel) continue;

      const isHomeRegion = homeCountries.length > 0 && homeCountries.includes(regionLabel);
      if (isHomeRegion) continue; 

      const userKey = String(user);
      if (!seenGeoUserRegions[userKey]) seenGeoUserRegions[userKey] = {};
      const alreadySeen = Boolean(seenGeoUserRegions[userKey][regionLabel]);

      if (!alreadySeen) {
        seenGeoUserRegions[userKey][regionLabel] = true;

        const key = `new-region|${userKey}|${regionLabel}|${bucket}`;
        if (!dedupe.has(key)) {
          dedupe.add(key);

          const severity = options?.geoThresholds?.newRegionSeverity || 'medium';

          alerts.push(
            makeAlert({
              type: 'geo.new-region',
              domain: 'geo',
              severity,
              confidence: clampConfidence(65 + (options.preset === 'strict' ? 5 : 0)),
              title: 'First-seen auth region for user',
              description:
                `First observed successful authentication for ${userKey} from region "${regionLabel}". ` +
                `This can be legitimate travel/VPN/provider change, but should be verified.`,
              remediation:
                'If unexpected, verify with the user, review device posture, revoke sessions/tokens, enforce MFA and check for additional logins from the same region/IP range.',
              events: [ev],
              evidence: {
                user: userKey,
                sourceIp: ip,
                region: regionLabel,
                bucket,
                homeCountries: homeCountries.slice(0, 20),
              },
            }),
          );
        }
      }
    }
  }

  if (typeof options.onStateUpdate === 'function') {
    options.onStateUpdate({
      ...(options.state || {}),
      seenGeoUserRegions,
    });
  }

  return alerts;
}

// ----- WEB: admin/sensitive endpoint activity -----

function detectWebAdminSensitive(webEvents, opts) {
  const { sensitivePaths, minEvents, preset } = opts || {};
  const alerts = [];

  const paths = (sensitivePaths || []).map((p) => String(p).toLowerCase());

  const byIp = new Map();
  webEvents.forEach((ev) => {
    const ip = ev.sourceIp || null;
    const path = safeLower(ev.httpPath || ev.path || '');
    if (!ip || !path) return;

    const hit = paths.some(
      (sp) => path === sp || path.startsWith(sp + '/') || path.includes(sp),
    );
    if (!hit) return;

    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(ev);
  });

  for (const [ip, list] of byIp.entries()) {
    if (list.length < minEvents) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    const dangerous = list.filter((e) => {
      const m = safeLower(e.httpMethod || e.method || '');
      return m === 'delete' || m === 'put' || m === 'patch';
    });

    const rowsText = buildRowRangeDescription(list);
    const examplePath =
      safeLower(list[0]?.httpPath || list[0]?.path || '') || '(unknown path)';

    const desc =
      `${rowsText ? rowsText + ' ' : ''}` +
      `IP "${ip}" accessed sensitive/admin paths (e.g., "${examplePath}") ${list.length} time(s).` +
      (dangerous.length
        ? ` ${dangerous.length} request(s) used modification methods (PUT/PATCH/DELETE).`
        : '');

    const confidence = clampConfidence(
      60 +
        Math.min(30, list.length * 5) +
        (dangerous.length ? 10 : 0) +
        (preset === 'strict' ? 5 : 0),
    );

    const severity = dangerous.length ? 'high' : 'medium';

    alerts.push(
      makeAlert({
        type: 'web.admin-sensitive',
        domain: 'web',
        severity,
        confidence,
        title: 'Sensitive/admin endpoint access',
        description: desc,
        remediation:
          'Confirm whether the source is authorized (admin user, internal tool, monitoring). If not expected, block or challenge the IP (WAF), review authentication events and inspect related requests around the same time window.',
        events: list,
        evidence: {
          ip,
          hits: list.length,
          dangerousMethods: dangerous.length,
        },
      }),
    );
  }

  return alerts;
}

// ----- WEB: authorization failures burst (401/403) -----

function detectWebAuthzBurst(webEvents, opts) {
  const { minEvents, windowMs, preset } = opts || {};
  const alerts = [];

  const byIp = new Map();
  webEvents.forEach((ev) => {
    const ip = ev.sourceIp || null;
    const status =
      ev.httpStatus != null
        ? Number(ev.httpStatus)
        : ev.status != null
        ? Number(ev.status)
        : null;
    if (!ip || !Number.isFinite(status)) return;
    if (status !== 401 && status !== 403) return;

    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(ev);
  });

  for (const [ip, list] of byIp.entries()) {
    if (list.length < minEvents) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let start = 0;
    for (let end = 0; end < list.length; end += 1) {
      const cutoff = list[end].timestamp.getTime() - windowMs;
      while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

      const windowEvents = list.slice(start, end + 1);
      if (windowEvents.length >= minEvents) {
        const rowsText = buildRowRangeDescription(windowEvents);

        const desc =
          `${rowsText ? rowsText + ' ' : ''}` +
          `IP "${ip}" generated ${windowEvents.length} HTTP 401/403 responses within ${Math.round(
            windowMs / 60000,
          )} minutes. This can indicate brute-force against web auth, token abuse or endpoint discovery.`;

        const confidence = clampConfidence(
          baseConfidenceFromCount(windowEvents.length, minEvents) +
            (preset === 'strict' ? 5 : 0),
        );

        alerts.push(
          makeAlert({
            type: 'web.authz-burst',
            domain: 'web',
            severity: 'medium',
            confidence,
            title: 'Burst of authorization failures (401/403)',
            description: desc,
            remediation:
              'Inspect the targeted paths, user agents, and whether requests include valid tokens. Consider rate-limiting, WAF rules, and correlating with authentication logs for the same IP/user.',
            events: windowEvents,
            evidence: {
              ip,
              count: windowEvents.length,
              windowMinutes: Math.round(windowMs / 60000),
            },
          }),
        );
        break;
      }
    }
  }

  return alerts;
}

// ----- WEB: server errors spike (5xx) -----

function detectWeb5xxSpike(webEvents, opts) {
  const { minErrors, windowMs, preset } = opts || {};
  const alerts = [];

  const keyFn = (ev) => ev.host || ev.sourceApp || 'web';
  const byKey = new Map();

  webEvents.forEach((ev) => {
    const status =
      ev.httpStatus != null
        ? Number(ev.httpStatus)
        : ev.status != null
        ? Number(ev.status)
        : null;
    if (!Number.isFinite(status)) return;
    if (status < 500 || status > 599) return;

    const key = keyFn(ev);
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(ev);
  });

  for (const [key, list] of byKey.entries()) {
    if (list.length < minErrors) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let start = 0;
    for (let end = 0; end < list.length; end += 1) {
      const cutoff = list[end].timestamp.getTime() - windowMs;
      while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

      const windowEvents = list.slice(start, end + 1);
      if (windowEvents.length >= minErrors) {
        const rowsText = buildRowRangeDescription(windowEvents);

        const desc =
          `${rowsText ? rowsText + ' ' : ''}` +
          `"${key}" produced ${windowEvents.length} HTTP 5xx responses within ${Math.round(
            windowMs / 60000,
          )} minutes. This can indicate outages, failed deployments or exploitation attempts causing errors.`;

        const confidence = clampConfidence(
          baseConfidenceFromCount(windowEvents.length, minErrors) +
            (preset === 'strict' ? 5 : 0),
        );

        alerts.push(
          makeAlert({
            type: 'web.errors-5xx',
            domain: 'web',
            severity: 'medium',
            confidence,
            title: 'Spike in server errors (5xx)',
            description: desc,
            remediation:
              'Check deployment/health metrics and identify failing routes. If errors correlate with unusual paths or suspicious IPs, investigate for exploitation (e.g., fuzzing, injection) and add WAF protections.',
            events: windowEvents,
            evidence: {
              key,
              count: windowEvents.length,
              windowMinutes: Math.round(windowMs / 60000),
            },
          }),
        );
        break;
      }
    }
  }

  return alerts;
}

// ----- WEB (LOW): rare HTTP methods (PUT/PATCH/DELETE) excluding admin-sensitive paths -----

function detectWebRareMethodsLow(webEvents, opts) {
  const { minEvents, windowMs, preset, adminSensitivePaths } = opts || {};
  const alerts = [];

  const paths = (adminSensitivePaths || []).map((p) => String(p).toLowerCase());
  const isAdminSensitivePath = (p) => {
    const path = safeLower(p || '');
    if (!path) return false;
    return paths.some(
      (sp) => path === sp || path.startsWith(sp + '/') || path.includes(sp),
    );
  };

  const candidates = webEvents.filter((e) => {
    const m = safeLower(e.httpMethod || e.method || '');
    const p = e.httpPath || e.path || '';
    if (!m) return false;
    if (m === 'get' || m === 'post') return false;

    if (isAdminSensitivePath(p)) return false;

    return Boolean(e.sourceIp || e.host || e.sourceApp);
  });

  if (candidates.length < minEvents) return [];

  const keyFn = (ev) => ev.sourceIp || ev.host || ev.sourceApp || '(unknown)';
  const byKey = new Map();

  candidates.forEach((ev) => {
    const key = keyFn(ev);
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(ev);
  });

  for (const [key, list] of byKey.entries()) {
    if (list.length < minEvents) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let start = 0;
    for (let end = 0; end < list.length; end += 1) {
      const cutoff = list[end].timestamp.getTime() - windowMs;
      while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

      const windowEvents = list.slice(start, end + 1);
      if (windowEvents.length < minEvents) continue;

      const methods = {};
      windowEvents.forEach((e) => {
        const m = safeLower(e.httpMethod || e.method || '');
        if (!m) return;
        methods[m] = (methods[m] || 0) + 1;
      });

      const examplePath =
        safeLower(windowEvents[0]?.httpPath || windowEvents[0]?.path || '') ||
        '(unknown path)';
      const exampleMethod =
        safeLower(windowEvents[0]?.httpMethod || windowEvents[0]?.method || '') ||
        '(unknown method)';

      const rowsText = buildRowRangeDescription(windowEvents);
      const desc =
        `${rowsText ? rowsText + ' ' : ''}` +
        `Source "${key}" issued ${windowEvents.length} non-GET/POST request(s) within ${Math.round(
          windowMs / 60000,
        )} minutes (e.g., ${exampleMethod.toUpperCase()} "${examplePath}"). ` +
        `This can be normal (APIs/admin tools) but is worth a quick review.`;

      const confidence = clampConfidence(
        baseConfidenceFromCount(windowEvents.length, minEvents) +
          (preset === 'strict' ? 5 : 0),
      );

      alerts.push(
        makeAlert({
          type: 'web.rare-methods',
          domain: 'web',
          severity: 'low',
          confidence,
          title: 'Non-standard HTTP methods observed',
          description: desc,
          remediation:
            'If this is an API or admin tool, confirm it is expected. Otherwise, inspect targeted paths and consider WAF rules or rate-limits for mutation methods (PUT/PATCH/DELETE).',
          events: windowEvents,
          evidence: {
            key,
            count: windowEvents.length,
            windowMinutes: Math.round(windowMs / 60000),
            methods,
          },
        }),
      );
      break;
    }
  }

  return alerts;
}

// ----- NET: port scan heuristic (many distinct ports per source IP) -----

function detectPortScan(netEvents, opts) {
  const { minPorts, windowMs, preset } = opts || {};
  const alerts = [];

  const candidates = netEvents.filter((e) => e.sourceIp && isFiniteNumber(e.destPort));
  if (candidates.length === 0) return [];

  const byIp = new Map();
  candidates.forEach((ev) => {
    const ip = ev.sourceIp;
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(ev);
  });

  for (const [ip, list] of byIp.entries()) {
    if (list.length < minPorts) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let start = 0;
    for (let end = 0; end < list.length; end += 1) {
      const cutoff = list[end].timestamp.getTime() - windowMs;
      while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

      const windowEvents = list.slice(start, end + 1);
      const ports = new Set(
        windowEvents.map((e) => e.destPort).filter((p) => isFiniteNumber(p)),
      );

      if (ports.size >= minPorts) {
        const rowsText = buildRowRangeDescription(windowEvents);

        const desc =
          `${rowsText ? rowsText + ' ' : ''}` +
          `IP "${ip}" connected to ${ports.size} distinct destination ports within ${Math.round(
            windowMs / 60000,
          )} minutes. This is consistent with port scanning or wide service probing.`;

        const confidence = clampConfidence(
          baseConfidenceFromCount(ports.size, minPorts) + 10 + (preset === 'strict' ? 5 : 0),
        );

        alerts.push(
          makeAlert({
            type: 'net.port-scan',
            domain: 'net',
            severity: 'high',
            confidence,
            title: 'Port scanning / broad service probing',
            description: desc,
            remediation:
              'If unexpected, block the source IP at perimeter controls and review firewall logs for broader scanning. Confirm whether this is an approved vulnerability scan.',
            events: windowEvents,
            evidence: {
              ip,
              distinctPorts: ports.size,
              windowMinutes: Math.round(windowMs / 60000),
            },
          }),
        );
        break;
      }
    }
  }

  return alerts;
}

// ----- NET (LOW): wide destination sweep (many distinct dest IPs) -----

function detectNetWideDestinationSweepLow(netEvents, opts) {
  const { minHosts, windowMs, preset } = opts || {};
  const alerts = [];

  const candidates = netEvents.filter((e) => e.sourceIp && e.destIp);
  if (candidates.length < minHosts) return [];

  const bySrc = new Map();
  candidates.forEach((ev) => {
    const ip = ev.sourceIp;
    if (!bySrc.has(ip)) bySrc.set(ip, []);
    bySrc.get(ip).push(ev);
  });

  for (const [srcIp, list] of bySrc.entries()) {
    if (list.length < minHosts) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let start = 0;
    for (let end = 0; end < list.length; end += 1) {
      const cutoff = list[end].timestamp.getTime() - windowMs;
      while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

      const windowEvents = list.slice(start, end + 1);
      const dests = new Set(windowEvents.map((e) => e.destIp).filter(Boolean));

      if (dests.size >= minHosts) {
        const rowsText = buildRowRangeDescription(windowEvents);
        const exampleDest = windowEvents[0]?.destIp || '(unknown)';

        const desc =
          `${rowsText ? rowsText + ' ' : ''}` +
          `Source IP "${srcIp}" contacted ${dests.size} distinct destination IPs within ${Math.round(
            windowMs / 60000,
          )} minutes (e.g., "${exampleDest}"). ` +
          `This can be normal (monitoring, service discovery), but may also indicate scanning or lateral movement.`;

        const confidence = clampConfidence(
          baseConfidenceFromCount(dests.size, minHosts) + (preset === 'strict' ? 5 : 0),
        );

        alerts.push(
          makeAlert({
            type: 'net.wide-destination-sweep',
            domain: 'net',
            severity: 'low',
            confidence,
            title: 'Wide destination sweep observed',
            description: desc,
            remediation:
              'Confirm whether this host is a known scanner/monitor. If unexpected, review destination list, check for failed connections and correlate with authentication and endpoint activity.',
            events: windowEvents,
            evidence: {
              sourceIp: srcIp,
              distinctDestIps: dests.size,
              windowMinutes: Math.round(windowMs / 60000),
            },
          }),
        );
        break;
      }
    }
  }

  return alerts;
}

// ----- DNS: NXDOMAIN burst -----

function detectDnsNxdomainBurst(dnsEvents, opts) {
  const { minEvents, windowMs, preset } = opts || {};
  const alerts = [];

  const candidates = dnsEvents.filter((e) => {
    const r = safeLower(e.dnsRcode || '');
    return r === 'nxdomain' || r === 'nameerror' || r === '3';
  });

  if (candidates.length < minEvents) return [];

  const byIp = new Map();
  candidates.forEach((ev) => {
    const ip = ev.sourceIp || '(unknown)';
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(ev);
  });

  for (const [ip, list] of byIp.entries()) {
    if (list.length < minEvents) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let start = 0;
    for (let end = 0; end < list.length; end += 1) {
      const cutoff = list[end].timestamp.getTime() - windowMs;
      while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

      const windowEvents = list.slice(start, end + 1);
      if (windowEvents.length >= minEvents) {
        const rowsText = buildRowRangeDescription(windowEvents);

        const sampleQname = windowEvents.find((e) => e.dnsQname)?.dnsQname || '(unknown)';

        const desc =
          `${rowsText ? rowsText + ' ' : ''}` +
          `Source "${ip}" generated ${windowEvents.length} NXDOMAIN responses within ${Math.round(
            windowMs / 60000,
          )} minutes (e.g., "${sampleQname}"). This may indicate DGA-like behavior, misconfiguration or aggressive discovery.`;

        const confidence = clampConfidence(
          baseConfidenceFromCount(windowEvents.length, minEvents) + (preset === 'strict' ? 5 : 0),
        );

        alerts.push(
          makeAlert({
            type: 'dns.nxdomain-burst',
            domain: 'dns',
            severity: 'medium',
            confidence,
            title: 'Burst of NXDOMAIN DNS lookups',
            description: desc,
            remediation:
              'Validate whether the source host/app is misconfigured. If not expected, investigate for malware-like domain generation and correlate with outbound connections and process activity around the same time.',
            events: windowEvents,
            evidence: {
              source: ip,
              count: windowEvents.length,
              windowMinutes: Math.round(windowMs / 60000),
            },
          }),
        );
        break;
      }
    }
  }

  return alerts;
}

// ----- DNS (LOW): unusual QTYPE / high TXT volume -----

function detectDnsUnusualQtypeLow(dnsEvents, opts) {
  const { minUnusual, minTxt, preset } = opts || {};
  const alerts = [];

  if (!hasAnyField(dnsEvents, 'dnsQtype')) return [];

  const normal = new Set(['a', 'aaaa', 'cname', 'mx', 'ns', 'soa', 'ptr', 'srv']);

  const keyFn = (ev) => ev.sourceIp || ev.host || ev.sourceApp || '(unknown)';
  const byKey = new Map();

  dnsEvents.forEach((ev) => {
    const qt = safeLower(ev.dnsQtype || '');
    if (!qt) return;

    const key = keyFn(ev);
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(ev);
  });

  for (const [key, list] of byKey.entries()) {
    if (!list || list.length === 0) continue;

    let txtCount = 0;
    let unusualCount = 0;
    const qtypeCounts = {};

    list.forEach((ev) => {
      const qt = safeLower(ev.dnsQtype || '');
      if (!qt) return;
      qtypeCounts[qt] = (qtypeCounts[qt] || 0) + 1;

      if (qt === 'txt') txtCount += 1;
      if (!normal.has(qt) && qt !== 'txt') unusualCount += 1;
    });

    const triggerTxt = isFiniteNumber(minTxt) && txtCount >= minTxt;
    const triggerUnusual = isFiniteNumber(minUnusual) && unusualCount >= minUnusual;

    if (!triggerTxt && !triggerUnusual) continue;

    const sampleQname = list.find((e) => e.dnsQname)?.dnsQname || '(unknown)';
    const rowsText = buildRowRangeDescription(list.slice(0, 10));
    const why =
      triggerTxt && triggerUnusual
        ? `high TXT volume (${txtCount}) and unusual QTYPEs (${unusualCount})`
        : triggerTxt
        ? `high TXT volume (${txtCount})`
        : `unusual QTYPE volume (${unusualCount})`;

    const desc =
      `${rowsText ? rowsText + ' ' : ''}` +
      `Source "${key}" generated ${why} (e.g., "${sampleQname}"). ` +
      `This can be legitimate (service discovery, security tools), but may also appear in tunneling or misconfiguration.`;

    const confidence = clampConfidence(
      45 + (triggerTxt ? 10 : 0) + (triggerUnusual ? 10 : 0) + (preset === 'strict' ? 5 : 0),
    );

    alerts.push(
      makeAlert({
        type: 'dns.unusual-qtype',
        domain: 'dns',
        severity: 'low',
        confidence,
        title: 'Unusual DNS query types observed',
        description: desc,
        remediation:
          'Confirm whether this source runs tooling that uses TXT/other records (EDR, service discovery). If unexpected, inspect the queried domains and correlate with outbound connections and process activity.',
        events: list.slice(0, 50),
        evidence: {
          source: key,
          txtCount,
          unusualCount,
          qtypeCounts,
        },
      }),
    );
  }

  return alerts;
}

// ----- ENDPOINT-LITE: suspicious tooling or sensitive file writes -----

function detectEndpointSuspicious(endpointEvents, opts) {
  const {
    suspiciousProcMin,
    suspiciousProcWindowMs,
    sensitiveWriteMin,
    sensitiveWriteWindowMs,
    largeWriteBytes,
    preset,
  } = opts || {};

  const alerts = [];

  const suspiciousProcNames = [
    'wget',
    'curl',
    'powershell',
    'pwsh',
    'cmd.exe',
    'bash',
    'sh',
    'nc',
    'netcat',
    'ncat',
    'certutil',
    'bitsadmin',
  ];

  const procEvents = endpointEvents.filter((e) => e.processName || e.processCmd);
  if (procEvents.length > 0) {
    const hits = procEvents.filter((e) => {
      const pn = safeLower(e.processName);
      const pc = safeLower(e.processCmd);
      return suspiciousProcNames.some((s) => pn === s || pn.includes(s) || pc.includes(s));
    });

    if (hits.length >= suspiciousProcMin) {
      const byHost = new Map();
      hits.forEach((ev) => {
        const k = ev.host || ev.sourceApp || '(host)';
        if (!byHost.has(k)) byHost.set(k, []);
        byHost.get(k).push(ev);
      });

      for (const [k, list] of byHost.entries()) {
        if (list.length < suspiciousProcMin) continue;

        list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

        let start = 0;
        for (let end = 0; end < list.length; end += 1) {
          const cutoff = list[end].timestamp.getTime() - suspiciousProcWindowMs;
          while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

          const windowEvents = list.slice(start, end + 1);
          if (windowEvents.length >= suspiciousProcMin) {
            const rowsText = buildRowRangeDescription(windowEvents);
            const example =
              windowEvents[0]?.processCmd || windowEvents[0]?.processName || '(unknown)';

            const desc =
              `${rowsText ? rowsText + ' ' : ''}` +
              `Host/app "${k}" executed suspicious tooling ${windowEvents.length} time(s) within ${Math.round(
                suspiciousProcWindowMs / 60000,
              )} minutes (e.g., "${String(example).slice(0, 120)}").`;

            const confidence = clampConfidence(
              baseConfidenceFromCount(windowEvents.length, suspiciousProcMin) +
                10 +
                (preset === 'strict' ? 5 : 0),
            );
            
            const exampleCmdLower = safeLower(String(example || ''));

            const strongIndicators = [
              'encodedcommand',
              '-enc',
              'mimikatz',
              'rundll32',
              'regsvr32',
              'mshta',
              'certutil',
              'bitsadmin',
              'invoke-webrequest',
              'iwr ',
              'downloadstring',
              'http://',
              'https://',
            ];

            const hasStrongIndicator = strongIndicators.some((s) => exampleCmdLower.includes(s));

            const procSeverity =
              preset === 'strict' || hasStrongIndicator
                ? 'high'
                : windowEvents.length >= suspiciousProcMin * 2
                ? 'medium'
                : 'low';

            alerts.push(
              makeAlert({
                type: 'endpoint.suspicious-proc',
                domain: 'endpoint',
                severity: procSeverity,
                confidence,
                title: 'Suspicious process/tool execution',
                description: desc,
                remediation:
                  'Confirm whether this activity is authorized (admin scripts, provisioning). If not expected, isolate the host, review parent processes and correlate with outbound connections and web requests.',
                events: windowEvents,
                evidence: { key: k, count: windowEvents.length },
              }),
            );
            break;
          }
        }
      }
    }
  }

  const fileEvents = endpointEvents.filter((e) => e.filePath || isFiniteNumber(e.fileBytes));
  if (fileEvents.length > 0) {
    const sensitivePathRe =
      /(^\/etc\/|^\/root\/|\/\.ssh\/|\/authorized_keys$|\/shadow$|\/passwd$|^c:\\windows\\system32\\|\\appdata\\roaming\\|\\startup\\)/i;

    const hits = fileEvents.filter((e) => {
      const p = String(e.filePath || '').trim();
      if (!p) return false;
      const bytes = e.fileBytes;
      return sensitivePathRe.test(p) || (isFiniteNumber(bytes) && bytes >= largeWriteBytes);
    });

    if (hits.length >= sensitiveWriteMin) {
      const byHost = new Map();
      hits.forEach((ev) => {
        const k = ev.host || ev.sourceApp || '(host)';
        if (!byHost.has(k)) byHost.set(k, []);
        byHost.get(k).push(ev);
      });

      for (const [k, list] of byHost.entries()) {
        if (list.length < sensitiveWriteMin) continue;

        list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

        let start = 0;
        for (let end = 0; end < list.length; end += 1) {
          const cutoff = list[end].timestamp.getTime() - sensitiveWriteWindowMs;
          while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

          const windowEvents = list.slice(start, end + 1);
          if (windowEvents.length >= sensitiveWriteMin) {
            const rowsText = buildRowRangeDescription(windowEvents);
            const samplePath = windowEvents[0]?.filePath || '(unknown path)';
            const largeWrites = windowEvents.filter(
              (e) => isFiniteNumber(e.fileBytes) && e.fileBytes >= largeWriteBytes,
            ).length;

            const desc =
              `${rowsText ? rowsText + ' ' : ''}` +
              `Host/app "${k}" wrote to sensitive paths or produced unusually large writes ${windowEvents.length} time(s) within ${Math.round(
                sensitiveWriteWindowMs / 60000,
              )} minutes (e.g., "${String(samplePath).slice(0, 120)}").` +
              (largeWrites
                ? ` ${largeWrites} write(s) exceeded ${Math.round(
                    largeWriteBytes / (1024 * 1024),
                  )} MB.`
                : '');

            const confidence = clampConfidence(
              baseConfidenceFromCount(windowEvents.length, sensitiveWriteMin) +
                (largeWrites ? 10 : 0) +
                (preset === 'strict' ? 5 : 0),
            );

            alerts.push(
              makeAlert({
                type: 'endpoint.sensitive-write',
                domain: 'endpoint',
                severity: largeWrites ? 'high' : 'medium',
                confidence,
                title: 'Sensitive or unusual file writes',
                description: desc,
                remediation:
                  'Confirm whether file changes match expected deployments or automation. If not expected, investigate the initiating process/user and correlate with authentication and network activity.',
                events: windowEvents,
                evidence: { key: k, count: windowEvents.length, largeWrites },
              }),
            );
            break;
          }
        }
      }
    }
  }

  return alerts;
}

// ----- ENDPOINT (LOW): execution from temp/download locations -----

function detectEndpointExecFromTempLow(endpointEvents, opts) {
  const { minEvents, windowMs, preset } = opts || {};
  const alerts = [];

  const candidates = endpointEvents.filter((e) => e.processCmd || e.processName);
  if (candidates.length < minEvents) return [];

  const tempRe =
    /(\\temp\\|\/tmp\/|\/var\/tmp\/|\\appdata\\local\\temp\\|\\downloads\\|\/downloads\/)/i;

  const keyFn = (ev) => ev.host || ev.sourceApp || '(host)';
  const byKey = new Map();

  candidates.forEach((ev) => {
    const cmd = String(ev.processCmd || ev.processName || '');
    if (!cmd) return;
    if (!tempRe.test(cmd)) return;

    const k = keyFn(ev);
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(ev);
  });

  for (const [k, list] of byKey.entries()) {
    if (list.length < minEvents) continue;

    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    let start = 0;
    for (let end = 0; end < list.length; end += 1) {
      const cutoff = list[end].timestamp.getTime() - windowMs;
      while (start < end && list[start].timestamp.getTime() < cutoff) start += 1;

      const windowEvents = list.slice(start, end + 1);
      if (windowEvents.length < minEvents) continue;

      const example =
        windowEvents[0]?.processCmd || windowEvents[0]?.processName || '(unknown)';
      const rowsText = buildRowRangeDescription(windowEvents);

      const desc =
        `${rowsText ? rowsText + ' ' : ''}` +
        `Host/app "${k}" executed process(es) from temp/download locations ${windowEvents.length} time(s) within ${Math.round(
          windowMs / 60000,
        )} minutes (e.g., "${String(example).slice(0, 120)}"). ` +
        `This is often benign, but is also common in dropper-style activity.`;

      const confidence = clampConfidence(
        baseConfidenceFromCount(windowEvents.length, minEvents) +
          5 +
          (preset === 'strict' ? 5 : 0),
      );

      alerts.push(
        makeAlert({
          type: 'endpoint.exec-from-temp',
          domain: 'endpoint',
          severity: 'low',
          confidence,
          title: 'Execution from temp/download locations',
          description: desc,
          remediation:
            'Confirm whether the execution is expected (installers, updates). If unexpected, inspect parent process/user, file origin and correlate with DNS/web activity near the same time.',
          events: windowEvents,
          evidence: {
            key: k,
            count: windowEvents.length,
            windowMinutes: Math.round(windowMs / 60000),
          },
        }),
      );
      break;
    }
  }

  return alerts;
}

// ---------- Public API ----------

/**
 * Run detection rules over normalized events
 *
 * @param {Array} events
 * @param {Object} [options]
 * @param {Array<string>} [options.homeIpPrefixes]
 * @param {boolean} [options.enableGeo]
 * @param {string} [options.strictness]
 * @returns {Array}
 */
export function runDetections(events, options = {}) {
  ALERT_COUNTER = 0;

  const preset = getPreset(options);
  const T = thresholds(preset);

  const rawEvents = Array.isArray(events) ? events : [];
  const normalized = normalizeEventsForDetection(rawEvents);
  if (normalized.length === 0) return [];

  const enableGeo = Boolean(options.enableGeo);

  // Accept multiple UI shapes
  const homeInput =
    options.homeIpPrefixes ??
    options.homePrefixes ??
    options.homeIps ??
    options.ipPrefixes ??
    options.homeIpEntries ??
    options.homeIpTable ??
    null;

  const homeNorm = normalizeHomePrefixEntries(homeInput);
  const homeIpPrefixes = homeNorm.prefixes;

  const authEvents = normalized.filter(isAuthEvent);
  const webEvents = normalized.filter(isWebEvent);
  const dnsEvents = normalized.filter(isDnsEvent);
  const netEvents = normalized.filter(isNetEvent);
  const endpointEvents = normalized.filter(isEndpointEvent);

  const alerts = [];

  // -------- Always-on quality signals --------
  alerts.push(
    ...detectQualitySignals(rawEvents, normalized, {
      preset,
      qualityThresholds: T.quality,
    }),
  );

  // -------- AUTH domain --------
  if (authEvents.length > 0) {
    alerts.push(
      ...detectBruteforceByKey(authEvents, (ev) => ev.sourceIp || null, {
        minFails: T.auth.bruteforceMinFails,
        windowMs: T.auth.bruteforceWindowMs,
        typePrefix: 'bruteforce.ip',
        severity: 'high',
        preset,
      }),
    );

    alerts.push(
      ...detectBruteforceByKey(authEvents, (ev) => ev.username || null, {
        minFails: T.auth.bruteforceMinFails,
        windowMs: T.auth.bruteforceWindowMs,
        typePrefix: 'bruteforce.user',
        severity: 'high',
        preset,
      }),
    );

    alerts.push(
      ...detectSuspiciousSuccessAfterFails(authEvents, {
        minFailsBeforeSuccess: T.auth.suspiciousSuccessMinFails,
        windowMs: T.auth.suspiciousSuccessWindowMs,
        preset,
      }),
    );

    alerts.push(
      ...detectPasswordSpray(authEvents, {
        minDistinctUsers: T.auth.sprayMinUsers,
        windowMs: T.auth.sprayWindowMs,
        preset,
      }),
    );

    alerts.push(
      ...detectNoisyAuthIp(authEvents, {
        minEvents: T.auth.noisyMinEvents,
        windowMs: T.auth.noisyWindowMs,
        preset,
      }),
    );

    alerts.push(
      ...detectAuthFirstSeenSuccess(authEvents, {
        preset,
        state: options.state,
        onStateUpdate: options.onStateUpdate,
      }),
    );

    // Build a set of event indexes involved in higher-signal auth alerts
    const claimedAuthIndexes = new Set();
    alerts
      .filter(
        (a) =>
          a &&
          (a.domain === 'auth' || a.domain === 'geo') &&
          a.type !== 'auth.isolated-failure'
      )
      .forEach((a) => {
        (a.relatedEventIndexes || []).forEach((idx) => claimedAuthIndexes.add(idx));
      });

    alerts.push(
      ...detectAuthIsolatedFailureLow(authEvents, {
        preset,
        claimedAuthIndexes,
        isolationWindowMs: Math.max(T.auth.bruteforceWindowMs, 10 * 60 * 1000),
      }),
    );
  }

  // -------- GEO domain (gated) --------
  if (enableGeo && homeIpPrefixes.length > 0 && authEvents.length > 0) {
    alerts.push(
      ...detectGeoAnomalies(normalized, homeIpPrefixes, {
        enableGeo,
        preset,
        geoThresholds: T.geo,

        homeCountries: homeNorm.countries,

        state: options.state,
        onStateUpdate: options.onStateUpdate,
      }),
    );
  }

  // -------- WEB domain --------
  const hasHttp =
    hasAnyField(webEvents, 'httpPath') ||
    hasAnyField(webEvents, 'path') ||
    hasAnyField(webEvents, 'httpMethod') ||
    hasAnyNumberField(webEvents, 'httpStatus') ||
    hasAnyNumberField(webEvents, 'status');

  if (webEvents.length > 0 && hasHttp) {
    alerts.push(
      ...detectWebAdminSensitive(webEvents, {
        sensitivePaths: T.web.adminSensitivePaths,
        minEvents: T.web.adminMinEvents,
        preset,
      }),
    );

    alerts.push(
      ...detectWebAuthzBurst(webEvents, {
        minEvents: T.web.authzBurstMin,
        windowMs: T.web.authzBurstWindowMs,
        preset,
      }),
    );

    alerts.push(
      ...detectWeb5xxSpike(webEvents, {
        minErrors: T.web.errors5xxMin,
        windowMs: T.web.errors5xxWindowMs,
        preset,
      }),
    );

    alerts.push(
      ...detectWebRareMethodsLow(webEvents, {
        minEvents: T.web.rareMethodsMin,
        windowMs: T.web.rareMethodsWindowMs,
        preset,
        adminSensitivePaths: T.web.adminSensitivePaths,
      }),
    );
  }

  // -------- NET domain --------
  if (netEvents.length > 0 && hasAnyNumberField(netEvents, 'destPort')) {
    alerts.push(
      ...detectPortScan(netEvents, {
        minPorts: T.net.portScanMinPorts,
        windowMs: T.net.portScanWindowMs,
        preset,
      }),
    );
  }

  if (netEvents.length > 0 && hasAnyField(netEvents, 'destIp')) {
    alerts.push(
      ...detectNetWideDestinationSweepLow(netEvents, {
        minHosts: T.net.destSweepMinHosts,
        windowMs: T.net.destSweepWindowMs,
        preset,
      }),
    );
  }

  // -------- DNS domain --------
  if (dnsEvents.length > 0 && hasAnyField(dnsEvents, 'dnsRcode')) {
    alerts.push(
      ...detectDnsNxdomainBurst(dnsEvents, {
        minEvents: T.dns.nxdomainMin,
        windowMs: T.dns.nxdomainWindowMs,
        preset,
      }),
    );
  }

  if (dnsEvents.length > 0 && hasAnyField(dnsEvents, 'dnsQtype')) {
    alerts.push(
      ...detectDnsUnusualQtypeLow(dnsEvents, {
        minUnusual: T.dns.unusualQtypeMin,
        minTxt: T.dns.unusualQtypeTxtMin,
        preset,
      }),
    );
  }

  // -------- ENDPOINT domain --------
  if (
    endpointEvents.length > 0 &&
    (hasAnyField(endpointEvents, 'processName') ||
      hasAnyField(endpointEvents, 'processCmd') ||
      hasAnyField(endpointEvents, 'filePath'))
  ) {
    if (
      hasAnyField(endpointEvents, 'processName') ||
      hasAnyField(endpointEvents, 'filePath') ||
      hasAnyField(endpointEvents, 'processCmd')
    ) {
      alerts.push(
        ...detectEndpointSuspicious(endpointEvents, {
          suspiciousProcMin: T.endpoint.suspiciousProcMin,
          suspiciousProcWindowMs: T.endpoint.suspiciousProcWindowMs,
          sensitiveWriteMin: T.endpoint.sensitiveWriteMin,
          sensitiveWriteWindowMs: T.endpoint.sensitiveWriteWindowMs,
          largeWriteBytes: T.endpoint.largeWriteBytes,
          preset,
        }),
      );
    }

    if (hasAnyField(endpointEvents, 'processName') || hasAnyField(endpointEvents, 'processCmd')) {
      alerts.push(
        ...detectEndpointExecFromTempLow(endpointEvents, {
          minEvents: T.endpoint.execTempMin,
          windowMs: T.endpoint.execTempWindowMs,
          preset,
        }),
      );
    }
  }

  const bucketMs = DEFAULT_BUCKET_MS;

  const pruned1 = suppressBruteforceIpWhenSpray(alerts, { bucketMs });
  const pruned2 = suppressBruteforceIpWhenUserOverlap(pruned1, {
    bucketMs,
    minShared: 3,
    overlapPct: 0.6,
  });

  return dedupeAlerts(pruned2, { bucketMs });
}

// ---- Public contract constants ----
export const ALERT_SEVERITIES = ['low', 'medium', 'high'];

export const ALERT_FIELDS = [
  'id',
  'type',
  'severity',
  'title',
  'domain',
  'confidence',
  'timestamp',
  'description',
  'remediation',
  'relatedEventIndexes',
  'relatedEventIds',
  'evidence',
];

export const DETECTION_DOMAINS = [
  'auth',
  'web',
  'dns',
  'net',
  'endpoint',
  'geo',
  'general',
];
