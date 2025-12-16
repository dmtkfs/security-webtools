export function parseTimestampValue(raw) {
  if (raw == null || raw === '') return null

  // Date passthrough
  if (raw instanceof Date) return Number.isNaN(raw.getTime()) ? null : raw

  // Numbers
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    const ms = raw >= 1e12 ? raw : raw >= 1e9 ? raw * 1000 : null
    if (ms == null) return null
    const d = new Date(ms)
    return Number.isNaN(d.getTime()) ? null : d
  }

  const s = String(raw).trim()
  if (!s) return null

  // Numeric strings
  if (/^\d+$/.test(s)) {
    const num = Number(s)
    const ms = num >= 1e12 ? num : num >= 1e9 ? num * 1000 : null
    if (ms == null) return null
    const d = new Date(ms)
    return Number.isNaN(d.getTime()) ? null : d
  }

  // ISO / RFC strings
  const d = new Date(s)
  return Number.isNaN(d.getTime()) ? null : d
}

function classifyOutcomeString(str) {
  const s = (str || '').toString().toLowerCase().trim()
  if (!s) return ''
  if (s === 'true' || s === '1') return 'success'
  if (s === 'false' || s === '0') return 'fail'

  if (/success|succeed(ed)?|ok|allowed|authorized|pass(ed)?/.test(s)) return 'success'
  if (/(fail|failure|error|denied|blocked|unauth|unauthorized|invalid|timeout)/.test(s)) return 'fail'
  return ''
}

export function normalizeOutcome(baseOutcome, obj) {
  let classified = classifyOutcomeString(baseOutcome);
  if (classified) return classified;

  if (obj?.outcome?.result) {
    classified = classifyOutcomeString(obj.outcome.result);
    if (classified) return classified;
  }

  // Boolean success fields
  const boolSuccess =
    typeof obj?.success === 'boolean'
      ? obj.success
      : typeof obj?.auth_success === 'boolean'
        ? obj.auth_success
        : typeof obj?.ok === 'boolean'
          ? obj.ok
          : null;

  // Nested auth.success
  if (obj?.auth && typeof obj.auth === 'object') {
    if (typeof obj.auth.success === 'boolean') {
      return obj.auth.success ? 'success' : 'fail';
    }
    if (obj.auth.result != null) {
      classified = classifyOutcomeString(obj.auth.result);
      if (classified) return classified;
    }
  }

  if (typeof baseOutcome === 'boolean') return baseOutcome ? 'success' : 'fail';

  if (boolSuccess === true) return 'success';
  if (boolSuccess === false) return 'fail';

  const statusVal = obj?.statusCode !== undefined ? obj.statusCode : obj?.status;
  if (statusVal !== undefined) {
    const n = Number(statusVal);
    if (Number.isFinite(n)) {
      if (n >= 200 && n < 400) return 'success';
      if (n >= 400) return 'fail';
    } else {
      classified = classifyOutcomeString(statusVal);
      if (classified) return classified;
    }
  }

  if (obj?.result) {
    classified = classifyOutcomeString(obj.result);
    if (classified) return classified;
  }

  if (obj?.ResultType) {
    classified = classifyOutcomeString(obj.ResultType);
    if (classified) return classified;
  }
  if (obj?.Status) {
    classified = classifyOutcomeString(obj.Status);
    if (classified) return classified;
  }

  // CloudTrail style
  if (obj && Object.prototype.hasOwnProperty.call(obj, 'errorCode')) {
    return obj.errorCode ? 'fail' : 'success';
  }

  return '';
}

export function toNumberOrNull(v) {
  if (v == null || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

export function finalizeCanonicalEvent(ev) {
  return {
    id: ev.id || '',
    timestamp: ev.timestamp instanceof Date ? ev.timestamp : null,

    sourceIp: ev.sourceIp || '',
    destIp: ev.destIp || '',
    destPort: toNumberOrNull(ev.destPort),
    username: ev.username || '',
    outcome: ev.outcome || '',
    eventType: ev.eventType || 'event',

    httpMethod: ev.httpMethod || '',
    httpPath: ev.httpPath || '',
    httpStatus: toNumberOrNull(ev.httpStatus),
    latencyMs: toNumberOrNull(ev.latencyMs),

    dnsQname: ev.dnsQname || '',
    dnsQtype: ev.dnsQtype || '',
    dnsRcode: ev.dnsRcode || '',

    bytesIn: toNumberOrNull(ev.bytesIn),
    bytesOut: toNumberOrNull(ev.bytesOut),

    processName: ev.processName || '',
    processCmd: ev.processCmd || '',

    filePath: ev.filePath || '',
    fileBytes: toNumberOrNull(ev.fileBytes),

    mfa: typeof ev.mfa === 'boolean' ? ev.mfa : ev.mfa ?? null,

    raw: ev.raw ?? '',
    sourceApp: ev.sourceApp || '',
    host: ev.host || '',
    environment: ev.environment || '',
    authMethod: ev.authMethod || '',
    geoCountry: ev.geoCountry || '',
    contextProfile: ev.contextProfile || '',
    details: ev.details || '',
  };
}
