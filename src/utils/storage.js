const TEMP_PREFIX = "temp:";
const PERSIST_PREFIX = "persist:";
const DEFAULT_TTL_MS = 1000 * 60 * 60;

// --- helpers ---
function safeParse(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// Persistent: no expiry (theme, last tool, UI prefs)
export function setPersistent(key, value) {
  const payload = { value };
  localStorage.setItem(PERSIST_PREFIX + key, JSON.stringify(payload));
}

export function getPersistent(key, fallback = null) {
  const raw = localStorage.getItem(PERSIST_PREFIX + key);
  if (!raw) return fallback;

  const parsed = safeParse(raw);
  return parsed?.value ?? fallback;
}

// Temporary: expires after TTL (scan results, parsed configs)
export function setTemp(key, value, ttlMs = DEFAULT_TTL_MS) {
  const payload = {
    value,
    ts: Date.now(),
    ttlMs,
  };
  localStorage.setItem(TEMP_PREFIX + key, JSON.stringify(payload));
}

export function getTemp(key, fallback = null) {
  const fullKey = TEMP_PREFIX + key;
  const raw = localStorage.getItem(fullKey);
  if (!raw) return fallback;

  const parsed = safeParse(raw);
  if (!parsed) {
    localStorage.removeItem(fullKey);
    return fallback;
  }

  const { value, ts, ttlMs } = parsed;
  const age = Date.now() - (ts ?? 0);
  const limit = ttlMs ?? DEFAULT_TTL_MS;

  if (!ts || age > limit) {
    localStorage.removeItem(fullKey);
    return fallback;
  }

  return value;
}

// Global cleanup
export function cleanupTemp() {
  const now = Date.now();

  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (!key?.startsWith(TEMP_PREFIX)) continue;

    const raw = localStorage.getItem(key);
    const parsed = safeParse(raw);
    if (!parsed) {
      localStorage.removeItem(key);
      continue;
    }

    const { ts, ttlMs = DEFAULT_TTL_MS } = parsed;
    const age = now - (ts ?? 0);
    if (!ts || age > ttlMs) {
      localStorage.removeItem(key);
    }
  }
}
