// Utility: Normalize any timestamp-like value into a date or null

function toDate(v) {
  if (v == null) return null

  if (v instanceof Date) {
    return Number.isNaN(v.getTime()) ? null : v
  }

  if (typeof v === 'number' && Number.isFinite(v)) {
    const ms = v < 1e12 ? v * 1000 : v
    const d = new Date(ms)
    return Number.isNaN(d.getTime()) ? null : d
  }

  if (typeof v === 'string') {
    const s = v.trim()
    if (!s) return null

    if (/^\d+$/.test(s)) {
      const num = Number(s)
      const ms = num < 1e12 ? num * 1000 : num
      const d = new Date(ms)
      return Number.isNaN(d.getTime()) ? null : d
    }

    const d = new Date(s)
    return Number.isNaN(d.getTime()) ? null : d
  }

  return null
}

// Utility: Pull an event timestamp from common fields
function eventTs(ev) {
  return (
    toDate(ev?.timestamp) ||
    toDate(ev?.time) ||
    toDate(ev?.ts) ||
    toDate(ev?.createdAt) ||
    toDate(ev?.date)
  )
}

// Utility: get the min/max timestamps from a list of events
export function computeTimeRange(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return { min: null, max: null }
  }

  let minTs = null
  let maxTs = null

  for (const ev of events) {
    const d = eventTs(ev)
    if (!d) continue
    const t = d.getTime()

    if (minTs === null || t < minTs) minTs = t
    if (maxTs === null || t > maxTs) maxTs = t
  }

  if (minTs === null || maxTs === null) {
    return { min: null, max: null }
  }

  return { min: new Date(minTs), max: new Date(maxTs) }
}

// Presets
export const TIME_PRESETS = [
  { id: 'all', label: 'All time', kind: 'all' },

  { id: 'last_1h', label: 'Last 1 hour', kind: 'relative', ms: 1 * 60 * 60 * 1000 },
  { id: 'last_6h', label: 'Last 6 hours', kind: 'relative', ms: 6 * 60 * 60 * 1000 },
  { id: 'last_12h', label: 'Last 12 hours', kind: 'relative', ms: 12 * 60 * 60 * 1000 },
  { id: 'last_24h', label: 'Last 24 hours', kind: 'relative', ms: 24 * 60 * 60 * 1000 },

  { id: 'last_7d', label: 'Last 7 days', kind: 'relative', ms: 7 * 24 * 60 * 60 * 1000 },
  { id: 'last_30d', label: 'Last 30 days', kind: 'relative', ms: 30 * 24 * 60 * 60 * 1000 },
  { id: 'last_12mo', label: 'Last 12 months', kind: 'relative', ms: 365 * 24 * 60 * 60 * 1000 },
]

// Apply presets
export function computeRangeFromPreset(events, presetId) {
  const { min, max } = computeTimeRange(events)
  if (!min || !max) return { from: null, to: null }

  const preset =
    TIME_PRESETS.find((p) => p.id === presetId) || TIME_PRESETS[0]

  if (preset.kind === 'all') {
    return { from: min, to: max }
  }
  

  if (preset.kind === 'relative') {
  const to = max
  let from = new Date(to.getTime() - (preset.ms || 0))

  if (from < min) from = min

  return { from, to }
}
  
  // fallback
  return { from: min, to: max }
}

// Filter events by from,to
export function filterEventsByRange(events, from, to) {
  if (!from || !to) return events || []

  const start = from.getTime()
  const end = to.getTime()

  return (events || []).filter((ev) => {
    const d = eventTs(ev)
    if (!d) return false
    const t = d.getTime()
    return t >= start && t <= end
  })
}

const SECOND_MS = 1000
const MINUTE_MS = 60 * SECOND_MS
const HOUR_MS = 60 * MINUTE_MS
const DAY_MS = 24 * HOUR_MS

// Determine appropriate bucket size
export function autoBucketSize(from, to, maxBuckets = 60) {
  if (!from || !to) return { sizeMs: HOUR_MS, unit: 'hour' }

  const spanMs = to.getTime() - from.getTime()
  if (spanMs <= 0) return { sizeMs: HOUR_MS, unit: 'hour' }

  const candidates = [
    { unit: 'second', sizeMs: SECOND_MS },
    { unit: 'minute', sizeMs: MINUTE_MS },
    { unit: 'hour', sizeMs: HOUR_MS },
    { unit: 'day', sizeMs: DAY_MS },
    { unit: 'month', sizeMs: 30 * DAY_MS },
  ]

  for (const c of candidates) {
    const bucketCount = Math.ceil(spanMs / c.sizeMs)
    if (bucketCount <= maxBuckets) return { sizeMs: c.sizeMs, unit: c.unit }
  }

  // fallback
  const approxMonths = Math.ceil(spanMs / (30 * DAY_MS))
  const finalSize = spanMs / Math.min(approxMonths, maxBuckets)
  return { sizeMs: finalSize, unit: 'month+' }
}

// Bucket events into even time buckets
export function bucketEvents(events, from, to, bucketSizeMs) {
  if (!from || !to || !bucketSizeMs || bucketSizeMs <= 0) return []

  const start = from.getTime()
  const end = to.getTime()

  const span = end - start
  const bucketCount = Math.floor(span / bucketSizeMs) + 1

  if (bucketCount <= 0) return []

  const buckets = []
  for (let i = 0; i < bucketCount; i++) {
    const bStart = start + i * bucketSizeMs
    buckets.push({
      bucketStart: new Date(bStart),
      total: 0,
      success: 0,
      fail: 0,
    })
  }

  for (const ev of events || []) {
    const d = eventTs(ev)
    if (!d) continue
    const t = d.getTime()
    if (t < start || t > end) continue

    const idx = Math.floor((t - start) / bucketSizeMs)
    if (idx >= 0 && idx < buckets.length) {
      buckets[idx].total++
      if (ev.outcome === 'success') buckets[idx].success++
      else if (ev.outcome === 'fail') buckets[idx].fail++
    }
  }

  return buckets
}

/**
 * High-level helper:
 * 1) compute (from,to) from preset (or explicit override)
 * 2) filter events
 * 3) bucket sizing (auto or explicit)
 * 4) produce buckets + metadata
 */
export function computeHistogram(
  events,
  presetId,
  explicitFrom = null,
  explicitTo = null,
  explicitBucketSizeMs = null,
) {
  // explicit override wins
  let from = explicitFrom
  let to = explicitTo

  if (!from || !to) {
    const range = computeRangeFromPreset(events, presetId)
    from = range.from
    to = range.to
  }

  const filtered = filterEventsByRange(events, from, to)

  let bucketInfo
  if (explicitBucketSizeMs) {
    let unit = 'second'
    if (explicitBucketSizeMs >= DAY_MS) unit = 'day'
    else if (explicitBucketSizeMs >= HOUR_MS) unit = 'hour'
    else if (explicitBucketSizeMs >= MINUTE_MS) unit = 'minute'
    bucketInfo = { sizeMs: explicitBucketSizeMs, unit }
  } else {
    bucketInfo = autoBucketSize(from, to, 60)
  }

  const buckets = bucketEvents(filtered, from, to, bucketInfo.sizeMs)

  return {
    from,
    to,
    filteredEvents: filtered,
    bucketSizeMs: bucketInfo.sizeMs,
    unit: bucketInfo.unit,
    buckets,
  }
}