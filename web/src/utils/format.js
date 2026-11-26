/**
 * Formatting helpers: timestamps (YYYY-MM-DD HH:MM ±HH:MM), bytes, durations, hashes.
 */

function pad2(n) {
  return String(n).padStart(2, '0')
}

export function formatTimestamp(value) {
  if (value === null || value === undefined || value === '' || value === 0) {
    return '—'
  }
  const date =
    typeof value === 'number' ? new Date(value > 1e12 ? value : value * 1000) : new Date(value)
  if (Number.isNaN(date.getTime())) {
    return String(value)
  }
  const yyyy = date.getFullYear()
  const mm = pad2(date.getMonth() + 1)
  const dd = pad2(date.getDate())
  const hh = pad2(date.getHours())
  const mi = pad2(date.getMinutes())
  const offsetMin = -date.getTimezoneOffset()
  const sign = offsetMin >= 0 ? '+' : '-'
  const absOffset = Math.abs(offsetMin)
  const oh = pad2(Math.floor(absOffset / 60))
  const om = pad2(absOffset % 60)
  return `${yyyy}-${mm}-${dd} ${hh}:${mi} ${sign}${oh}:${om}`
}

export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || Number.isNaN(Number(bytes))) {
    return '—'
  }
  const value = Number(bytes)
  if (value < 1024) return `${value} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let size = value / 1024
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size >= 100 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`
}

export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) {
    return '—'
  }
  const total = Math.max(0, Math.floor(Number(seconds)))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (h > 0) return `${h}h ${pad2(m)}m ${pad2(s)}s`
  if (m > 0) return `${m}m ${pad2(s)}s`
  return `${s}s`
}

export function formatDurationMs(ms) {
  if (ms === null || ms === undefined || Number.isNaN(Number(ms)) || Number(ms) < 0) {
    return '—'
  }
  const value = Number(ms)
  if (value < 1000) return `${Math.round(value)} ms`
  if (value < 60_000) return `${(value / 1000).toFixed(1)}s`
  return formatDuration(Math.round(value / 1000))
}

export function extractDetailDuration(detail) {
  if (!detail || typeof detail !== 'string') return ''
  const match = detail.match(/\((\d+(?:\.\d+)?)\s*s\)/)
  if (!match) return ''
  return formatDurationMs(parseFloat(match[1]) * 1000)
}

export function shortHash(hash, len = 10) {
  if (!hash || typeof hash !== 'string') return '—'
  return hash.length > len ? hash.slice(0, len) : hash
}

export function decodeHexToBytes(hex) {
  if (!hex || typeof hex !== 'string' || hex.length % 2 !== 0) {
    return new Uint8Array()
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function decodeHexToText(hex) {
  const bytes = decodeHexToBytes(hex)
  if (bytes.length === 0) return ''
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  } catch {
    return ''
  }
}

export function isProbablyBinary(bytes) {
  const limit = Math.min(bytes.length, 4096)
  for (let i = 0; i < limit; i += 1) {
    if (bytes[i] === 0) return true
  }
  return false
}

export function translateWithFallback(t, key, fallback = '—') {
  const label = t(key)
  return label === key ? fallback : label
}

export function friendlyBusyError(err, t, rawMessage = '', fallbackKey = '') {
  const message = rawMessage || err?.message || ''
  if (err?.status === 409 || err?.code === 'lock_busy' || message === 'profile busy') {
    return t('files.profileBusy')
  }
  return message || (fallbackKey ? t(fallbackKey) : '')
}
