import { ApiError, apiRequest, buildQuery, encodeSegment, notifyUnauthorized } from './http.js'
import { cachedInspection, readInspection } from './inspections.js'

const base = (profile) => `/v1/remote/${encodeSegment(profile)}`
const treeUrl = (profile, query) => `${base(profile)}/tree${buildQuery(query)}`
const local = (profile) => `/v1/local/${encodeSegment(profile)}`

export function cachedLocalTree(profile) {
  return cachedInspection(`${local(profile)}/tree`)
}

export function fetchLocalTree(profile, { signal, refresh } = {}) {
  const path = `${local(profile)}/tree`
  return readInspection(profile, path, (sharedSignal) => apiRequest(path, { signal: sharedSignal }),
    { signal, refresh, cacheable: true, queueKey: local(profile) })
}

export function buildLocalDownloadUrl(profile, path) {
  return `${local(profile)}/download${buildQuery({ path })}`
}

export function buildLocalThumbnailUrl(profile, path, size = 160) {
  return `${local(profile)}/thumbnail${buildQuery({ path, size })}`
}

function waitForRetry(ms, signal) {
  signal?.throwIfAborted()
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', abort)
      resolve()
    }, ms)
    function abort() {
      clearTimeout(timer)
      reject(signal.reason)
    }
    signal?.addEventListener('abort', abort, { once: true })
  })
}

async function retryInspection(request, signal) {
  const delays = [0, 250, 750, 1500, 2500]
  for (const delay of delays) {
    signal?.throwIfAborted()
    if (delay) await waitForRetry(delay, signal)
    try {
      return await request()
    } catch (error) {
      if (error.status !== 409 || error.message !== 'profile busy' || delay === delays.at(-1)) throw error
    }
  }
}

function inspect(profile, url, signal, { cacheable = true, refresh = false, priority = 'normal', tier = 'head' } = {}) {
  return readInspection(profile, url,
    (sharedSignal) => retryInspection(() => apiRequest(url, { signal: sharedSignal }), sharedSignal),
    { signal, cacheable, refresh, priority, tier })
}

export function cachedRemoteReading(profile, kind) {
  return cachedInspection(`${base(profile)}/${kind}`)
}

export function fetchRemoteSummary(profile, signal, { refresh = false } = {}) {
  return inspect(profile, `${base(profile)}/summary`, signal, { refresh })
}

export function fetchRemoteCommits(profile, signal, { refresh = false } = {}) {
  return inspect(profile, `${base(profile)}/commits`, signal, { refresh })
}

export function cachedRemoteTree(profile, query) {
  return cachedInspection(treeUrl(profile, query))
}

export function fetchRemoteTree(profile, { commit, head, prefix, signal, refresh } = {}) {
  return inspect(profile, treeUrl(profile, { commit, head, prefix }), signal, {
    refresh,
    tier: commit ? 'immutable' : 'head',
  })
}

export function fetchRemoteFileLog(profile, path, signal) {
  return inspect(profile, `${base(profile)}/log${buildQuery({ path })}`, signal)
}

export function cachedRemoteDiff(profile, { from, to, path } = {}) {
  return cachedInspection(`${base(profile)}/diff${buildQuery({ from, to, path })}`)
}

export function fetchRemoteDiff(profile, { from, to, path, signal } = {}) {
  return inspect(profile, `${base(profile)}/diff${buildQuery({ from, to, path })}`, signal, {
    cacheable: true,
    tier: 'immutable',
  })
}

export function buildRemoteDownloadUrl(profile, { path, commit } = {}) {
  return `${base(profile)}/download${buildQuery({ path, commit })}`
}

export function buildRemoteThumbnailUrl(profile, { path, hash, commit, size = 160, rev } = {}) {
  if (!hash) return ''
  return `${base(profile)}/thumbnail${buildQuery({
    path,
    hash,
    commit: commit || undefined,
    size,
    rev: rev || undefined,
  })}`
}

const MAX_SAVED_PREVIEW_THUMBS = 256
const savedPreviewThumbs = new Map()

export function getSavedRemoteThumbnail(profile, hash) {
  if (!profile || !hash) return ''
  const key = `${profile}|${hash}`
  const value = savedPreviewThumbs.get(key)
  if (!value) return ''
  savedPreviewThumbs.delete(key)
  savedPreviewThumbs.set(key, value)
  return value
}

export function saveRemoteThumbnail(profile, hash, dataUrl) {
  if (!profile || !hash || !dataUrl) return
  const key = `${profile}|${hash}`
  if (savedPreviewThumbs.has(key)) savedPreviewThumbs.delete(key)
  savedPreviewThumbs.set(key, dataUrl)
  while (savedPreviewThumbs.size > MAX_SAVED_PREVIEW_THUMBS) {
    const oldest = savedPreviewThumbs.keys().next().value
    if (oldest === undefined) break
    savedPreviewThumbs.delete(oldest)
  }
}

export function clearSavedRemoteThumbnails(profile) {
  if (!profile) {
    savedPreviewThumbs.clear()
    return
  }
  const prefix = `${profile}|`
  for (const key of [...savedPreviewThumbs.keys()]) {
    if (key.startsWith(prefix)) savedPreviewThumbs.delete(key)
  }
}

export function readFileChunk(profile, url, offset, maxBytes, signal) {
  const range = `bytes=${offset}-${offset + maxBytes - 1}`
  return readInspection(profile, `${url}#${range}`, (sharedSignal) => retryInspection(async () => {
    const response = await fetch(url, {
      credentials: 'same-origin',
      headers: { Range: range },
      signal: sharedSignal,
    })
    if (response.status === 416 && offset === 0 && response.headers.get('content-range') === 'bytes */0') {
      return { bytes: new Uint8Array(), done: true }
    }
    if (!response.ok) {
      const body = await response.json().catch(() => null)
      const code = body?.code || ''
      if (response.status === 401 || (response.status === 403 && code === 'invalid_credential')) {
        notifyUnauthorized()
      }
      throw new ApiError(body?.error || `HTTP ${response.status}`, { status: response.status, code })
    }
    const bytes = new Uint8Array(await response.arrayBuffer())
    const total = Number(response.headers.get('content-range')?.split('/').at(-1))
    return { bytes, done: Number.isFinite(total) ? offset + bytes.length >= total : bytes.length < maxBytes }
  }, sharedSignal), { signal, priority: 'high', queueKey: url.startsWith('/v1/local/') ? local(profile) : profile })
}

export function restoreRemote(profile, { dst, prefix, commit, dryRun = true, signal } = {}) {
  const body = { dst, dry_run: dryRun }
  if (prefix) body.prefix = prefix
  if (commit) body.commit = commit
  return apiRequest(`${base(profile)}/restore`, { method: 'POST', body, signal })
}

export function fetchRemoteWriters(profile, signal) {
  return inspect(profile, `${base(profile)}/writers`, signal, { cacheable: false })
}

export function fetchRemoteHealth(profile, signal, { refresh = false } = {}) {
  return inspect(profile, `${base(profile)}/health`, signal, { refresh })
}
