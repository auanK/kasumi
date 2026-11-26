import { shallowReactive } from 'vue'

const cache = new Map()
const pending = new Map()
const reads = new Set()
const queues = shallowReactive(new Map())
const MAX_CACHED_REPORTS = 96
const HEAD_CACHE_TTL = 300_000
const IMMUTABLE_CACHE_TTL = 900_000
const PRIORITY_RANK = { low: 0, normal: 1, high: 2 }

function getQueueState(queueKey) {
  let q = queues.get(queueKey)
  if (!q) {
    q = { active: null, waiting: [] }
    queues.set(queueKey, q)
  }
  return q
}

function updateQueuePresence(queueKey) {
  const q = queues.get(queueKey)
  if (q && !q.active && q.waiting.length === 0) {
    queues.delete(queueKey)
  }
}

function pumpQueue(queueKey) {
  const q = queues.get(queueKey)
  if (!q || q.active) return
  while (q.waiting.length > 0) {
    const next = q.waiting.shift()
    if (next.controller.signal.aborted || next.cancelled) {
      updateQueuePresence(queueKey)
      continue
    }
    q.active = next
    queueMicrotask(() => {
      if (next.controller.signal.aborted || next.cancelled) {
        next.releaseSlot()
        return
      }
      next.run()
    })
    return
  }
  updateQueuePresence(queueKey)
}

export function cachedInspection(key) {
  const entry = cache.get(key)
  if (!entry) return null
  cache.delete(key)
  cache.set(key, entry)
  return { ...entry, fresh: entry.expiresAt > Date.now() }
}

export function inspectionPending(queueKey) {
  return queues.has(queueKey)
}

export function invalidateInspections(profile, { discard = false, includeImmutable = false } = {}) {
  for (const [key, entry] of cache) {
    if (profile !== undefined && profile !== entry.profile) continue
    if (discard) {
      cache.delete(key)
    } else if (entry.tier !== 'immutable' || includeImmutable) {
      entry.expiresAt = 0
    }
  }
  for (const entry of [...reads]) {
    if (profile !== undefined && profile !== entry.profile) continue
    if (discard) {
      entry.expired = true
      entry.cancelAndRelease()
    } else if (entry.tier !== 'immutable' || includeImmutable) {
      entry.expired = true
    }
  }
}

export async function readInspection(
  profile,
  key,
  request,
  {
    signal,
    cacheable = false,
    refresh = false,
    queueKey = profile,
    priority = 'normal',
    tier = 'head',
  } = {},
) {
  signal?.throwIfAborted()
  const cached = cacheable && !refresh && cachedInspection(key)
  if (cached?.fresh) return cached.value

  let entry = pending.get(key)
  if (!entry || entry.controller.signal.aborted || entry.expired) {
    const controller = new AbortController()
    const rank = PRIORITY_RANK[priority] ?? PRIORITY_RANK.normal
    const q = getQueueState(queueKey)

    let settled = false
    let slotReleased = false
    let resolveResult
    let rejectResult
    const result = new Promise((resolve, reject) => {
      resolveResult = resolve
      rejectResult = reject
    })

    const current = {
      profile,
      key,
      queueKey,
      priority: rank,
      tier,
      controller,
      readers: 0,
      expired: false,
      started: false,
      cancelled: false,
      result,
      releaseSlot() {
        if (slotReleased) return
        slotReleased = true
        if (q.active === current) {
          q.active = null
        } else {
          const idx = q.waiting.indexOf(current)
          if (idx !== -1) q.waiting.splice(idx, 1)
        }
        pumpQueue(queueKey)
      },
      cancelAndRelease() {
        current.cancelled = true
        if (!controller.signal.aborted) {
          controller.abort()
        }
        reads.delete(current)
        if (pending.get(key) === current) pending.delete(key)
        current.releaseSlot()
        if (!settled) {
          settled = true
          rejectResult(controller.signal.reason || new DOMException('Aborted', 'AbortError'))
        }
      },
      async run() {
        if (controller.signal.aborted || current.cancelled) {
          reads.delete(current)
          if (pending.get(key) === current) pending.delete(key)
          current.releaseSlot()
          if (!settled) {
            settled = true
            rejectResult(controller.signal.reason || new DOMException('Aborted', 'AbortError'))
          }
          return
        }
        current.started = true
        const timeout = setTimeout(
          () => controller.abort(new DOMException('Inspection timed out', 'TimeoutError')),
          45_000,
        )
        try {
          const value = await request(controller.signal)
          clearTimeout(timeout)
          controller.signal.throwIfAborted()
          if (cacheable && !current.expired) {
            const readAt = Date.now()
            const ttl = tier === 'immutable' ? IMMUTABLE_CACHE_TTL : HEAD_CACHE_TTL
            cache.delete(key)
            cache.set(key, { profile, tier, value, readAt, expiresAt: readAt + ttl })
            if (cache.size > MAX_CACHED_REPORTS) cache.delete(cache.keys().next().value)
          }
          if (!settled) {
            settled = true
            resolveResult(value)
          }
        } catch (err) {
          clearTimeout(timeout)
          if (!settled) {
            settled = true
            rejectResult(err)
          }
        } finally {
          reads.delete(current)
          if (pending.get(key) === current) pending.delete(key)
          current.releaseSlot()
        }
      },
    }

    pending.set(key, current)
    reads.add(current)

    // Insert waiting item ordered by priority (highest first, FIFO within equal priority).
    let insertAt = q.waiting.length
    for (let i = 0; i < q.waiting.length; i++) {
      if (q.waiting[i].priority < rank) {
        insertAt = i
        break
      }
    }
    q.waiting.splice(insertAt, 0, current)
    pumpQueue(queueKey)
    entry = current
  }

  entry.readers++
  let abort
  try {
    if (!signal) return await entry.result
    const cancellation = new Promise((_, reject) => {
      abort = () => reject(signal.reason)
      signal.addEventListener('abort', abort, { once: true })
    })
    return await Promise.race([entry.result, cancellation])
  } finally {
    if (abort) signal.removeEventListener('abort', abort)
    // Abort even an already-started request when no browser consumers remain,
    // and immediately free its queue slot so previews or next navigation aren't blocked.
    if (--entry.readers === 0 && signal?.aborted) {
      entry.cancelAndRelease()
    }
  }
}
