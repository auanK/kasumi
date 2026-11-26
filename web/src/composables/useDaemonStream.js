import { computed, reactive, ref, watch } from 'vue'
import { fetchAuthStatus } from '../api/auth.js'
import { fetchDaemonLogs, fetchDaemonStatus } from '../api/daemon.js'
import { notifyUnauthorized } from '../api/http.js'
import { connectEventStream } from '../api/sse.js'
import { invalidateInspections } from '../api/inspections.js'

const MAX_LOG_ITEMS = 300

const daemonStatus = ref(null)
const daemonInstance = ref('')
const jobs = ref([])
const logs = ref([])
const streamState = ref('disconnected')
const error = ref('')
const uptimeAnchorSeconds = ref(null)
const uptimeAnchorMs = ref(0)
const nowTickMs = ref(Date.now())

let handle = null
let refCount = 0
let statusRevision = 0
let statusRequest = 0
let statusInFlight = null
let fallbackTimer = null
let uptimeTimer = null

function updateUptimeAnchor(seconds) {
  if (typeof seconds === 'number' && Number.isFinite(seconds)) {
    const now = Date.now()
    uptimeAnchorSeconds.value = seconds
    uptimeAnchorMs.value = now
    nowTickMs.value = now
  }
}

function clearUptimeTimer() {
  if (uptimeTimer !== null) {
    window.clearInterval(uptimeTimer)
    uptimeTimer = null
  }
}

function ensureUptimeTimer() {
  if (!handle || uptimeTimer !== null || typeof window === 'undefined') return
  nowTickMs.value = Date.now()
  uptimeTimer = window.setInterval(() => {
    nowTickMs.value = Date.now()
  }, 1000)
}

const liveUptimeSeconds = computed(() => {
  const base = uptimeAnchorSeconds.value ?? daemonStatus.value?.uptime_seconds
  if (typeof base !== 'number' || !Number.isFinite(base)) return null
  if (daemonStatus.value?.running === false || streamState.value !== 'connected') {
    return base
  }
  const elapsed = Math.max(0, Math.floor((nowTickMs.value - uptimeAnchorMs.value) / 1000))
  return base + elapsed
})

function clearFallbackPolling() {
  if (fallbackTimer !== null) {
    window.clearInterval(fallbackTimer)
    fallbackTimer = null
  }
}

function ensureFallbackPolling() {
  if (!handle || fallbackTimer !== null || typeof window === 'undefined') return
  fallbackTimer = window.setInterval(() => {
    refreshStatus().catch(() => {})
  }, 5000)
}

watch(() => daemonStatus.value?.profiles, (profiles, before) => {
  if (!profiles || !before) return
  const current = new Map(profiles.map((profile) => [profile.name, profile]))
  for (const old of before) {
    const profile = current.get(old.name)
    if (!profile || (profile.locked && !old.locked)) {
      invalidateInspections(old.name, { discard: true })
    } else if (old.last_sync_finished_at !== profile.last_sync_finished_at ||
               (old.state === 'running_sync' && profile.state !== 'running_sync') ||
               (old.busy && !profile.busy)) {
      invalidateInspections(old.name)
    }
  }
}, { flush: 'sync' })

const HISTORY_REWRITING_OPS = new Set(['gc', 'garbage_collect', 'repack', 'resolve_missing', 'resolve-missing'])

watch(jobs, (current, before) => {
  const running = new Set(before.filter((job) => job.state === 'running').map((job) => job.id))
  for (const job of current) {
    if (job.state === 'completed' && job.operation !== 'preview' && running.has(job.id)) {
      invalidateInspections(job.profile, {
        includeImmutable: HISTORY_REWRITING_OPS.has(job.operation),
      })
    }
  }
}, { flush: 'sync' })

function mergeStatusSnapshot(snapshot) {
  if (!snapshot) return
  if (typeof snapshot.daemon_instance === 'string' && snapshot.daemon_instance) {
    daemonInstance.value = snapshot.daemon_instance
  }
  if (Array.isArray(snapshot.jobs)) {
    jobs.value = snapshot.jobs
  }
  if (typeof snapshot.uptime_seconds === 'number') {
    updateUptimeAnchor(snapshot.uptime_seconds)
  }
  if (snapshot.daemon || snapshot.profiles) {
    statusRevision++
    daemonStatus.value = {
      ...(daemonStatus.value || {}),
      ...snapshot,
    }
  }
}

function appendLog(entry) {
  if (!entry) return
  if (entry.seq && logs.value.some((item) => item.seq === entry.seq)) {
    return
  }
  logs.value = [...logs.value.slice(-(MAX_LOG_ITEMS - 1)), entry]
}

export function refreshStatus() {
  if (statusInFlight) return statusInFlight
  const request = ++statusRequest
  const revision = statusRevision
  const promise = (async () => {
    try {
      const status = await fetchDaemonStatus()
      if (request === statusRequest) {
        if (typeof status?.daemon_instance === 'string' && status.daemon_instance) {
          daemonInstance.value = status.daemon_instance
        }
        const live = daemonStatus.value
        daemonStatus.value = revision === statusRevision || !live ? status : {
          ...status,
          profiles: live.profiles ?? status.profiles,
          uptime_seconds: live.uptime_seconds ?? status.uptime_seconds,
        }
        if (revision === statusRevision || typeof live?.uptime_seconds !== 'number') {
          updateUptimeAnchor(status?.uptime_seconds)
        }
        error.value = ''
      }
      return status
    } catch (err) {
      if (request === statusRequest) error.value = err?.message || 'Failed to query background service'
      throw err
    } finally {
      if (statusInFlight === promise) statusInFlight = null
    }
  })()
  statusInFlight = promise
  return promise
}

export function ensureStatus() {
  if (daemonStatus.value) return Promise.resolve(daemonStatus.value)
  if (statusInFlight) return statusInFlight
  return refreshStatus()
}

export async function refreshLogs(options = {}) {
  const report = await fetchDaemonLogs(options)
  if (report && Array.isArray(report.events)) {
    const latestSeq = report.latest_seq ?? report.events.at(-1)?.seq ?? 0
    const newerEvents = logs.value.filter((entry) => entry.seq > latestSeq)
    logs.value = [...report.events, ...newerEvents].slice(-MAX_LOG_ITEMS)
  }
  return report
}

export function startDaemonStream() {
  refCount += 1
  if (handle) return
  ensureStatus().catch(() => {})
  refreshLogs({ lines: 120, full: true }).catch(() => {})
  handle = connectEventStream({
    onStatus: (payload) => mergeStatusSnapshot(payload),
    onLog: (entry) => appendLog(entry),
    onStateChange: (next) => {
      streamState.value = next
      if (next === 'connected') {
        clearFallbackPolling()
        ensureUptimeTimer()
      } else if (next === 'reconnecting') {
        clearUptimeTimer()
        if (handle) {
          refreshStatus().catch(() => {})
          ensureFallbackPolling()
        }
      } else if (next === 'disconnected') {
        clearUptimeTimer()
      }
    },
    checkSession: async () => {
      const info = await fetchAuthStatus()
      return Boolean(info?.authenticated)
    },
    onSessionExpired: () => {
      notifyUnauthorized()
    },
  })
}

export function stopDaemonStream(force = false) {
  refCount = force ? 0 : Math.max(0, refCount - 1)
  if (refCount === 0 && handle) {
    const active = handle
    handle = null
    clearFallbackPolling()
    clearUptimeTimer()
    active.close()
    statusInFlight = null
    statusRequest++
    invalidateInspections(undefined, { discard: true })
    daemonStatus.value = null
    daemonInstance.value = ''
    uptimeAnchorSeconds.value = null
    uptimeAnchorMs.value = 0
    jobs.value = []
    logs.value = []
  }
}

export function useDaemonStream() {
  return reactive({
    daemonStatus,
    daemonInstance,
    liveUptimeSeconds,
    jobs,
    logs,
    streamState,
    error,
    refreshStatus,
    ensureStatus,
    refreshLogs,
    startDaemonStream,
    stopDaemonStream,
  })
}
