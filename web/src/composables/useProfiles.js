import { computed, ref, watch } from 'vue'
import { getProfile, listProfiles } from '../api/profiles.js'
import { useDaemonStream } from './useDaemonStream.js'

const profiles = ref([])
const loading = ref(false)
const loaded = ref(false)
const error = ref('')
const stream = useDaemonStream()
let inFlightRefresh = null
let refreshGeneration = 0

watch(() => stream.daemonStatus?.profiles, (snapshot, previous) => {
  if (!snapshot || !previous) return
  const prior = new Map(previous.map((profile) => [profile.name, profile]))
  for (const profile of snapshot) {
    const old = prior.get(profile.name)
    const row = profiles.value.find((item) => item.name === profile.name)
    if (!old || !row) continue
    if (old.last_sync_finished_at === profile.last_sync_finished_at &&
        !(old.state === 'running_sync' && profile.state !== 'running_sync') &&
        !(old.busy && !profile.busy)) continue
    getProfile(profile.name).then((updated) => {
      if (updated?.activity && profiles.value.includes(row)) {
        row.activity = updated.activity
        row.state = updated.state
        row.problem = updated.problem
      }
    }).catch(() => {})
  }
})

export function clearProfiles() {
  refreshGeneration++
  inFlightRefresh = null
  profiles.value = []
  loaded.value = false
  loading.value = false
  error.value = ''
}

export function refreshProfiles() {
  if (inFlightRefresh) return inFlightRefresh
  const generation = refreshGeneration
  loading.value = true
  error.value = ''
  // Trigger shared daemon status recovery non-blockingly only if not already loaded/in-flight.
  stream.ensureStatus().catch(() => {})
  const promise = (async () => {
    try {
      const res = await listProfiles()
      if (generation !== refreshGeneration) return profiles.value
      profiles.value = Array.isArray(res?.profiles) ? res.profiles : []
      loaded.value = true
      return profiles.value
    } catch (err) {
      if (generation === refreshGeneration) {
        error.value = err?.message || 'Failed to load profiles'
      }
      throw err
    } finally {
      if (generation === refreshGeneration) {
        loading.value = false
      }
      if (inFlightRefresh === promise) {
        inFlightRefresh = null
      }
    }
  })()
  inFlightRefresh = promise
  return promise
}

export function useProfiles() {
  const daemonMap = computed(() => {
    const map = new Map()
    for (const item of stream.daemonStatus?.profiles || []) {
      map.set(item.name, item)
    }
    return map
  })

  return {
    profiles,
    loading,
    loaded,
    error,
    daemonMap,
    refreshProfiles,
    clearProfiles,
  }
}
