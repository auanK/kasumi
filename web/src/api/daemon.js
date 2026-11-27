import { apiRequest, buildQuery } from './http.js'
import { invalidateInspections } from './inspections.js'

export function fetchDaemonStatus(profile) {
  return apiRequest(`/v1/status${buildQuery({ profile })}`)
}

export function fetchDaemonLogs({ profile, lines = 150, full = true } = {}) {
  return apiRequest(`/v1/logs${buildQuery({ profile, lines, full: full ? 'true' : 'false' })}`)
}

export function triggerSync({ profile, wait = false } = {}) {
  const body = { wait }
  if (profile) body.profile = profile
  return apiRequest('/v1/sync', { method: 'POST', body })
}

export function pauseProfile(profile) {
  return apiRequest('/v1/pause', { method: 'POST', body: { profile } })
}

export function resumeProfile(profile) {
  return apiRequest('/v1/resume', { method: 'POST', body: { profile } })
}

export function unlockProfile(profile, credentials) {
  return apiRequest('/v1/unlock', {
    method: 'POST',
    body: { profile, ...credentials },
  })
}

export async function lockProfile(profile) {
  const result = await apiRequest('/v1/lock', { method: 'POST', body: { profile } })
  invalidateInspections(profile, { discard: true })
  return result
}

export function cancelProfileSync(profile) {
  return apiRequest('/v1/cancel', { method: 'POST', body: { profile } })
}

export function reloadDaemonConfig() {
  return apiRequest('/v1/reload', { method: 'POST', body: {} })
}

export function stopDaemon() {
  return apiRequest('/v1/stop', { method: 'POST', body: {} })
}

export function setAutostart(enabled) {
  return apiRequest('/v1/autostart', { method: 'POST', body: { enabled: Boolean(enabled) } })
}

export function fetchWebConfig() {
  return apiRequest('/v1/web/config')
}

export function updateWebConfig(payload) {
  return apiRequest('/v1/web/config', { method: 'PATCH', body: payload })
}
