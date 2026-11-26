import { apiRequest, encodeSegment } from './http.js'
import { invalidateInspections } from './inspections.js'

async function changeProfile(name, path, options) {
  const result = await apiRequest(`/v1/profiles/${encodeSegment(name)}${path}`, options)
  invalidateInspections(name, { discard: true })
  return result
}

export function listProfiles() {
  return apiRequest('/v1/profiles')
}

export function getProfile(name) {
  return apiRequest(`/v1/profiles/${encodeSegment(name)}`)
}

export function createProfile(payload) {
  return apiRequest('/v1/profiles', { method: 'POST', body: payload })
}

export function updateProfile(name, payload) {
  return changeProfile(name, '', { method: 'PATCH', body: payload })
}

export async function uploadProfileIcon(name, file) {
  if (!file) throw new Error('No file selected')
  if (file.size > 512 * 1024) {
    throw new Error('Image exceeds 512 KB')
  }
  const buffer = await file.arrayBuffer()
  const bytes = new Uint8Array(buffer)
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  const result = await apiRequest(`/v1/profiles/${encodeSegment(name)}/icon`, {
    method: 'POST',
    body: { data_base64: btoa(binary) },
  })
  return result
}

export function deleteProfileIcon(name) {
  return apiRequest(`/v1/profiles/${encodeSegment(name)}/icon`, {
    method: 'DELETE',
    body: {},
  })
}

export function cloneProfile(name, targetName) {
  return apiRequest(`/v1/profiles/${encodeSegment(name)}/clone`, {
    method: 'POST',
    body: { name: targetName },
  })
}

export function renameProfile(name, targetName) {
  return changeProfile(name, '/rename', {
    method: 'POST',
    body: { name: targetName },
  })
}

export function updateProfileStorage(name, keyStorage) {
  return changeProfile(name, '/storage', {
    method: 'POST',
    body: { key_storage: keyStorage },
  })
}

export function updateProfileKey(name, payload) {
  return changeProfile(name, '/key', {
    method: 'POST',
    body: payload,
  })
}

export function deleteProfile(name) {
  return changeProfile(name, '', {
    method: 'DELETE',
    body: { confirm: true },
  })
}

export function testProfileConnection(name, { signal } = {}) {
  return apiRequest(`/v1/profiles/${encodeSegment(name)}/test`, {
    method: 'POST',
    body: {},
    signal,
  })
}

export function listRcloneRemotes({ signal } = {}) {
  return apiRequest('/v1/rclone/remotes', { signal })
}

export function fetchDiagnostics(profile) {
  if (profile) {
    return apiRequest(`/v1/diagnostics/${encodeSegment(profile)}`)
  }
  return apiRequest('/v1/diagnostics')
}

export function checkIgnorePaths(profile, paths, { signal } = {}) {
  return apiRequest(`/v1/profiles/${encodeSegment(profile)}/ignore/check`, {
    method: 'POST',
    body: { paths },
    signal,
  })
}

export function initIgnoreFile(profile, { preset = 'default', dryRun = true, force = false, signal } = {}) {
  return apiRequest(`/v1/profiles/${encodeSegment(profile)}/ignore/init`, {
    method: 'POST',
    body: { preset, dry_run: dryRun, force },
    signal,
  })
}
