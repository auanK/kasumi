import { apiRequest, encodeSegment } from './http.js'

export function startPreviewJob(profile, signal) {
  return apiRequest(`/v1/profiles/${encodeSegment(profile)}/preview`, {
    method: 'POST',
    body: {},
    signal,
  })
}

export function startMaintenanceJob(profile, operation, payload = {}) {
  return apiRequest(
    `/v1/maintenance/${encodeSegment(profile)}/${encodeSegment(operation)}`,
    {
      method: 'POST',
      body: payload,
    }
  )
}

export function fetchJob(jobId, signal) {
  return apiRequest(`/v1/jobs/${encodeSegment(jobId)}`, { signal })
}
