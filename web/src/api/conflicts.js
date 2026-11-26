import { apiRequest, buildQuery, encodeSegment } from './http.js'

export function listConflicts(profile, { signal } = {}) {
  return apiRequest(`/v1/conflicts/${encodeSegment(profile)}`, { signal })
}

export function fetchConflictDiff(profile, { path, artifact, signal }) {
  return apiRequest(`/v1/conflicts/${encodeSegment(profile)}/diff${buildQuery({ path, artifact })}`, { signal })
}

export function resolveConflict(profile, { path, choice, artifact, dryRun = true }) {
  const body = { path, choice, dry_run: dryRun }
  if (artifact) body.artifact = artifact
  return apiRequest(`/v1/conflicts/${encodeSegment(profile)}/resolve`, {
    method: 'POST',
    body,
  })
}
