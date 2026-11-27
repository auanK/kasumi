import { formatBytes, translateWithFallback } from './format.js'

const STAGE_KEY_ALIASES = {
  checking_controls: 'checking_controls',
  establishing_barrier: 'establishing_barrier',
  probing_consistency: 'probing_consistency',
  listing_remote: 'listing',
  authenticating_history: 'authenticating',
  analyzing_reachability: 'analyzing_reachability',
  loading_activities: 'loading_activities',
  removing_objects: 'removing',
  releasing_barrier: 'releasing_barrier',
  auditing_content: 'auditing_content',
  preparing_plan: 'planning',
  comparing_snapshots: 'comparing',
  checking_remote_content: 'checking_remote',
}

const JOB_STEPS = {
  gc: ['preparing', 'analyzing', 'applying', 'finalizing'],
  fsck: ['preparing', 'observing', 'analyzing', 'auditing_content', 'finalizing'],
  repack: ['scanning', 'preparing_remote', 'staging', 'uploading', 'verifying'],
  resolve_missing: ['observing', 'calculating', 'applying', 'publishing', 'finalizing'],
  'resolve-missing': ['observing', 'calculating', 'applying', 'publishing', 'finalizing'],
  sync: ['observing', 'calculating', 'applying', 'publishing', 'finalizing'],
}

export const SIMULATION_OPS = new Set(['gc', 'repack', 'resolve-missing', 'resolve_missing'])

export function isDryRunJob(job) {
  return Boolean(job?.dry_run ?? job?.result?.dry_run ?? job?.summary?.dry_run)
}

export function jobData(job) {
  return job?.result || job?.summary || null
}

export function getJobSteps(operation) {
  return JOB_STEPS[operation] || []
}

export function resolveJobDurationMs(record, fallbackFinished = 0, fallbackStarted = 0) {
  if (typeof record?.duration_ms === 'number' && record.duration_ms >= 0) return record.duration_ms
  if (typeof record?.result?.duration_ms === 'number' && record.result.duration_ms >= 0) {
    return record.result.duration_ms
  }
  const finished = record?.finished_at || fallbackFinished || 0
  const started = record?.started_at || fallbackStarted || 0
  if (finished && started && finished >= started) {
    return (finished - started) * 1000
  }
  return null
}

function translateStage(raw, t) {
  if (!raw) return ''
  const mapped = STAGE_KEY_ALIASES[raw] || raw
  return translateWithFallback(t, 'stage.' + mapped, raw)
}

export function formatJobStage(job, t) {
  const progress = job?.progress
  if (!progress || typeof progress !== 'object') return ''
  const sub = translateStage(progress.sub_stage && progress.sub_stage !== 'none' ? progress.sub_stage : '', t)
  const activity = translateStage(progress.activity || '', t)
  const primary = translateStage(progress.stage || '', t)
  return sub || activity || primary
}

export function extractJobProgressMeter(job, t) {
  const p = job?.progress
  if (!p || typeof p !== 'object') return { current: null, total: null, percent: null, countLabel: '', bytesLabel: '' }

  let current = null
  let total = null
  let countLabel = ''
  if (p.total_objects > 0) {
    current = p.completed_objects ?? p.objects ?? 0
    total = p.total_objects
    countLabel = t('sync.objects', { done: current, total })
  } else if (p.candidate_objects > 0) {
    current = p.removed_objects ?? 0
    total = p.candidate_objects
    countLabel = t('sync.objects', { done: current, total })
  } else if (p.total_items > 0) {
    current = p.applied_items ?? 0
    total = p.total_items
    countLabel = t('sync.changes', { done: current, total })
  } else if (p.completed_objects > 0 || p.objects > 0) {
    current = p.completed_objects ?? p.objects
    countLabel = t('sync.count', { count: current })
  }

  let bytesLabel = ''
  const doneBytes = p.completed_plaintext_bytes ?? p.bytes ?? null
  const totalBytes = p.total_plaintext_bytes ?? p.total_bytes ?? null
  if (totalBytes > 0) {
    bytesLabel = `${formatBytes(doneBytes || 0)} / ${formatBytes(totalBytes)}`
    if (total == null) {
      current = doneBytes || 0
      total = totalBytes
    }
  } else if (doneBytes > 0) {
    bytesLabel = formatBytes(doneBytes)
  }

  const percent = total > 0 && current != null
    ? Math.min(100, Math.floor((100 * current) / total))
    : null
  return { current, total, percent, countLabel, bytesLabel }
}

export function extractJobMetrics(job, t) {
  const value = jobData(job)
  if (!value) return []
  const dryRun = isDryRunJob(job)
  const op = job?.operation
  const metrics = []

  const add = (labelKey, val) => {
    if (val !== undefined && val !== null && val !== '—' && val !== '') {
      metrics.push([labelKey, val])
    }
  }

  if (op === 'fsck') {
    add('maintenance.checkedObjects', value.checked_objects)
    add('maintenance.checkedBytes', value.checked_plaintext_bytes != null ? formatBytes(value.checked_plaintext_bytes) : undefined)
    add('maintenance.filesReassembled', value.files_reassembled)
    add('maintenance.wireDownload', value.wire_download_bytes != null ? formatBytes(value.wire_download_bytes) : undefined)
  } else if (op === 'gc' || op === 'garbage_collect') {
    add('maintenance.candidateObjects', value.candidate_objects)
    add('maintenance.spaceOrphans', value.candidate_bytes != null ? formatBytes(value.candidate_bytes) : undefined)
    if (!dryRun) {
      add('maintenance.removedObjects', value.removed_objects)
      add('maintenance.removedBytes', value.removed_bytes != null ? formatBytes(value.removed_bytes) : undefined)
    }
    add('maintenance.candidateContent', value.candidate_content_objects)
    add('maintenance.candidateCommits', value.candidate_expired_commits)
    add('maintenance.candidateActivities', value.candidate_activities)
    add('maintenance.deferredRecent', value.deferred_recent_objects)
  } else if (op === 'repack') {
    add('maintenance.liveSmallBlobs', value.live_small_blobs)
    add('maintenance.dirtyPacks', value.dirty_packs_detected)
    add('maintenance.looseBlobs', value.loose_small_blobs_detected)
    add('maintenance.repackedObjects', value.repacked_blobs)
    add('maintenance.repackedBytes', value.repacked_plaintext_bytes != null ? formatBytes(value.repacked_plaintext_bytes) : undefined)
    if (!dryRun) add('maintenance.newPacks', value.new_packs)
  } else if (op === 'resolve-missing' || op === 'resolve_missing') {
    add('maintenance.resolvedPaths', value.resolved_count)
    add('maintenance.publishedLabel', value.published === undefined ? undefined : t(value.published ? 'maintenance.publishedYes' : 'maintenance.publishedNo'))
  } else if (op === 'remove-writer' || op === 'remove_writer') {
    if (Array.isArray(value.removed_identifiers)) {
      add('maintenance.writersRemoved', value.removed_identifiers.length)
    }
    if (value.already_absent_identifiers?.length) {
      add('maintenance.writersAlreadyAbsent', value.already_absent_identifiers.length)
    }
  } else {
    add('overview.sendBytes', value.upload_bytes != null ? formatBytes(value.upload_bytes) : (value.wire_upload_bytes != null ? formatBytes(value.wire_upload_bytes) : undefined))
    add('overview.receiveBytes', value.download_bytes != null ? formatBytes(value.download_bytes) : (value.wire_download_bytes != null ? formatBytes(value.wire_download_bytes) : undefined))
    add('maintenance.scheduledPending', value.pending)
  }

  return metrics
}

export function formatJobHeadline(job, t) {
  const value = jobData(job)
  if (!value) return ''
  if (job?.state === 'failed') return value.error || t('outcome.failed')
  const dryRun = isDryRunJob(job)
  const op = job?.operation

  if (op === 'fsck') {
    return t('maintenance.summary.fsck', {
      objects: value.checked_objects ?? 0,
      bytes: formatBytes(value.checked_plaintext_bytes ?? 0),
    })
  }
  if (op === 'gc' || op === 'garbage_collect') {
    const count = dryRun ? (value.candidate_objects ?? 0) : (value.removed_objects ?? 0)
    const bytes = formatBytes((dryRun ? value.candidate_bytes : value.removed_bytes) ?? 0)
    if (dryRun) {
      return count === 0
        ? t('maintenance.summary.gcSimEmpty')
        : t('maintenance.summary.gcSim', { count, bytes })
    }
    return t('maintenance.summary.gcReal', { count, bytes })
  }
  if (op === 'repack') {
    if (dryRun) {
      return value.actionable
        ? t('maintenance.summary.repackSim', {
            blobs: value.repacked_blobs ?? value.loose_small_blobs_detected ?? 0,
            packs: value.dirty_packs_detected ?? 0,
          })
        : t('maintenance.summary.repackSimEmpty')
    }
    return t('maintenance.summary.repackReal', {
      blobs: value.repacked_blobs ?? 0,
      packs: value.new_packs ?? 0,
    })
  }
  if (op === 'resolve-missing' || op === 'resolve_missing') {
    return t(dryRun ? 'maintenance.summary.resolveSim' : 'maintenance.summary.resolveReal', {
      count: value.resolved_count ?? 0,
    })
  }
  if (op === 'remove-writer' || op === 'remove_writer') {
    if (Array.isArray(value.removed_identifiers)) {
      const removed = value.removed_identifiers.length
      const absent = value.already_absent_identifiers?.length ?? 0
      if (removed === 1 && absent === 0) {
        return t('maintenance.summary.removeWriter', { id: value.removed_identifiers[0] })
      }
      return t('maintenance.summary.removeWritersBatch', { removed, absent })
    }
    if (value.identifier) {
      return t('maintenance.summary.removeWriter', { id: value.identifier })
    }
  }
  if (op === 'sync') {
    return t('maintenance.summary.sync', {
      uploaded: value.uploaded ?? 0,
      downloaded: value.downloaded ?? 0,
    })
  }
  return ''
}
