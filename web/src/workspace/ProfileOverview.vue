<script setup>
import { computed } from 'vue'
import { t } from '../i18n/index.js'
import { formatTimestamp, formatDuration, formatDurationMs, shortHash, translateWithFallback } from '../utils/format.js'
import { resolveJobDurationMs } from '../utils/jobFormat.js'

const props = defineProps({
  profile: { type: Object, required: true },
  daemonState: { type: Object, default: null },
})
const live = computed(() => props.daemonState || props.profile.daemon || {})
const activity = computed(() => props.profile.activity || {})
const lastSync = computed(() => activity.value.last_complete_sync)
const latest = computed(() => activity.value.last_attempt)
const commit = computed(() => activity.value.accepted_commit)
const executions = computed(() =>
  [...(activity.value.recent_executions || [])]
    .sort((a, b) => (b.finished_at || b.started_at || 0) - (a.finished_at || a.started_at || 0))
    .slice(0, 30)
)
const lastSyncDurationMs = computed(() =>
  resolveJobDurationMs(
    lastSync.value,
    live.value.last_sync_finished_at,
    live.value.last_sync_started_at
  )
)
const lastSyncNote = computed(() => {
  const parts = []
  if (lastSync.value?.status) parts.push(outcome(lastSync.value.status))
  if (lastSyncDurationMs.value != null) parts.push(formatDurationMs(lastSyncDurationMs.value))
  return parts.join(' · ')
})
const watchEnabled = computed(() => live.value.watch_enabled ?? props.profile.watch_enabled ?? true)
const interval = computed(() => live.value.sync_interval_seconds ?? props.profile.sync_interval_seconds ?? 300)
const issue = computed(() => live.value.last_error || (props.profile.state === 'problem'
  ? t('overview.localProblem', { problem: props.profile.problem || '—' }) : ''))
function operation(value) {
  return value ? translateWithFallback(t, 'operation.' + value, value) : '—'
}
function outcome(value) {
  return value ? translateWithFallback(t, 'outcome.' + value, value) : '—'
}
</script>

<template>
  <div class="k-overview">
    <div v-if="issue" class="k-alert k-alert--error" role="status">{{ issue }}</div>
    <div class="k-overview-grid">
      <section>
        <h3>{{ t('overview.folders') }}</h3>
        <dl class="k-facts">
          <dt>{{ t('wizard.localDir') }}</dt>
          <dd class="k-path">{{ profile.local_dir || '—' }}</dd>
          <dt>{{ t('wizard.remoteDir') }}</dt>
          <dd class="k-path">{{ profile.remote_dir || '—' }}</dd>
          <dt>{{ t('overview.watch') }}</dt>
          <dd>{{ watchEnabled ? t('common.enabled') : t('common.disabled') }}</dd>
          <dt>{{ t('overview.interval') }}</dt>
          <dd>{{ interval ? formatDuration(interval) : t('common.disabled') }}</dd>
        </dl>
      </section>
      <section>
        <h3>{{ t('overview.profileActivity') }}</h3>
        <dl class="k-facts">
          <dt>{{ t('profile.lastSync') }}</dt>
          <dd>
            {{ lastSync?.finished_at || live.last_sync_finished_at ? formatTimestamp(lastSync?.finished_at || live.last_sync_finished_at) : t('profile.neverSynced') }}
            <span v-if="lastSyncNote" class="k-fact-note">{{ lastSyncNote }}</span>
          </dd>
          <dt>{{ t('overview.lastChange') }}</dt>
          <dd>{{ commit ? formatTimestamp(commit.created_at) : '—' }}<span v-if="commit?.machine_name" class="k-fact-note">{{ commit.machine_name }}</span></dd>
          <dt>{{ t('overview.nextCheck') }}</dt>
          <dd>{{ formatTimestamp(live.next_sync_at) }}</dd>
          <dt>{{ t('overview.pending') }}</dt>
          <dd>{{ live.dirty_paths_count ?? '—' }}</dd>
        </dl>
      </section>
    </div>
    <details class="k-disclosure k-show-advanced">
      <summary>{{ t('overview.technicalDetails') }}</summary>
      <div class="k-disclosure-body k-stack">
        <dl class="k-facts">
          <dt>{{ t('overview.localState') }}</dt>
          <dd>{{ profile.state || '—' }}</dd>
          <dt>{{ t('settings.securityTitle') }}</dt>
          <dd>{{ profile.key_storage || '—' }}</dd>
          <dt>{{ t('overview.acceptedCommit') }}</dt>
          <dd class="k-path">{{ commit?.commit_id || '—' }}</dd>
          <dt>{{ t('overview.machineId') }}</dt>
          <dd class="k-path">{{ commit?.machine_id_hex || '—' }}</dd>
          <dt>{{ t('overview.retention') }}</dt>
          <dd>{{ t('overview.retentionValue', { depth: profile.min_history_depth ?? '—', hours: profile.min_history_age_hours ?? '—' }) }}</dd>
          <dt>{{ t('overview.lastAttempt') }}</dt>
          <dd>
            <template v-if="latest">
              {{ operation(latest.operation) + ' · ' + outcome(latest.status) }}<template v-if="latest.duration_ms != null"> · {{ formatDurationMs(latest.duration_ms) }}</template>
            </template>
            <template v-else>—</template>
          </dd>
        </dl>
        <div v-if="executions.length" class="k-table-scroll k-overview-history" role="region"
          :aria-label="t('overview.recentExecutions')" tabindex="0">
          <table class="k-data-table">
            <caption>{{ t('overview.recentExecutions') }}</caption>
            <thead><tr><th>{{ t('overview.lastAttempt') }}</th><th>{{ t('overview.when') }}</th><th>{{ t('overview.duration') }}</th><th>{{ t('overview.result') }}</th><th>{{ t('overview.acceptedCommit') }}</th></tr></thead>
            <tbody><tr v-for="entry in executions" :key="entry.execution_id">
              <td>{{ operation(entry.operation) }}</td>
              <td>{{ formatTimestamp(entry.finished_at || entry.started_at) }}</td>
              <td class="k-mono">{{ formatDurationMs(entry.duration_ms) }}</td>
              <td :title="entry.detail">{{ outcome(entry.status) }}<span v-if="entry.detail" class="k-fact-note k-truncate">{{ entry.detail }}</span></td>
              <td class="k-mono" :title="entry.commit_id">{{ shortHash(entry.commit_id) }}</td>
            </tr></tbody>
          </table>
        </div>
      </div>
    </details>
  </div>
</template>
