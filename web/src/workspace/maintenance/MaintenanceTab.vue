<script setup>
import { computed, onUnmounted, ref, watch } from 'vue'
import { fetchJob } from '../../api/maintenance.js'
import { useDaemonStream } from '../../composables/useDaemonStream.js'
import { useProfileActivity } from '../../composables/useProfileActivity.js'
import { pushToast } from '../../composables/useToasts.js'
import { t } from '../../i18n/index.js'
import { SIMULATION_OPS, formatJobHeadline, isDryRunJob } from '../../utils/jobFormat.js'
import IgnoreRulesCard from './IgnoreRulesCard.vue'
import JobsActivityCard from './JobsActivityCard.vue'
import QuickActionsCard from './QuickActionsCard.vue'
import VaultSpaceCard from './VaultSpaceCard.vue'

const props = defineProps({
  profile: { type: String, required: true },
})

const stream = useDaemonStream()
const { blockedReason } = useProfileActivity(() => props.profile)
const submittedJobs = ref([])
const startingAction = ref(false)
const verifyingJobs = new Set()
const notifiedFinished = new Set()
let pollAbort

const profileJobs = computed(() => {
  const byId = new Map()
  for (const job of submittedJobs.value) {
    if (job?.id && (!job.profile || job.profile === props.profile)) byId.set(job.id, job)
  }
  for (const job of stream.jobs || []) {
    if (job?.id && (!job.profile || job.profile === props.profile)) {
      byId.set(job.id, { ...(byId.get(job.id) || {}), ...job })
    }
  }
  return Array.from(byId.values()).sort(
    (a, b) => (b.started_at || 0) - (a.started_at || 0) || (b.id || 0) - (a.id || 0)
  )
})
const runningJob = computed(() => profileJobs.value.some((job) => job.state === 'running'))
const actionReason = computed(() => blockedReason.value ||
  (runningJob.value ? t('workspace.jobInProgress') : ''))

function markJobInterrupted(id) {
  submittedJobs.value = submittedJobs.value.map((job) =>
    job.id === id && job.state === 'running'
      ? { ...job, state: 'failed', result: { error: t('maintenance.jobInterrupted') } }
      : job
  )
}

async function reconcileSubmittedJobs() {
  const liveIds = new Set((stream.jobs || []).map((job) => job.id))
  const currentInstance = stream.daemonInstance || ''
  for (const job of submittedJobs.value) {
    if (!job?.id || job.state !== 'running') continue
    if (liveIds.has(job.id)) continue
    if (currentInstance && job.daemonInstance && currentInstance !== job.daemonInstance) {
      markJobInterrupted(job.id)
      continue
    }
    if (verifyingJobs.has(job.id)) continue
    verifyingJobs.add(job.id)
    pollAbort ??= new AbortController()
    try {
      const updated = await fetchJob(job.id, pollAbort.signal)
      if (updated?.id) {
        submittedJobs.value = submittedJobs.value.map((entry) =>
          entry.id === updated.id ? { ...entry, ...updated } : entry
        )
      }
    } catch (err) {
      if (err?.status === 404) {
        markJobInterrupted(job.id)
      }
    } finally {
      verifyingJobs.delete(job.id)
    }
  }
}

watch(
  profileJobs,
  (current, before) => {
    const previouslyRunning = new Set((before || []).filter((j) => j.state === 'running').map((j) => j.id))
    for (const job of current) {
      if (!job?.id || job.operation === 'preview' || job.state === 'running') continue
      if (!previouslyRunning.has(job.id) || notifiedFinished.has(job.id)) continue
      notifiedFinished.add(job.id)
      const headline = formatJobHeadline(job, t)
      const opLabel = t('operation.' + job.operation)
      if (job.state === 'failed') {
        pushToast(`${opLabel}: ${headline || t('maintenance.jobFailed')}`, 'error')
      } else if (SIMULATION_OPS.has(job.operation)) {
        const key = isDryRunJob(job) ? 'maintenance.simulationFinished' : 'maintenance.executionFinished'
        pushToast(`${t(key, { operation: opLabel })}${headline ? ' — ' + headline : ''}`, 'ok')
      } else {
        pushToast(`${opLabel}: ${headline || t('outcome.completed')}`, 'ok')
      }
    }
  },
  { flush: 'post' }
)

watch(
  [() => stream.jobs, () => stream.daemonInstance, () => stream.streamState],
  () => {
    reconcileSubmittedJobs()
  },
  { flush: 'post' }
)

onUnmounted(() => pollAbort?.abort())

function onJobCreated(job) {
  if (job?.id) {
    const tracked = { ...job, daemonInstance: stream.daemonInstance || '' }
    submittedJobs.value = [...submittedJobs.value.filter((j) => j.id !== job.id), tracked]
  }
}
</script>

<template>
  <div class="k-workspace-scroll">
    <div class="k-settings-layout">
      <div class="k-stack">
        <div v-if="actionReason" class="k-alert k-alert--info" role="status">{{ actionReason }}</div>
        <QuickActionsCard :profile="profile" :blocked-reason="actionReason"
          @working="startingAction = $event" @job-created="onJobCreated" />
        <IgnoreRulesCard :profile="profile" :disabled="Boolean(actionReason) || startingAction" />
      </div>
      <aside class="k-stack">
        <VaultSpaceCard :profile="profile" />
        <JobsActivityCard :jobs="profileJobs" />
      </aside>
    </div>
  </div>
</template>
