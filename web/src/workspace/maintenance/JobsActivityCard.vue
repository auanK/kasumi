<script setup>
import { computed, onUnmounted, ref } from 'vue'
import StatusBadge from '../../components/StatusBadge.vue'
import BaseModal from '../../components/BaseModal.vue'
import { fetchJob } from '../../api/maintenance.js'
import { formatDurationMs, formatTimestamp } from '../../utils/format.js'
import { t } from '../../i18n/index.js'
import {
  SIMULATION_OPS,
  extractJobMetrics,
  extractJobProgressMeter,
  formatJobHeadline,
  formatJobStage,
  isDryRunJob,
  jobData,
  resolveJobDurationMs,
} from '../../utils/jobFormat.js'

const props = defineProps({ jobs: { type: Array, default: () => [] } })

const selected = ref(null)
const result = ref(null)
const error = ref('')
let inspectRequest = null

const facts = computed(() => extractJobMetrics(result.value, t))
const modalDryRun = computed(() =>
  result.value && SIMULATION_OPS.has(result.value.operation) ? isDryRunJob(result.value) : null
)
const resultTimestamp = computed(() => jobTimestamp(result.value))
const resultDuration = computed(() => resolveJobDurationMs(result.value))

function jobTimestamp(job) {
  return job?.finished_at || job?.started_at || 0
}

const jobRows = computed(() =>
  props.jobs.map((job) => ({
    job,
    hasMode: SIMULATION_OPS.has(job?.operation),
    dryRun: isDryRunJob(job),
    timestamp: jobTimestamp(job),
    duration: resolveJobDurationMs(job),
    progress: extractJobProgressMeter(job, t),
    stage: formatJobStage(job, t),
    hasData: Boolean(jobData(job)),
    headline: formatJobHeadline(job, t),
    inlineFacts: extractJobMetrics(job, t).slice(0, 3),
  }))
)

function closeModal() {
  inspectRequest?.abort()
  inspectRequest = null
  selected.value = null
}

onUnmounted(() => {
  inspectRequest?.abort()
  inspectRequest = null
})

async function inspect(job) {
  inspectRequest?.abort()
  const controller = new AbortController()
  inspectRequest = controller
  selected.value = job
  result.value = null
  error.value = ''
  try {
    const response = await fetchJob(job.id, controller.signal)
    if (!controller.signal.aborted && selected.value?.id === job.id) {
      result.value = response
    }
  } catch (err) {
    if (!controller.signal.aborted && selected.value?.id === job.id) {
      error.value = err?.message || t('overview.actionFailed')
    }
  }
}
</script>

<template>
  <section class="k-card">
    <header class="k-card-header"><strong>{{ t('maintenance.jobsTitle') }}</strong></header>
    <p v-if="jobRows.length === 0" class="k-card-body k-muted k-event-empty">{{ t('common.none') }}</p>
    <ul v-else class="k-jobs-list">
      <li v-for="row in jobRows" :key="row.job.id" class="k-job-item">
        <button type="button" class="k-list-row k-job-btn" @click="inspect(row.job)">
          <div class="k-row k-row--between k-row--wrap k-w-full">
            <span class="k-row k-row--wrap">
              <strong>{{ t('operation.' + row.job.operation) }}</strong>
              <span
                v-if="row.hasMode"
                class="k-mode-pill"
                :class="row.dryRun ? 'k-mode-pill--sim' : 'k-mode-pill--real'"
              >
                {{ t(row.dryRun ? 'maintenance.simulationBadge' : 'maintenance.realExecutionBadge') }}
              </span>
            </span>
            <StatusBadge :state="row.job.state" />
          </div>

          <div v-if="row.timestamp || row.duration != null" class="k-row k-row--wrap k-text-xs k-faint k-mono">
            <span v-if="row.timestamp">{{ formatTimestamp(row.timestamp) }}</span>
            <span v-if="row.duration != null">· {{ formatDurationMs(row.duration) }}</span>
          </div>

          <div v-if="row.job.state === 'running'" class="k-stack--sm k-w-full">
            <div v-if="row.stage || row.progress.percent !== null" class="k-row k-row--between k-text-xs k-muted">
              <span>{{ row.stage }}</span>
              <span v-if="row.progress.percent !== null" class="k-mono">{{ row.progress.percent }}%</span>
            </div>
            <progress
              class="k-progress"
              :aria-label="t('outcome.running')"
              :max="row.progress.total ?? undefined"
              :value="row.progress.total && row.progress.current != null ? Math.min(row.progress.current, row.progress.total) : undefined"
            />
          </div>

          <div v-else-if="row.hasData" class="k-stack--sm k-w-full k-job-inline-summary">
            <span
              v-if="row.headline"
              class="k-text-xs"
              :class="row.job.state === 'failed' ? 'k-text-error' : 'k-muted'"
            >
              {{ row.headline }}
            </span>
            <div v-if="row.inlineFacts.length" class="k-job-kpis">
              <span v-for="[key, val] in row.inlineFacts" :key="key" class="k-job-kpi k-text-xs">
                <span class="k-faint">{{ t(key) }}:</span>
                <strong class="k-mono">{{ val }}</strong>
              </span>
            </div>
          </div>
        </button>
      </li>
    </ul>

    <BaseModal :open="Boolean(selected)" :title="t('maintenance.jobDetails')" @close="closeModal">
      <p v-if="error" class="k-alert k-alert--error" role="alert">{{ error }}</p>
      <p v-else-if="!result" class="k-muted" role="status">{{ t('common.loading') }}</p>
      <template v-else>
        <div
          v-if="modalDryRun !== null"
          class="k-alert"
          :class="modalDryRun ? 'k-alert--warn' : 'k-alert--ok'"
          role="status"
        >
          {{ t(modalDryRun ? 'maintenance.simulationNotice' : 'maintenance.realExecutionNotice') }}
        </div>
        <div class="k-row k-row--wrap">
          <strong>{{ t('operation.' + result.operation) }}</strong>
          <StatusBadge :state="result.state" />
          <span
            v-if="modalDryRun !== null"
            class="k-mode-pill"
            :class="modalDryRun ? 'k-mode-pill--sim' : 'k-mode-pill--real'"
          >
            {{ t(modalDryRun ? 'maintenance.simulationBadge' : 'maintenance.realExecutionBadge') }}
          </span>
        </div>
        <p v-if="result.result?.error" class="k-alert k-alert--error">{{ result.result.error }}</p>
        <p v-if="result.result?.warning" class="k-alert k-alert--warn">{{ result.result.warning }}</p>
        <dl v-if="facts.length || resultTimestamp || resultDuration != null" class="k-facts">
          <template v-if="resultTimestamp">
            <dt>{{ t('overview.when') }}</dt><dd class="k-mono">{{ formatTimestamp(resultTimestamp) }}</dd>
          </template>
          <template v-if="resultDuration != null">
            <dt>{{ t('overview.duration') }}</dt><dd class="k-mono">{{ formatDurationMs(resultDuration) }}</dd>
          </template>
          <template v-for="[key, value] in facts" :key="key">
            <dt>{{ t(key) }}</dt><dd class="k-mono">{{ value }}</dd>
          </template>
        </dl>
        <details class="k-disclosure">
          <summary>{{ t('maintenance.rawResponse') }}</summary>
          <pre class="k-code-block k-scroll-md">{{ JSON.stringify(result, null, 2) }}</pre>
        </details>
      </template>
    </BaseModal>
  </section>
</template>

<style scoped>
.k-jobs-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 8px;
  margin: 0;
  list-style: none;
}
.k-job-item + .k-job-item {
  border-top: 1px solid var(--k-border-subtle);
  padding-top: 6px;
}
.k-job-btn {
  flex-direction: column;
  align-items: stretch;
  gap: 6px;
  padding: 8px;
}
.k-job-inline-summary {
  text-align: left;
}
.k-job-kpis {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 10px;
}
.k-job-kpi {
  display: inline-flex;
  align-items: baseline;
  gap: 4px;
}
.k-text-error {
  color: var(--k-error);
}
</style>
