<script setup>
import { computed } from 'vue'
import { t } from '../i18n/index.js'
import {
  SIMULATION_OPS,
  extractJobProgressMeter,
  formatJobStage,
  getJobSteps,
  isDryRunJob,
} from '../utils/jobFormat.js'

const props = defineProps({ job: { type: Object, required: true } })

const steps = computed(() => getJobSteps(props.job?.operation))
const currentStage = computed(() => props.job?.progress?.stage || '')
const stepIndex = computed(() => steps.value.indexOf(currentStage.value))
const showModeBadge = computed(() => SIMULATION_OPS.has(props.job?.operation))
const dryRun = computed(() => isDryRunJob(props.job))
const meter = computed(() => extractJobProgressMeter(props.job, t))
const stageLabel = computed(() => formatJobStage(props.job, t) || t('operation.' + props.job?.operation))
const itemPath = computed(() => props.job?.progress?.item_path || '')
const filesReassembled = computed(() => props.job?.progress?.files_reassembled)
</script>

<template>
  <section
    class="k-sync-progress"
    :class="{ 'k-job-progress--sim': showModeBadge && dryRun }"
    :aria-label="t('operation.' + job.operation)"
  >
    <div class="k-row k-row--between k-row--wrap">
      <div class="k-row k-row--wrap">
        <strong>{{ t('operation.' + job.operation) }}</strong>
        <span
          v-if="showModeBadge"
          class="k-mode-pill"
          :class="dryRun ? 'k-mode-pill--sim' : 'k-mode-pill--real'"
        >
          {{ t(dryRun ? 'maintenance.simulationBadge' : 'maintenance.realExecutionBadge') }}
        </span>
      </div>
      <span v-if="meter.percent !== null" class="k-sync-percent">{{ meter.percent }}%</span>
    </div>

    <ol v-if="steps.length" class="k-sync-steps" :class="{ 'k-sync-steps--4': steps.length === 4 }">
      <li
        v-for="(step, index) in steps"
        :key="step"
        :class="{ 'is-current': stepIndex === index, 'is-done': stepIndex > index }"
        :aria-current="stepIndex === index ? 'step' : undefined"
      >
        <span class="k-sync-number" aria-hidden="true">{{ stepIndex > index ? '✓' : index + 1 }}</span>
        {{ t('stage.' + step) }}
      </li>
    </ol>

    <div class="k-sync-meter">
      <span class="k-sync-activity">{{ stageLabel }}</span>
      <progress
        class="k-progress"
        :aria-label="t('operation.' + job.operation)"
        :max="meter.total ?? undefined"
        :value="meter.total && meter.current != null ? Math.min(meter.current, meter.total) : undefined"
      />
    </div>

    <div v-if="itemPath || meter.countLabel || meter.bytesLabel || filesReassembled" class="k-sync-metrics">
      <span v-if="itemPath" class="k-sync-file" :title="itemPath">{{ itemPath }}</span>
      <span v-if="meter.countLabel">{{ meter.countLabel }}</span>
      <span v-if="meter.bytesLabel">{{ meter.bytesLabel }}</span>
      <span v-if="filesReassembled">{{ t('maintenance.filesReassembledCount', { count: filesReassembled }) }}</span>
    </div>
  </section>
</template>
