<script setup>
import { computed } from 'vue'
import { t } from '../i18n/index.js'
import { formatBytes } from '../utils/format.js'

const props = defineProps({ live: { type: Object, required: true } })
const phases = ['observing', 'calculating', 'applying', 'publishing', 'finalizing']
const phase = computed(() => props.live.sync_phase || props.live.active_stage)
const phaseIndex = computed(() => phases.indexOf(phase.value))
const itemsTotal = computed(() => props.live.sync_total_items)
const itemsDone = computed(() => props.live.sync_applied_items)
const hasItemProgress = computed(() => itemsTotal.value > 0 && itemsDone.value != null)
const progress = computed(() => {
  if (hasItemProgress.value) return [itemsDone.value, itemsTotal.value]
  if (props.live.active_total_bytes > 0) return [props.live.active_bytes || 0, props.live.active_total_bytes]
  if (props.live.active_total_objects > 0) return [props.live.active_objects || 0, props.live.active_total_objects]
  return null
})
const percent = computed(() => progress.value && Math.min(100, Math.floor(100 * progress.value[0] / progress.value[1])))
const activity = computed(() => {
  const stage = props.live.active_stage
  if (!stage || stage === phase.value) return ''
  const key = 'stage.' + stage
  const label = t(key)
  return label === key ? '' : label
})
const rate = computed(() => props.live.active_bytes > 0 && Number.isFinite(props.live.active_bytes_per_second)
  ? formatBytes(Math.round(props.live.active_bytes_per_second)) + '/s' : '')
</script>

<template>
  <section class="k-sync-progress" :aria-label="t('status.syncing')">
    <ol class="k-sync-steps">
      <li v-for="(step, index) in phases" :key="step"
        :class="{ 'is-current': phaseIndex === index, 'is-done': phaseIndex > index }"
        :aria-current="phaseIndex === index ? 'step' : undefined">
        <span class="k-sync-number" aria-hidden="true">{{ phaseIndex > index ? '✓' : index + 1 }}</span>
        {{ t('sync.phase.' + step) }}
      </li>
    </ol>
    <div class="k-sync-meter">
      <span class="k-sync-activity">{{ activity || t(phaseIndex < 0 ? 'status.syncing' : 'sync.phase.' + phase) }}</span>
      <progress class="k-progress" :aria-label="t('status.syncing')"
        :max="progress?.[1]" :value="progress ? Math.min(progress[0], progress[1]) : undefined" />
      <strong v-if="percent !== null" class="k-sync-percent">{{ percent }}%</strong>
    </div>
    <div v-if="live.active_item_path || live.active_total_objects || live.active_bytes || hasItemProgress"
      class="k-sync-metrics">
      <span v-if="live.active_item_path" class="k-sync-file" :title="live.active_item_path">
        {{ live.active_item_path }}
        <small v-if="live.active_item_total_bytes">
          {{ formatBytes(live.active_item_bytes) }} / {{ formatBytes(live.active_item_total_bytes) }}
        </small>
      </span>
      <span v-if="hasItemProgress">{{ t('sync.changes', { done: itemsDone, total: itemsTotal }) }}</span>
      <span v-else-if="live.active_total_objects">
        {{ t('sync.objects', { done: live.active_objects || 0, total: live.active_total_objects }) }}
      </span>
      <span v-else-if="live.active_objects">{{ t('sync.count', { count: live.active_objects }) }}</span>
      <span v-if="live.active_total_bytes || live.active_bytes">
        {{ formatBytes(live.active_bytes || 0) }}
        <template v-if="live.active_total_bytes"> / {{ formatBytes(live.active_total_bytes) }}</template>
      </span>
      <strong v-if="rate" class="k-sync-rate">{{ rate }}</strong>
    </div>
  </section>
</template>
