<script setup>
import { onUnmounted, ref, watch } from 'vue'
import StatusBadge from '../../components/StatusBadge.vue'
import { cachedRemoteReading, fetchRemoteHealth, fetchRemoteSummary } from '../../api/remote.js'
import { formatBytes, formatTimestamp, friendlyBusyError } from '../../utils/format.js'
import { t } from '../../i18n/index.js'

const props = defineProps({
  profile: { type: String, required: true },
})
const emit = defineEmits(['loading'])

function cachedForProfile(profile) {
  const space = cachedRemoteReading(profile, 'summary')
  const health = cachedRemoteReading(profile, 'health')
  return { space: space?.value, spaceAt: space?.readAt, health: health?.value, healthAt: health?.readAt }
}

const reading = ref(cachedForProfile(props.profile))
const loading = ref('')
const error = ref('')
let request

watch(() => props.profile, (profile) => {
  request?.abort()
  loading.value = ''
  error.value = ''
  emit('loading', false)
  reading.value = cachedForProfile(profile)
})

async function load(kind) {
  if (!props.profile || loading.value) return
  const profile = props.profile
  request?.abort()
  const controller = new AbortController()
  request = controller
  const { signal } = controller
  loading.value = kind
  emit('loading', true)
  error.value = ''
  try {
    const fetchReading = kind === 'space' ? fetchRemoteSummary : fetchRemoteHealth
    const result = await fetchReading(profile, signal, { refresh: true })
    if (signal.aborted) return
    reading.value = { ...reading.value, [kind]: result, [kind + 'At']: Date.now() }
  } catch (err) {
    if (!signal.aborted) error.value = err.message
  } finally {
    if (!signal.aborted) {
      loading.value = ''
      emit('loading', false)
    }
  }
}
onUnmounted(() => request?.abort())
</script>

<template>
  <section class="k-card">
    <header class="k-card-header">
      <strong>{{ t('maintenance.spaceTitle') }}</strong>
      <div class="k-row">
        <StatusBadge v-if="reading.health?.state" :state="reading.health.state" />
      </div>
    </header>

    <div class="k-card-body k-stack">
      <div class="k-row k-row--wrap">
        <button type="button" class="k-btn k-btn--compact" :disabled="Boolean(loading)" @click="load('space')">
          {{ t(loading === 'space' ? 'common.loading' : 'maintenance.measureSpace') }}
        </button>
        <button type="button" class="k-btn k-btn--compact" :disabled="Boolean(loading)" @click="load('health')">
          {{ t(loading === 'health' ? 'common.loading' : 'maintenance.checkHealth') }}
        </button>
      </div>
      <div v-if="error" class="k-alert k-alert--error" role="alert">{{ friendlyBusyError(null, t, error) }}</div>

      <div v-if="reading.space" class="k-grid-3">
        <div class="k-stack--sm">
          <span class="k-field-label">{{ t('maintenance.spaceTree') }}</span>
          <strong class="k-mono">
            {{ formatBytes(reading.space.space_usage?.current_content_bytes) }}
          </strong>
        </div>
        <div class="k-stack--sm">
          <span class="k-field-label">{{ t('maintenance.spaceHistory') }}</span>
          <strong class="k-mono">
            {{ formatBytes(reading.space.space_usage?.retained_content_bytes) }}
          </strong>
        </div>
        <div class="k-stack--sm">
          <span class="k-field-label">{{ t('maintenance.spaceOrphans') }}</span>
          <strong class="k-mono">
            {{ formatBytes(reading.space.space_usage?.orphan_content_bytes) }}
          </strong>
        </div>
      </div>
      <span v-if="reading.spaceAt" class="k-muted k-text-xs">{{ t('maintenance.spaceReadAt', { time: formatTimestamp(reading.spaceAt) }) }}</span>
      <span v-if="reading.healthAt" class="k-muted k-text-xs">{{ t('maintenance.healthReadAt', { time: formatTimestamp(reading.healthAt) }) }}</span>
    </div>
  </section>
</template>
