<script setup>
import { computed, ref, watch } from 'vue'
import BaseModal from '../components/BaseModal.vue'
import { fetchJob, startPreviewJob } from '../api/maintenance.js'
import { t } from '../i18n/index.js'
import { formatBytes, friendlyBusyError, translateWithFallback } from '../utils/format.js'
import { extractJobProgressMeter, formatJobStage } from '../utils/jobFormat.js'

const props = defineProps({ profile: { type: String, default: '' } })
const emit = defineEmits(['close'])
const job = ref(null)
const error = ref('')
const attempt = ref(0)
const result = computed(() => job.value?.state === 'completed' ? job.value.result : null)
const progressLabel = computed(() => formatJobStage(job.value, t) || t('overview.previewLoading'))
const meter = computed(() => extractJobProgressMeter(job.value, t))

function label(action) {
  return translateWithFallback(t, 'plan.' + action, action)
}

function friendlyError(err, rawMessage = '') {
  return friendlyBusyError(err, t, rawMessage, 'overview.actionFailed')
}

watch([() => props.profile, attempt], async ([profile], _, onCleanup) => {
  job.value = null
  error.value = ''
  if (!profile) return

  const controller = new AbortController()
  let timer
  onCleanup(() => {
    clearTimeout(timer)
    controller.abort()
  })
  const { signal } = controller

  function showError(err, rawMessage = '') {
    if (!signal.aborted) error.value = friendlyError(err, rawMessage)
  }

  function receive(snapshot) {
    if (signal.aborted) return
    job.value = snapshot
    if (['failed', 'cancelled'].includes(snapshot.state)) {
      showError(null, snapshot.result?.error)
    } else if (snapshot.state !== 'completed') {
      timer = setTimeout(async () => {
        try {
          receive(await fetchJob(snapshot.id, signal))
        } catch (err) {
          showError(err)
        }
      }, 500)
    }
  }

  try {
    receive(await startPreviewJob(profile, signal))
  } catch (err) {
    showError(err)
  }
}, { immediate: true })
</script>

<template>
  <BaseModal :open="Boolean(profile)" :title="t('overview.previewTitle', { name: profile })" wide @close="emit('close')">
    <div v-if="error" class="k-alert k-alert--error k-row k-row--between k-row--wrap" role="alert">
      <span>{{ error }}</span>
      <button type="button" class="k-btn k-btn--compact" @click="attempt++">{{ t('common.retry') }}</button>
    </div>
    <div v-else-if="!result" class="k-stack--sm" role="status">
      <div class="k-row k-row--between k-muted">
        <span>{{ progressLabel }}</span>
        <span v-if="meter.countLabel" class="k-mono k-text-xs">{{ meter.countLabel }}</span>
      </div>
      <progress class="k-progress" :max="meter.total ?? undefined"
        :value="meter.total && meter.current != null ? Math.min(meter.current, meter.total) : undefined" />
    </div>
    <div v-else class="k-stack">
      <div class="k-preview-totals">
        <div><span>{{ t('overview.changes') }}</span><strong>{{ result.items.length }}</strong></div>
        <div><span>{{ t('overview.sendBytes') }}</span><strong>{{ formatBytes(result.upload_bytes) }}</strong></div>
        <div><span>{{ t('overview.receiveBytes') }}</span><strong>{{ formatBytes(result.download_bytes) }}</strong></div>
      </div>
      <div v-if="result.has_conflicts" class="k-alert k-alert--warn">{{ t('overview.previewConflicts') }}</div>
      <div v-if="result.warning" class="k-alert k-alert--warn">{{ result.warning }}</div>
      <p v-if="!result.items.length" class="k-muted">{{ t('overview.previewEmpty') }}</p>
      <div v-else class="k-table-scroll">
        <table class="k-data-table">
          <thead><tr><th scope="col">{{ t('overview.action') }}</th><th scope="col">{{ t('overview.path') }}</th><th scope="col">{{ t('overview.size') }}</th></tr></thead>
          <tbody><tr v-for="(item, index) in result.items" :key="index">
            <td>{{ label(item.action) }}</td>
            <td class="k-path">{{ item.path }}<span v-if="item.alternative_path" class="k-fact-note">→ {{ item.alternative_path }}</span></td>
            <td>{{ item.size ? formatBytes(item.size) : '—' }}</td>
          </tr></tbody>
        </table>
      </div>
      <details v-if="result.pending_paths?.length" class="k-disclosure">
        <summary>{{ t('overview.previewPending', { count: result.pending_paths.length }) }}</summary>
        <ul class="k-disclosure-body"><li v-for="path in result.pending_paths" :key="path" class="k-path">{{ path }}</li></ul>
      </details>
    </div>
    <template #footer><button type="button" class="k-btn" @click="emit('close')">{{ t('common.close') }}</button></template>
  </BaseModal>
</template>
