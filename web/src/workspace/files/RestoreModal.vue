<script setup>
import { onUnmounted, ref, watch } from 'vue'
import BaseModal from '../../components/BaseModal.vue'
import { restoreRemote } from '../../api/remote.js'
import { useProfileActivity } from '../../composables/useProfileActivity.js'
import { pushToast } from '../../composables/useToasts.js'
import { formatBytes, shortHash } from '../../utils/format.js'
import { t } from '../../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  profile: { type: String, required: true },
  commit: { type: String, default: '' },
  initialPrefix: { type: String, default: '' },
})

const emit = defineEmits(['close'])
const dst = ref('')
const prefix = ref('')
const previewResult = ref(null)
const busy = ref(false)
const error = ref('')
const { blockedReason } = useProfileActivity(() => props.profile)
let previewRequestSeq = 0
let previewAbort = null

function invalidatePreview() {
  previewAbort?.abort()
  previewAbort = null
  previewRequestSeq++
  busy.value = false
  previewResult.value = null
  error.value = ''
}

watch(
  () => props.open,
  (open) => {
    invalidatePreview()
    if (open) {
      prefix.value = props.initialPrefix || ''
    }
  }
)

watch([() => props.profile, () => props.commit, prefix, dst], () => {
  invalidatePreview()
})

onUnmounted(() => previewAbort?.abort())

async function runRestore(dryRun) {
  if (busy.value || blockedReason.value || !dst.value.trim()) return
  previewAbort?.abort()
  const controller = new AbortController()
  previewAbort = controller
  const requestId = ++previewRequestSeq
  busy.value = true
  error.value = ''
  try {
    const res = await restoreRemote(props.profile, {
      dst: dst.value.trim(),
      prefix: prefix.value.trim() || undefined,
      commit: props.commit || undefined,
      dryRun,
      signal: controller.signal,
    })
    if (controller.signal.aborted || requestId !== previewRequestSeq) return
    previewResult.value = res
    if (!dryRun) {
      pushToast(`Restored to ${dst.value.trim()}`, 'ok')
      emit('close')
    }
  } catch (err) {
    if (!controller.signal.aborted && requestId === previewRequestSeq) {
      error.value = err?.message || 'Restore failed'
    }
  } finally {
    if (requestId === previewRequestSeq) {
      busy.value = false
      previewAbort = null
    }
  }
}
</script>

<template>
  <BaseModal :open="open" :title="t('files.restoreTitle')" @close="emit('close')">
    <div class="k-stack">
      <p class="k-muted k-text-sm k-restore-hint">{{ t('files.restoreHint') }}</p>
      <div v-if="commit" class="k-text-sm">{{ t('files.snapshot') }} · <span class="k-mono">{{ shortHash(commit, 10) }}</span></div>
      <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>
      <div v-if="blockedReason" class="k-alert k-alert--info" role="status">{{ blockedReason }}</div>

      <div class="k-field">
        <label class="k-field-label">{{ t('files.restoreDst') }}</label>
        <input
          v-model="dst"
          class="k-input k-mono"
          placeholder="/tmp/restored-files"
          :disabled="busy"
        />
      </div>

      <div class="k-field">
        <label class="k-field-label">{{ t('files.restorePrefix') }}</label>
        <input v-model="prefix" class="k-input k-mono" placeholder="/" :disabled="busy" />
      </div>

      <div v-if="previewResult" class="k-alert k-alert--info k-mono">
        {{ previewResult.files_restored ?? previewResult.file_count ?? 0 }} file(s) ·
        {{ formatBytes(previewResult.bytes_restored ?? previewResult.total_bytes) }}
      </div>
    </div>

    <template #footer>
      <button type="button" class="k-btn" :disabled="busy" @click="emit('close')">
        {{ t('common.cancel') }}
      </button>
      <button type="button" class="k-btn" :disabled="busy || Boolean(blockedReason) || !dst.trim()" @click="runRestore(true)">
        {{ t('common.preview') }}
      </button>
      <button
        type="button"
        class="k-btn k-btn--primary"
        :disabled="busy || Boolean(blockedReason) || !dst.trim()"
        @click="runRestore(false)"
      >
        {{ t('files.restoreNow') }}
      </button>
    </template>
  </BaseModal>
</template>

<style scoped>
.k-restore-hint {
  margin: 0;
}
</style>
