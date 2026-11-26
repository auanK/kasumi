<script setup>
import { ref, watch } from 'vue'
import BaseModal from '../../components/BaseModal.vue'
import { updateProfileStorage } from '../../api/profiles.js'
import { pushToast } from '../../composables/useToasts.js'
import { t } from '../../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  profile: { type: Object, default: null },
  blockedReason: { type: String, default: '' },
})

const emit = defineEmits(['close', 'saved'])
const storage = ref('vault')
const busy = ref(false)
const error = ref('')

watch(
  () => props.open,
  (open) => {
    if (open && props.profile) {
      storage.value = props.profile.key_storage || 'vault'
      error.value = ''
    }
  }
)

async function onSubmit() {
  if (!props.profile || busy.value || props.blockedReason) return
  busy.value = true
  error.value = ''
  try {
    await updateProfileStorage(props.profile.name, storage.value)
    pushToast(`Key storage updated to "${storage.value}"`, 'ok')
    emit('saved')
    emit('close')
  } catch (err) {
    error.value = err?.message || 'Failed to change key storage'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <BaseModal
    :open="open"
    :title="`${t('settings.securityTitle')} · ${profile?.name || ''}`"
    @close="emit('close')"
  >
    <form id="settings-storage-form" class="k-stack" @submit.prevent="onSubmit">
      <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>
      <div v-if="blockedReason" class="k-alert k-alert--info" role="status">{{ blockedReason }}</div>
      <div class="k-alert k-alert--warn k-text-sm">
        Switching away from OS Keyring or Private file removes the previously saved local key. Run
        Update key right after if switching to a persistent mode.
      </div>
      <div class="k-field">
        <label class="k-field-label">{{ t('wizard.storageTitle') }}</label>
        <select v-model="storage" class="k-select" :disabled="busy">
          <option value="vault">{{ t('wizard.storageVault') }}</option>
          <option value="file">{{ t('wizard.storageFile') }}</option>
          <option value="memory">{{ t('wizard.storageMemory') }}</option>
        </select>
      </div>
    </form>

    <template #footer>
      <button type="button" class="k-btn" :disabled="busy" @click="emit('close')">
        {{ t('common.cancel') }}
      </button>
      <button
        type="submit"
        form="settings-storage-form"
        class="k-btn k-btn--primary"
        :disabled="busy || Boolean(blockedReason)"
      >
        {{ busy ? t('common.loading') : t('common.save') }}
      </button>
    </template>
  </BaseModal>
</template>
