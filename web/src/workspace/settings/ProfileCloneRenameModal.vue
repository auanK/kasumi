<script setup>
import { ref, watch } from 'vue'
import BaseModal from '../../components/BaseModal.vue'
import { cloneProfile, renameProfile } from '../../api/profiles.js'
import { pushToast } from '../../composables/useToasts.js'
import { t } from '../../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  mode: { type: String, default: 'clone' }, // clone | rename
  profile: { type: Object, default: null },
  blockedReason: { type: String, default: '' },
})

const emit = defineEmits(['close', 'cloned', 'renamed'])
const targetName = ref('')
const busy = ref(false)
const error = ref('')

watch(
  () => props.open,
  (open) => {
    if (open && props.profile) {
      targetName.value = props.mode === 'clone' ? `${props.profile.name}-copy` : props.profile.name
      error.value = ''
    }
  }
)

async function onSubmit() {
  if (!props.profile || busy.value || props.blockedReason) return
  const dest = targetName.value.trim()
  if (!dest) return
  busy.value = true
  error.value = ''
  try {
    if (props.mode === 'clone') {
      await cloneProfile(props.profile.name, dest)
      pushToast(`Cloned "${props.profile.name}" → "${dest}" (paused)`, 'ok')
      emit('cloned', dest)
    } else {
      await renameProfile(props.profile.name, dest)
      pushToast(`Renamed "${props.profile.name}" → "${dest}"`, 'ok')
      emit('renamed', dest)
    }
    emit('close')
  } catch (err) {
    error.value = err?.message || 'Operation failed'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <BaseModal
    :open="open"
    :title="mode === 'clone' ? t('settings.clone') : t('settings.rename')"
    @close="emit('close')"
  >
    <form id="settings-clone-rename-form" class="k-stack" @submit.prevent="onSubmit">
      <div v-if="mode === 'clone'" class="k-alert k-alert--info k-text-sm">
        Cloned profiles start paused so you can review paths before syncing.
      </div>
      <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>
      <div v-if="blockedReason" class="k-alert k-alert--info" role="status">{{ blockedReason }}</div>

      <div class="k-field">
        <label class="k-field-label">New profile name</label>
        <input v-model="targetName" class="k-input" required :disabled="busy" />
      </div>
    </form>

    <template #footer>
      <button type="button" class="k-btn" :disabled="busy" @click="emit('close')">
        {{ t('common.cancel') }}
      </button>
      <button
        type="submit"
        form="settings-clone-rename-form"
        class="k-btn k-btn--primary"
        :disabled="busy || Boolean(blockedReason) || !targetName.trim()"
      >
        {{ busy ? t('common.loading') : t('common.confirm') }}
      </button>
    </template>
  </BaseModal>
</template>
