<script setup>
import { onUnmounted, ref, watch } from 'vue'
import BaseModal from '../../components/BaseModal.vue'
import PasswordField from '../../components/PasswordField.vue'
import { updateProfileKey } from '../../api/profiles.js'
import { pushToast } from '../../composables/useToasts.js'
import { t } from '../../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  profile: { type: Object, default: null },
  blockedReason: { type: String, default: '' },
})

const emit = defineEmits(['close', 'saved'])
const mode = ref('password')
const password = ref('')
const saltPassword = ref('')
const masterKey = ref('')
const replace = ref(false)
const busy = ref(false)
const error = ref('')

function clearSecrets() {
  password.value = ''
  saltPassword.value = ''
  masterKey.value = ''
}

onUnmounted(clearSecrets)

watch(
  () => props.open,
  (open) => {
    clearSecrets()
    if (open) {
      replace.value = false
      error.value = ''
    }
  }
)

async function onSubmit() {
  if (!props.profile || busy.value || props.blockedReason) return
  busy.value = true
  error.value = ''
  try {
    const payload =
      mode.value === 'master_key'
        ? { master_key: masterKey.value.trim(), replace: replace.value }
        : { password: password.value, salt_password: saltPassword.value, replace: replace.value }
    await updateProfileKey(props.profile.name, payload)
    clearSecrets()
    pushToast(`Key saved for "${props.profile.name}"`, 'ok')
    emit('saved')
    emit('close')
  } catch (err) {
    error.value = err?.message || 'Failed to save key'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <BaseModal :open="open" :title="`Update key · ${profile?.name || ''}`" @close="emit('close')">
    <form id="settings-key-form" class="k-stack" @submit.prevent="onSubmit">
      <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>
      <div v-if="blockedReason" class="k-alert k-alert--info" role="status">{{ blockedReason }}</div>

      <div class="k-row k-row--lg">
        <label class="k-row">
          <input v-model="mode" type="radio" value="password" />
          <span>{{ t('wizard.credPassword') }}</span>
        </label>
        <label class="k-row">
          <input v-model="mode" type="radio" value="master_key" />
          <span>{{ t('wizard.credMasterKey') }}</span>
        </label>
      </div>

      <template v-if="mode === 'password'">
        <PasswordField v-model="password" label="Vault Password" required :disabled="busy" />
        <PasswordField v-model="saltPassword" label="Salt Password" required :disabled="busy" />
      </template>
      <PasswordField
        v-else
        v-model="masterKey"
        :label="t('wizard.credMasterKey')"
        autocomplete="off"
        required
        :disabled="busy"
      />

      <label class="k-row k-text-sm">
        <input v-model="replace" type="checkbox" />
        <span>Replace existing different key</span>
      </label>
    </form>

    <template #footer>
      <button type="button" class="k-btn" :disabled="busy" @click="emit('close')">
        {{ t('common.cancel') }}
      </button>
      <button type="submit" form="settings-key-form" class="k-btn k-btn--primary" :disabled="busy || Boolean(blockedReason)">
        {{ busy ? t('common.loading') : t('common.save') }}
      </button>
    </template>
  </BaseModal>
</template>
