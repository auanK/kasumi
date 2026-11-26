<script setup>
import { onUnmounted, ref, watch } from 'vue'
import BaseModal from '../../components/BaseModal.vue'
import PasswordField from '../../components/PasswordField.vue'
import { unlockProfile } from '../../api/daemon.js'
import { pushToast } from '../../composables/useToasts.js'
import { t } from '../../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  profile: { type: Object, default: null },
})

const emit = defineEmits(['close', 'unlocked'])
const mode = ref('password')
const password = ref('')
const saltPassword = ref('')
const masterKey = ref('')
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
    if (open) error.value = ''
  }
)

async function onSubmit() {
  if (!props.profile) return
  busy.value = true
  error.value = ''
  try {
    const creds =
      mode.value === 'master_key'
        ? { master_key: masterKey.value.trim() }
        : { password: password.value, salt_password: saltPassword.value }
    await unlockProfile(props.profile.name, creds)
    clearSecrets()
    pushToast(`Unlocked "${props.profile.name}"`, 'ok')
    emit('unlocked')
    emit('close')
  } catch (err) {
    error.value = err?.message || 'Failed to unlock profile'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <BaseModal
    :open="open"
    :title="`${t('profile.unlock')} (${profile?.name || ''})`"
    @close="emit('close')"
  >
    <form id="unlock-profile-form" class="k-stack" @submit.prevent="onSubmit">
      <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>

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
    </form>

    <template #footer>
      <button type="button" class="k-btn" :disabled="busy" @click="emit('close')">
        {{ t('common.cancel') }}
      </button>
      <button
        type="submit"
        form="unlock-profile-form"
        class="k-btn k-btn--primary"
        :disabled="busy"
      >
        {{ busy ? t('common.loading') : t('profile.unlock') }}
      </button>
    </template>
  </BaseModal>
</template>
