<script setup>
import { onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import AuthShell from './AuthShell.vue'
import PasswordField from '../components/PasswordField.vue'
import { useAuth } from '../composables/useAuth.js'
import { pushToast } from '../composables/useToasts.js'
import { t } from '../i18n/index.js'

const router = useRouter()
const { setupInitialPassword } = useAuth()

const bootstrapToken = ref('')
const username = ref('')
const password = ref('')
const confirmPassword = ref('')
const busy = ref(false)
const error = ref('')

function clearSecrets() {
  bootstrapToken.value = ''
  password.value = ''
  confirmPassword.value = ''
}

onUnmounted(clearSecrets)

async function onSubmit() {
  error.value = ''
  if ([...password.value].length < 8) {
    error.value = t('auth.passwordTooShort')
    return
  }
  if (password.value !== confirmPassword.value) {
    error.value = t('auth.passwordMismatch')
    return
  }
  busy.value = true
  try {
    await setupInitialPassword(bootstrapToken.value, password.value, username.value)
    clearSecrets()
    pushToast(t('auth.completeSetup'), 'ok')
    router.replace({ name: 'login' })
  } catch (err) {
    error.value = err?.message || 'Setup failed'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AuthShell :title="t('auth.setupTitle')" :subtitle="t('auth.setupHint')">
    <form class="k-stack" @submit.prevent="onSubmit">
      <div v-if="error" class="k-alert k-alert--error" role="alert">{{ error }}</div>

      <PasswordField
        id="setup-token"
        v-model="bootstrapToken"
        :label="t('auth.bootstrapToken')"
        autocomplete="off"
        required
        :disabled="busy"
      />

      <label class="k-field">
        <span class="k-field-label">{{ t('auth.username') }}</span>
        <input v-model="username" class="k-input" autocomplete="username" required
          maxlength="256" :disabled="busy" />
      </label>

      <PasswordField
        id="setup-pw"
        v-model="password"
        :label="t('auth.newPassword')"
        autocomplete="new-password"
        required
        :disabled="busy"
      />

      <PasswordField
        id="setup-pw-confirm"
        v-model="confirmPassword"
        :label="t('auth.confirmPassword')"
        autocomplete="new-password"
        required
        :disabled="busy"
      />

      <button
        type="submit"
        class="k-btn k-btn--primary k-btn--block"
        :disabled="busy || !bootstrapToken || !username.trim()"
      >
        {{ busy ? t('common.loading') : t('auth.completeSetup') }}
      </button>
    </form>
  </AuthShell>
</template>
