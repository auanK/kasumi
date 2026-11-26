<script setup>
import { onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import AuthShell from './AuthShell.vue'
import PasswordField from '../components/PasswordField.vue'
import { useAuth } from '../composables/useAuth.js'
import { t } from '../i18n/index.js'

const router = useRouter()
const { auth, login } = useAuth()

const username = ref(auth.username)
const password = ref('')
const busy = ref(false)
const error = ref('')

onUnmounted(() => {
  password.value = ''
})

async function onSubmit() {
  error.value = ''
  busy.value = true
  try {
    await login(password.value, username.value)
    password.value = ''
    router.replace({ name: 'hub' })
  } catch (err) {
    if (err?.status === 429) {
      error.value = t('auth.rateLimited')
    } else if (err?.status === 401) {
      error.value = t('auth.invalidCredentials')
    } else {
      error.value = err?.message || t('auth.invalidCredentials')
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AuthShell :title="t('auth.loginTitle')" :subtitle="t('auth.loginHint')">
    <form class="k-stack" @submit.prevent="onSubmit">
      <div v-if="error" class="k-alert k-alert--error" role="alert">{{ error }}</div>

      <div class="k-field">
        <label for="login-user" class="k-field-label">{{ t('auth.username') }}</label>
        <input
          id="login-user"
          v-model="username"
          class="k-input"
          autocomplete="username"
          required
          :disabled="busy"
        />
      </div>

      <PasswordField
        id="login-password"
        v-model="password"
        :label="t('auth.password')"
        autocomplete="current-password"
        required
        :disabled="busy"
      />

      <button type="submit" class="k-btn k-btn--primary k-btn--block" :disabled="busy || !password">
        {{ busy ? t('common.loading') : t('auth.signIn') }}
      </button>
    </form>
  </AuthShell>
</template>
