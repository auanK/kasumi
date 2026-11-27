<script setup>
import { onUnmounted, ref, watch } from 'vue'
import BaseModal from '../components/BaseModal.vue'
import ConfirmModal from '../components/ConfirmModal.vue'
import PasswordField from '../components/PasswordField.vue'
import { useAuth } from '../composables/useAuth.js'
import { pushToast } from '../composables/useToasts.js'
import { t } from '../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'changed'])
const { auth, changePassword, changeUsername } = useAuth()

const activeTab = ref('username')
const currentPassword = ref('')
const username = ref('')
const nextPassword = ref('')
const confirmPassword = ref('')
const busy = ref(false)
const error = ref('')
const confirmUsernameOpen = ref(false)

watch(
  () => props.open,
  (open) => {
    if (open) {
      activeTab.value = 'username'
      username.value = auth.username || ''
      currentPassword.value = ''
      nextPassword.value = ''
      confirmPassword.value = ''
      error.value = ''
      confirmUsernameOpen.value = false
    }
  },
  { immediate: true }
)

function switchTab(tab) {
  if (busy.value) return
  activeTab.value = tab
  error.value = ''
  confirmUsernameOpen.value = false
  nextPassword.value = ''
  confirmPassword.value = ''
}

function reset() {
  activeTab.value = 'username'
  currentPassword.value = ''
  nextPassword.value = ''
  confirmPassword.value = ''
  error.value = ''
  confirmUsernameOpen.value = false
}

function onClose() {
  if (busy.value) return
  reset()
  emit('close')
}

onUnmounted(reset)

function onSubmitUsername() {
  error.value = ''
  const trimmed = username.value.trim()
  if (!trimmed) {
    error.value = t('auth.username')
    return
  }
  if (trimmed === (auth.username || '')) {
    error.value = t('auth.usernameUnchanged')
    return
  }
  if (!currentPassword.value) {
    error.value = t('auth.currentPassword')
    return
  }
  username.value = trimmed
  confirmUsernameOpen.value = true
}

async function confirmUsernameChange() {
  const trimmed = username.value.trim()
  busy.value = true
  error.value = ''
  try {
    await changeUsername(currentPassword.value, trimmed)
    reset()
    pushToast(t('auth.usernameUpdated'), 'ok')
    emit('changed')
    emit('close')
  } catch (err) {
    confirmUsernameOpen.value = false
    error.value = err?.message || 'Failed to update username'
  } finally {
    busy.value = false
  }
}

async function onSubmitPassword() {
  error.value = ''
  if ([...nextPassword.value].length < 8) {
    error.value = t('auth.passwordTooShort')
    return
  }
  if (nextPassword.value !== confirmPassword.value) {
    error.value = t('auth.passwordMismatch')
    return
  }
  busy.value = true
  try {
    await changePassword(currentPassword.value, nextPassword.value)
    reset()
    pushToast(t('auth.changePasswordNote'), 'ok')
    emit('changed')
    emit('close')
  } catch (err) {
    error.value = err?.message || 'Failed to change password'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <BaseModal :open="open" :title="t('auth.changePasswordTitle')" @close="onClose">
    <div class="k-stack">
      <div class="k-segmented" role="tablist">
        <button
          type="button"
          role="tab"
          class="k-seg-btn"
          :class="{ 'k-seg-btn--active': activeTab === 'username' }"
          :aria-selected="activeTab === 'username'"
          :disabled="busy"
          @click="switchTab('username')"
        >
          {{ t('auth.tabUsername') }}
        </button>
        <button
          type="button"
          role="tab"
          class="k-seg-btn"
          :class="{ 'k-seg-btn--active': activeTab === 'password' }"
          :aria-selected="activeTab === 'password'"
          :disabled="busy"
          @click="switchTab('password')"
        >
          {{ t('auth.tabPassword') }}
        </button>
      </div>

      <form
        v-if="activeTab === 'username'"
        key="username"
        id="change-username-form"
        class="k-stack"
        @submit.prevent="onSubmitUsername"
      >
        <div class="k-alert k-alert--info">{{ t('auth.changeUsernameNote') }}</div>
        <div v-if="error" class="k-alert k-alert--error" role="alert">{{ error }}</div>

        <label class="k-field">
          <span class="k-field-label">{{ t('auth.newUsername') }}</span>
          <input
            v-model="username"
            class="k-input"
            autocomplete="username"
            required
            maxlength="256"
            :disabled="busy"
          />
        </label>
        <PasswordField
          v-model="currentPassword"
          :label="t('auth.currentPassword')"
          autocomplete="current-password"
          required
          :disabled="busy"
        />
      </form>

      <form
        v-else
        key="password"
        id="change-pw-form"
        class="k-stack"
        @submit.prevent="onSubmitPassword"
      >
        <div class="k-alert k-alert--info">{{ t('auth.changePasswordNote') }}</div>
        <div v-if="error" class="k-alert k-alert--error" role="alert">{{ error }}</div>

        <PasswordField
          id="pw-current"
          v-model="currentPassword"
          :label="t('auth.currentPassword')"
          autocomplete="current-password"
          required
          :disabled="busy"
        />
        <PasswordField
          id="pw-next"
          v-model="nextPassword"
          :label="t('auth.newPassword')"
          autocomplete="new-password"
          required
          :disabled="busy"
        />
        <PasswordField
          id="pw-confirm"
          v-model="confirmPassword"
          :label="t('auth.confirmPassword')"
          autocomplete="new-password"
          required
          :disabled="busy"
        />
      </form>
    </div>

    <template #footer>
      <button type="button" class="k-btn" :disabled="busy" @click="onClose">
        {{ t('common.cancel') }}
      </button>
      <button
        type="submit"
        :form="activeTab === 'username' ? 'change-username-form' : 'change-pw-form'"
        class="k-btn k-btn--primary"
        :disabled="busy"
      >
        {{ busy ? t('common.loading') : t('common.save') }}
      </button>
    </template>

    <ConfirmModal
      :open="confirmUsernameOpen"
      :title="t('auth.confirmUsernameTitle')"
      :message="t('auth.confirmUsernameBody', { username: username.trim() })"
      :confirm-label="t('auth.confirmUsernameAction')"
      :busy="busy"
      @close="confirmUsernameOpen = false"
      @confirm="confirmUsernameChange"
    />
  </BaseModal>
</template>
