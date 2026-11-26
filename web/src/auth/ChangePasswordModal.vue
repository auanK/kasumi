<script setup>
import { onUnmounted, ref, watch } from 'vue'
import BaseModal from '../components/BaseModal.vue'
import PasswordField from '../components/PasswordField.vue'
import { useAuth } from '../composables/useAuth.js'
import { pushToast } from '../composables/useToasts.js'
import { t } from '../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'changed'])
const { auth, changePassword } = useAuth()

const currentPassword = ref('')
const username = ref('')
const nextPassword = ref('')
const confirmPassword = ref('')
const busy = ref(false)
const error = ref('')
watch(() => props.open, (open) => {
  if (open) username.value = auth.username
}, { immediate: true })

function reset() {
  currentPassword.value = ''
  nextPassword.value = ''
  confirmPassword.value = ''
  error.value = ''
}

function onClose() {
  reset()
  emit('close')
}

onUnmounted(reset)

async function onSubmit() {
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
    await changePassword(currentPassword.value, nextPassword.value, username.value)
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
    <form id="change-pw-form" class="k-stack" @submit.prevent="onSubmit">
      <div class="k-alert k-alert--info">{{ t('auth.changePasswordNote') }}</div>
      <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>

      <PasswordField
        v-model="currentPassword"
        :label="t('auth.currentPassword')"
        autocomplete="current-password"
        required
        :disabled="busy"
      />
      <label class="k-field">
        <span class="k-field-label">{{ t('auth.username') }}</span>
        <input v-model="username" class="k-input" autocomplete="username" required
          maxlength="256" :disabled="busy" />
      </label>
      <PasswordField
        v-model="nextPassword"
        :label="t('auth.newPassword')"
        autocomplete="new-password"
        required
        :disabled="busy"
      />
      <PasswordField
        v-model="confirmPassword"
        :label="t('auth.confirmPassword')"
        autocomplete="new-password"
        required
        :disabled="busy"
      />
    </form>

    <template #footer>
      <button type="button" class="k-btn" :disabled="busy" @click="onClose">
        {{ t('common.cancel') }}
      </button>
      <button type="submit" form="change-pw-form" class="k-btn k-btn--primary" :disabled="busy">
        {{ busy ? t('common.loading') : t('common.save') }}
      </button>
    </template>
  </BaseModal>
</template>
