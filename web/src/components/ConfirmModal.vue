<script setup>
import BaseModal from './BaseModal.vue'
import { t } from '../i18n/index.js'

defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, required: true },
  message: { type: String, required: true },
  confirmLabel: { type: String, default: '' },
  danger: { type: Boolean, default: false },
  busy: { type: Boolean, default: false },
  blockedReason: { type: String, default: '' },
})

const emit = defineEmits(['confirm', 'close'])
</script>

<template>
  <BaseModal :open="open" :title="title" @close="emit('close')">
    <p class="k-confirm-text">{{ message }}</p>
    <p v-if="blockedReason" class="k-alert k-alert--info" role="status">{{ blockedReason }}</p>
    <slot />
    <template #footer>
      <button type="button" class="k-btn" :disabled="busy" @click="emit('close')">
        {{ t('common.cancel') }}
      </button>
      <button
        type="button"
        class="k-btn"
        :class="danger ? 'k-btn--danger' : 'k-btn--primary'"
        :disabled="busy || Boolean(blockedReason)"
        @click="emit('confirm')"
      >
        {{ confirmLabel || t('common.confirm') }}
      </button>
    </template>
  </BaseModal>
</template>

<style scoped>
.k-confirm-text {
  margin: 0;
  color: var(--k-text-muted);
  line-height: 1.55;
}
</style>
