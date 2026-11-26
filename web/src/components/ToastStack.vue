<script setup>
import { useToasts } from '../composables/useToasts.js'

const { toasts, dismissToast } = useToasts()
</script>

<template>
  <div class="k-toast-stack" aria-live="polite">
    <div
      v-for="item in toasts"
      :key="item.id"
      class="k-toast"
      :class="`k-alert k-alert--${item.kind}`"
    >
      <span class="k-toast-msg">{{ item.message }}</span>
      <button type="button" class="k-btn k-btn--ghost k-btn--compact" @click="dismissToast(item.id)">
        ✕
      </button>
    </div>
  </div>
</template>

<style scoped>
.k-toast-stack {
  position: fixed;
  right: 16px;
  bottom: 16px;
  z-index: 1200;
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-width: 380px;
}

.k-toast {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
}

.k-toast-msg {
  word-break: break-word;
}
</style>
