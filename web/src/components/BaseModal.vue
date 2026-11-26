<script setup>
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { t } from '../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: '' },
  wide: { type: Boolean, default: false },
})

const emit = defineEmits(['close'])
const dialog = ref(null)
let returnFocus

function restoreFocus() {
  if (returnFocus?.isConnected && (document.activeElement === document.body || dialog.value?.contains(document.activeElement))) {
    returnFocus.focus()
  }
  returnFocus = null
}

watch(() => props.open, async (open) => {
  if (open) returnFocus = document.activeElement
  await nextTick()
  if (open && props.open) dialog.value?.focus()
  else if (!open && !props.open) restoreFocus()
}, { immediate: true })
onBeforeUnmount(restoreFocus)

function keepFocus(event) {
  const items = [...dialog.value.querySelectorAll('button, input, select, textarea, a[href], summary, [tabindex]')]
    .filter((item) => item.tabIndex >= 0 && !item.matches(':disabled') && item.getClientRects().length)
  const endpoint = event.shiftKey ? items.at(-1) : items[0]
  const opposite = event.shiftKey ? items[0] : items.at(-1)
  if (!endpoint || document.activeElement === dialog.value || document.activeElement === opposite) {
    event.preventDefault()
    const target = endpoint || dialog.value
    target.focus()
  }
}
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="k-modal-backdrop" @mousedown.self="emit('close')">
      <div
        class="k-modal"
        ref="dialog"
        tabindex="-1"
        :class="{ 'k-modal--wide': wide }"
        role="dialog"
        aria-modal="true"
        :aria-label="title"
        @keydown.esc.stop.prevent="emit('close')"
        @keydown.tab="keepFocus"
      >
        <header class="k-modal-header">
          <h3 class="k-modal-title">{{ title }}</h3>
          <button type="button" class="k-btn k-btn--ghost k-btn--compact" :aria-label="t('overview.closeDialog')" @click="emit('close')">
            ✕
          </button>
        </header>
        <div class="k-modal-body">
          <slot />
        </div>
        <footer v-if="$slots.footer" class="k-modal-footer">
          <slot name="footer" />
        </footer>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.k-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 1100;
  background: rgba(9, 10, 14, 0.74);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.25rem;
}

.k-modal {
  width: 100%;
  max-width: 520px;
  max-height: 90dvh;
  display: flex;
  flex-direction: column;
  background: var(--k-surface);
  border: 1px solid var(--k-border);
  border-radius: var(--k-radius-sm);
}

.k-modal--wide {
  max-width: 860px;
}

.k-modal:focus { outline: none; }

.k-modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 18px;
  background: var(--k-surface-header);
  border-radius: var(--k-radius-sm) var(--k-radius-sm) 0 0;
  border-bottom: 1px solid var(--k-border-subtle);
}

.k-modal-title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
}

.k-modal-body {
  padding: 18px;
  overflow: auto;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.k-modal-footer {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 18px;
  border-top: 1px solid var(--k-border-subtle);
}
</style>
