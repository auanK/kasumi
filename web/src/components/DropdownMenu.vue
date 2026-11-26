<script setup>
import { onMounted, onUnmounted, ref } from 'vue'

defineProps({
  align: { type: String, default: 'left' }, // 'left' | 'right'
})

const open = ref(false)
const rootRef = ref(null)

function close() {
  open.value = false
}

function onDocClick(evt) {
  if (open.value && rootRef.value && !rootRef.value.contains(evt.target)) {
    open.value = false
  }
}

function onKeydown(evt) {
  if (open.value && evt.key === 'Escape') {
    open.value = false
  }
}

onMounted(() => {
  document.addEventListener('click', onDocClick)
  window.addEventListener('keydown', onKeydown)
})

onUnmounted(() => {
  document.removeEventListener('click', onDocClick)
  window.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <div ref="rootRef" class="k-menu-wrap">
    <slot name="trigger" :open="open" :toggle="() => (open = !open)" :close="close" />
    <div
      v-if="open"
      class="k-menu"
      :class="{ 'k-menu--right': align === 'right' }"
      role="menu"
      @click="close"
    >
      <slot :close="close" />
    </div>
  </div>
</template>

<style scoped>
.k-menu-wrap {
  position: relative;
  display: inline-flex;
  align-items: center;
}

.k-menu {
  position: absolute;
  top: calc(100% + 5px);
  left: 0;
  min-width: 210px;
  z-index: 950;
  padding: 5px;
  background: var(--k-surface-elevated);
  border: 1px solid var(--k-border);
  border-radius: var(--k-radius-sm);
  box-shadow: 0 12px 28px rgba(0, 0, 0, 0.45);
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.k-menu--right {
  left: auto;
  right: 0;
}

.k-menu :deep(.k-menu-item) {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 7px 10px;
  border: none;
  border-radius: var(--k-radius-xs);
  background: transparent;
  color: var(--k-text);
  font-size: 13px;
  text-align: left;
  cursor: pointer;
}

.k-menu :deep(.k-menu-item:hover:not(:disabled)) {
  background: var(--k-hover);
}

.k-menu :deep(.k-menu-item--active) {
  color: var(--k-lavender);
  background: var(--k-active);
}

.k-menu :deep(.k-menu-item--danger) {
  color: var(--k-error);
}

.k-menu :deep(.k-menu-divider) {
  height: 1px;
  margin: 4px 2px;
  background: var(--k-border-subtle);
}
</style>
