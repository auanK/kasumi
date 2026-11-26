<script setup>
defineProps({
  title: { type: String, required: true },
  description: { type: String, default: '' },
})
</script>

<template>
  <div class="k-empty k-card">
    <p class="k-empty-title">{{ title }}</p>
    <p v-if="description" class="k-empty-desc">{{ description }}</p>
    <div v-if="$slots.default" class="k-empty-actions">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.k-empty {
  padding: 2.25rem 1.5rem;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 8px;
}

.k-empty-title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
}

.k-empty-desc {
  margin: 0;
  color: var(--k-text-muted);
  max-width: 520px;
}

.k-empty-actions {
  margin-top: 8px;
}
</style>
