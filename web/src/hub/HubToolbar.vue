<script setup>
import { t } from '../i18n/index.js'

defineProps({
  search: { type: String, default: '' },
  filter: { type: String, default: 'all' },
  counts: {
    type: Object,
    default: () => ({ all: 0, active: 0, paused: 0, attention: 0 }),
  },
})

const emit = defineEmits(['update:search', 'update:filter'])
</script>

<template>
  <div class="k-hub-toolbar">
    <input
      :value="search"
      type="search"
      class="k-input k-hub-search"
      :aria-label="t('hub.searchPlaceholder')"
      :placeholder="t('hub.searchPlaceholder')"
      @input="emit('update:search', $event.target.value)"
    />

    <div class="k-segmented" role="group" :aria-label="t('overview.filterProfiles')">
      <button
        type="button"
        class="k-seg-btn"
        :class="{ 'k-seg-btn--active': filter === 'all' }"
        :aria-pressed="filter === 'all'"
        @click="emit('update:filter', 'all')"
      >
        {{ t('hub.filterAll') }} ({{ counts.all }})
      </button>
      <button
        type="button"
        class="k-seg-btn"
        :class="{ 'k-seg-btn--active': filter === 'active' }"
        :aria-pressed="filter === 'active'"
        @click="emit('update:filter', 'active')"
      >
        {{ t('hub.filterActive') }} ({{ counts.active }})
      </button>
      <button
        type="button"
        class="k-seg-btn"
        :class="{ 'k-seg-btn--active': filter === 'paused' }"
        :aria-pressed="filter === 'paused'"
        @click="emit('update:filter', 'paused')"
      >
        {{ t('hub.filterPaused') }} ({{ counts.paused }})
      </button>
      <button
        v-if="counts.attention > 0 || filter === 'attention'"
        type="button"
        class="k-seg-btn"
        :class="{ 'k-seg-btn--active': filter === 'attention' }"
        :aria-pressed="filter === 'attention'"
        @click="emit('update:filter', 'attention')"
      >
        {{ t('hub.filterAttention') }} ({{ counts.attention }})
      </button>
    </div>
  </div>
</template>

<style scoped>
.k-hub-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
}

.k-hub-search {
  max-width: 340px;
}
</style>
