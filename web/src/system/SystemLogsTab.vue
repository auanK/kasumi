<script setup>
import { computed, ref } from 'vue'
import { useDaemonStream } from '../composables/useDaemonStream.js'
import { formatTimestamp } from '../utils/format.js'
import { t } from '../i18n/index.js'

const stream = useDaemonStream()
const query = ref('')
const showNoop = ref(false)

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase()
  return (stream.logs || [])
    .filter((entry) => {
      if (!showNoop.value && entry.kind === 'fast_noop') return false
      if (!q) return true
      return `${entry.profile_name || ''} ${entry.kind || ''} ${entry.detail || ''}`
        .toLowerCase()
        .includes(q)
    })
    .slice()
    .reverse()
})
</script>

<template>
  <div class="k-stack">
    <div class="k-row k-row--wrap">
      <input
        v-model="query"
        type="search"
        class="k-input k-input--compact k-min-w-0"
        :placeholder="t('common.search')"
      />
      <label class="k-row k-text-sm">
        <input v-model="showNoop" type="checkbox" />
        <span>{{ t('system.showUnchangedChecks') }}</span>
      </label>
      <button
        type="button"
        class="k-btn k-btn--compact"
        @click="stream.refreshLogs({ lines: 150, full: true }).catch(() => {})"
      >
        {{ t('common.refresh') }}
      </button>
    </div>

    <div class="k-log-box k-scroll-md k-mono">
      <div v-if="filtered.length === 0" class="k-muted k-card-body">{{ t('common.none') }}</div>
      <div
        v-for="item in filtered"
        :key="`${item.seq}-${item.timestamp_unix}`"
        class="k-log-entry"
      >
        <span class="k-faint">{{ formatTimestamp(item.timestamp_unix) }}</span>
        <span class="k-log-kind">{{ item.kind }}</span>
        <span class="k-log-prof">{{ item.profile_name || 'daemon' }}</span>
        <span class="k-log-msg">{{ item.detail }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.k-log-box {
  border: 1px solid var(--k-border-subtle);
  border-radius: var(--k-radius-xs);
  background: var(--k-input-bg);
  font-size: 12px;
}

.k-log-entry {
  display: grid;
  grid-template-columns: 168px 104px 96px minmax(0, 1fr);
  gap: 8px;
  padding: 5px 10px;
  border-bottom: 1px solid var(--k-border-subtle);
}

.k-log-kind {
  color: var(--k-primary);
}

.k-log-prof {
  color: var(--k-info);
}

.k-log-msg {
  word-break: break-word;
}

@media (max-width: 720px) {
  .k-log-entry {
    grid-template-columns: 1fr;
    gap: 2px;
  }
}
</style>
