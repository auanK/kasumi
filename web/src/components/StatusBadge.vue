<script setup>
import { computed } from 'vue'
import { t } from '../i18n/index.js'

const props = defineProps({
  state: { type: String, default: 'idle' },
  label: { type: String, default: '' },
})

const normalized = computed(() => (props.state || 'idle').toLowerCase())

const displayLabel = computed(() => {
  if (props.label) return props.label
  const s = normalized.value
  if (s === 'idle' || s === 'ready' || s === 'ok') return t('status.ready')
  if (s === 'running_sync' || s === 'syncing') return t('status.syncing')
  if (s === 'external') return t('status.external')
  if (s === 'pending_debounce' || s === 'pending') return t('status.pending')
  if (s === 'paused') return t('status.paused')
  if (s === 'locked') return t('status.locked')
  if (s === 'backoff' || s === 'retrying') return t('status.retrying')
  if (['needs_attention', 'problem', 'error'].includes(s)) return t('status.attention')
  if (s === 'initialized') return t('status.uninitialized')
  if (s === 'unknown') return t('status.unknown')
  if (s === 'healthy' || s === 'degraded' || s === 'critical') return t('status.' + s)
  if (['managed', 'ignored_protected', 'ignored_disposable'].includes(s)) return t('ignore.disposition.' + s)
  if (['running', 'completed', 'failed'].includes(s)) return t('outcome.' + s)
  return props.state
})

const tone = computed(() => {
  const s = normalized.value
  if (['ok', 'idle', 'ready', 'connected', 'completed', 'succeeded', 'healthy', 'managed'].includes(s)) {
    return 'ok'
  }
  if (['running_sync', 'syncing', 'running', 'connecting', 'external'].includes(s)) {
    return 'info'
  }
  if (['paused', 'locked', 'backoff', 'reconnecting', 'warning', 'degraded', 'ignored_protected', 'ignored_disposable',
    'queued', 'pending', 'pending_debounce', 'needs_attention', 'problem'].includes(s)) {
    return 'warn'
  }
  if (['error', 'failed', 'offline', 'conflict', 'disconnected', 'critical'].includes(s)) {
    return 'error'
  }
  return 'muted'
})
</script>

<template>
  <span class="k-badge" :class="`k-badge--${tone}`">
    <span class="k-badge-dot" />
    {{ displayLabel }}
  </span>
</template>

<style scoped>
.k-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 8px;
  border-radius: var(--k-radius-xs);
  border: 1px solid var(--k-border);
  font-size: 11.5px;
  font-weight: 500;
  line-height: 1.45;
  white-space: nowrap;
}

.k-badge-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
}

.k-badge--ok {
  color: var(--k-ok);
  background: var(--k-ok-bg);
  border-color: var(--k-ok-border);
}

.k-badge--info {
  color: var(--k-info);
  background: var(--k-info-bg);
  border-color: var(--k-info-border);
}

.k-badge--warn {
  color: var(--k-warn);
  background: var(--k-warn-bg);
  border-color: var(--k-warn-border);
}

.k-badge--error {
  color: var(--k-error);
  background: var(--k-error-bg);
  border-color: var(--k-error-border);
}

.k-badge--muted {
  color: var(--k-text-muted);
  background: var(--k-surface-elevated);
}
</style>
