<script setup>
import { computed } from 'vue'
import StatusBadge from '../components/StatusBadge.vue'
import { useDaemonStream } from '../composables/useDaemonStream.js'
import { t } from '../i18n/index.js'
import { extractDetailDuration, formatDuration, formatTimestamp, translateWithFallback } from '../utils/format.js'

defineEmits(['open-system', 'open-profile'])
const stream = useDaemonStream()
const live = computed(() => stream.daemonStatus || {})
const events = computed(() => stream.logs.slice(-5).reverse())
const stateLabel = computed(() => t(stream.streamState === 'connected' ? 'system.pillOnline' :
  stream.streamState === 'reconnecting' ? 'system.pillReconnecting' : 'system.pillOffline'))

function eventDuration(entry) {
  return extractDetailDuration(entry?.detail)
}

function eventLabel(entry) {
  const key = 'event.' + (eventTone(entry) === 'unchanged' ? 'unchanged' : entry.kind)
  return translateWithFallback(t, key, entry.detail || entry.kind.replaceAll('_', ' '))
}

function eventTone(entry) {
  if (entry.kind === 'fast_noop' ||
      (entry.kind === 'sync_completed' && (entry.outcome === 'no_changes' ||
        /^up=0, down=0, rm=0, mv=0(?:\s|$)/.test(entry.detail || '')))) return 'unchanged'
  if (entry.kind === 'sync_completed') return 'success'
  if (['sync_error', 'needs_attention', 'failed', 'error'].includes(entry.kind)) return 'error'
  if (['paused', 'locked', 'backoff', 'sync_cancelled'].includes(entry.kind)) return 'warning'
  if (['sync_started', 'started', 'resumed'].includes(entry.kind)) return 'running'
  return 'neutral'
}
</script>

<template>
  <aside class="k-service-panel" :aria-label="t('system.title')">
    <section>
      <div class="k-section-header">
        <h2>{{ t('overview.thisDevice') }}</h2>
        <button type="button" class="k-btn k-btn--compact" @click="$emit('open-system', 'daemon')">{{ t('overview.serviceSettings') }}</button>
      </div>
      <div class="k-card k-service-card">
        <header class="k-card-header">
          <strong>Kasumi</strong>
          <StatusBadge :state="stream.streamState" :label="stateLabel" />
        </header>
        <dl class="k-facts">
          <dt>{{ t('overview.device') }}</dt><dd>{{ live.machine_name || '—' }}</dd>
          <dt>{{ t('overview.uptime') }}</dt><dd>{{ formatDuration(stream.liveUptimeSeconds ?? live.uptime_seconds) }}</dd>
          <dt>{{ t('overview.autostart') }}</dt>
          <dd>{{ live.autostart ? t(!live.autostart.supported ? 'overview.serviceUnavailable' : live.autostart.installed ? 'common.enabled' : 'common.disabled') : '—' }}</dd>
          <dt>{{ t('overview.version') }}</dt><dd>{{ live.kasumi_version ? 'v' + live.kasumi_version : '—' }}</dd>
        </dl>
      </div>
    </section>
    <section>
      <div class="k-section-header">
        <h2>{{ t('overview.activity') }}</h2>
        <button type="button" class="k-btn k-btn--compact" @click="$emit('open-system', 'logs')">{{ t('overview.viewLogs') }}</button>
      </div>
      <div class="k-card k-service-events">
        <p v-if="!events.length" class="k-muted k-event-empty">{{ t('overview.noActivity') }}</p>
        <ul v-else>
          <li v-for="entry in events" :key="entry.seq" :data-tone="eventTone(entry)">
            <button v-if="entry.profile_name" type="button" class="k-event-profile" @click="$emit('open-profile', entry.profile_name)">{{ entry.profile_name }}</button>
            <strong v-else>{{ t('overview.thisDevice') }}</strong>
            <div class="k-event-detail" :title="entry.detail">{{ eventLabel(entry) }}</div>
            <time>{{ formatTimestamp(entry.timestamp_unix) }}<template v-if="eventDuration(entry)"> · {{ eventDuration(entry) }}</template></time>
          </li>
        </ul>
      </div>
    </section>
  </aside>
</template>
