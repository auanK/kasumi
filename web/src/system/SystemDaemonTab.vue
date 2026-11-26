<script setup>
import { ref } from 'vue'
import ConfirmModal from '../components/ConfirmModal.vue'
import { reloadDaemonConfig, setAutostart, stopDaemon } from '../api/daemon.js'
import { useDaemonStream } from '../composables/useDaemonStream.js'
import { pushToast } from '../composables/useToasts.js'
import { formatDuration } from '../utils/format.js'
import { t } from '../i18n/index.js'

const stream = useDaemonStream()
const busy = ref(false)
const stopConfirmOpen = ref(false)

async function toggleAutostart() {
  const next = !stream.daemonStatus?.autostart?.installed
  busy.value = true
  try {
    await setAutostart(next)
    await stream.refreshStatus()
    pushToast(next ? t('common.enabled') : t('common.disabled'), 'ok')
  } catch (err) {
    pushToast(err?.message || 'Failed to update autostart', 'error')
  } finally {
    busy.value = false
  }
}

async function handleReload() {
  busy.value = true
  try {
    await reloadDaemonConfig()
    await stream.refreshStatus()
    pushToast(t('system.reload'), 'ok')
  } catch (err) {
    pushToast(err?.message || 'Reload failed', 'error')
  } finally {
    busy.value = false
  }
}

async function handleStop() {
  stopConfirmOpen.value = false
  busy.value = true
  try {
    await stopDaemon()
    pushToast(t('system.stop'), 'ok')
  } catch (err) {
    pushToast(err?.message || 'Stop failed', 'error')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="k-stack">
    <div class="k-grid-2">
      <div class="k-card k-card-body k-stack--sm">
        <span class="k-field-label">{{ t('overview.device') }}</span>
        <strong class="k-mono">{{ stream.daemonStatus?.machine_name || '—' }}</strong>
      </div>
      <div class="k-card k-card-body k-stack--sm">
        <span class="k-field-label">Kasumi</span>
        <strong class="k-mono">{{ stream.daemonStatus?.kasumi_version ? `v${stream.daemonStatus.kasumi_version}` : '—' }}</strong>
      </div>
      <div class="k-card k-card-body k-stack--sm">
        <span class="k-field-label">{{ t('overview.uptime') }}</span>
        <strong class="k-mono">{{ formatDuration(stream.liveUptimeSeconds ?? stream.daemonStatus?.uptime_seconds) }}</strong>
      </div>
      <div class="k-card k-card-body k-stack--sm">
        <span class="k-field-label">PID / Web Port</span>
        <strong class="k-mono">
          {{ stream.daemonStatus?.pid ?? '—' }} ·
          {{ stream.daemonStatus?.web_port || stream.daemonStatus?.ipc_port || '—' }}
        </strong>
      </div>
      <div class="k-card k-card-body k-stack--sm">
        <span class="k-field-label">Pinned RAM</span>
        <strong class="k-mono">
          {{ stream.daemonStatus?.secure_pages_locked ? t('common.enabled') : 'best-effort' }}
        </strong>
      </div>
    </div>

    <div
      v-if="stream.daemonStatus?.autostart?.supported"
      class="k-card k-card-body k-row k-row--between"
    >
      <div>
        <strong>Start automatically at sign in</strong>
        <div class="k-faint k-text-sm">
          {{ stream.daemonStatus.autostart.method || 'user session' }}
        </div>
      </div>
      <button type="button" class="k-btn k-btn--compact" :disabled="busy" @click="toggleAutostart">
        {{ stream.daemonStatus.autostart.installed ? t('common.enabled') : t('common.disabled') }}
      </button>
    </div>

    <div class="k-row k-row--between k-row--wrap">
      <button type="button" class="k-btn k-btn--compact" :disabled="busy" @click="handleReload">
        {{ t('system.reload') }}
      </button>
      <button
        type="button"
        class="k-btn k-btn--danger k-btn--compact"
        :disabled="busy"
        @click="stopConfirmOpen = true"
      >
        {{ t('system.stop') }}
      </button>
    </div>

    <ConfirmModal
      :open="stopConfirmOpen"
      :title="t('system.stopConfirmTitle')"
      :message="t('system.stopConfirmBody')"
      :confirm-label="t('system.stop')"
      danger
      :busy="busy"
      @close="stopConfirmOpen = false"
      @confirm="handleStop"
    />
  </div>
</template>
