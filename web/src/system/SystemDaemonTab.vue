<script setup>
import { computed, onMounted, ref } from 'vue'
import ConfirmModal from '../components/ConfirmModal.vue'
import {
  fetchWebConfig,
  reloadDaemonConfig,
  setAutostart,
  stopDaemon,
  updateWebConfig,
} from '../api/daemon.js'
import { useDaemonStream } from '../composables/useDaemonStream.js'
import { pushToast } from '../composables/useToasts.js'
import { formatDuration } from '../utils/format.js'
import { t } from '../i18n/index.js'

const stream = useDaemonStream()
const busy = ref(false)
const stopConfirmOpen = ref(false)

const webBind = ref('127.0.0.1')
const webPort = ref(3137)
const activePort = ref(null)
const allowedHostsText = ref('')
const skipHostCheck = ref(false)
const customBindMode = ref(false)
const webConfigBusy = ref(false)
const webConfigError = ref('')
const restartRequired = ref(false)

const listenMode = computed(() => {
  if (customBindMode.value) return 'custom'
  if (webBind.value === '127.0.0.1') return 'local'
  if (webBind.value === '0.0.0.0') return 'all'
  return 'custom'
})

function selectListenMode(mode) {
  if (mode === 'local') {
    customBindMode.value = false
    webBind.value = '127.0.0.1'
  } else if (mode === 'all') {
    customBindMode.value = false
    webBind.value = '0.0.0.0'
  } else {
    customBindMode.value = true
  }
}

async function loadWebConfig() {
  webConfigError.value = ''
  try {
    const cfg = await fetchWebConfig()
    if (!cfg) return
    webBind.value = cfg.bind || '127.0.0.1'
    webPort.value = Number.isFinite(Number(cfg.port)) ? Number(cfg.port) : 3137
    activePort.value = cfg.active_port ?? null
    allowedHostsText.value = Array.isArray(cfg.allowed_hosts)
      ? cfg.allowed_hosts.join(', ')
      : ''
    skipHostCheck.value = Boolean(cfg.skip_host_check)
    customBindMode.value = webBind.value !== '127.0.0.1' && webBind.value !== '0.0.0.0'
  } catch (err) {
    webConfigError.value = err?.message || t('system.webLoadFailed')
  }
}

onMounted(() => {
  loadWebConfig()
})

async function handleSaveWebConfig() {
  webConfigError.value = ''
  webConfigBusy.value = true
  try {
    const hosts = allowedHostsText.value
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)
    const parsedPort = Number.parseInt(String(webPort.value), 10)
    const payload = {
      bind: webBind.value.trim() || '127.0.0.1',
      port: Number.isNaN(parsedPort) ? -1 : parsedPort,
      allowed_hosts: hosts,
      skip_host_check: Boolean(skipHostCheck.value),
    }
    const res = await updateWebConfig(payload)
    if (res) {
      webBind.value = res.bind || payload.bind
      if (Number.isFinite(Number(res.port))) webPort.value = Number(res.port)
      allowedHostsText.value = Array.isArray(res.allowed_hosts)
        ? res.allowed_hosts.join(', ')
        : hosts.join(', ')
      skipHostCheck.value = Boolean(res.skip_host_check)
      customBindMode.value = webBind.value !== '127.0.0.1' && webBind.value !== '0.0.0.0'
      if (res.restart_required) restartRequired.value = true
    }
    pushToast(t('system.webSaved'), 'ok')
  } catch (err) {
    webConfigError.value = err?.message || t('system.webLoadFailed')
  } finally {
    webConfigBusy.value = false
  }
}

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
          {{ activePort || stream.daemonStatus?.web_port || stream.daemonStatus?.ipc_port || '—' }}
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

    <form class="k-card k-card-body k-stack" @submit.prevent="handleSaveWebConfig">
      <div class="k-row k-row--between k-row--wrap">
        <div>
          <strong>{{ t('system.webTitle') }}</strong>
          <div class="k-faint k-text-sm">{{ t('system.webSubtitle') }}</div>
        </div>
        <span class="k-mono k-text-sm k-faint">
          {{ webBind }}:{{ webPort }}
        </span>
      </div>

      <div v-if="webConfigError" class="k-alert k-alert--error" role="alert">{{ webConfigError }}</div>
      <div v-if="restartRequired" class="k-alert k-alert--warn" role="status">
        {{ t('system.webRestartNotice') }}
      </div>

      <div class="k-field">
        <span class="k-field-label">{{ t('system.webMode') }}</span>
        <div class="k-segmented" role="group">
          <button
            type="button"
            class="k-seg-btn"
            :class="{ 'k-seg-btn--active': listenMode === 'local' }"
            :disabled="webConfigBusy"
            @click="selectListenMode('local')"
          >
            {{ t('system.webBindLocal') }}
          </button>
          <button
            type="button"
            class="k-seg-btn"
            :class="{ 'k-seg-btn--active': listenMode === 'all' }"
            :disabled="webConfigBusy"
            @click="selectListenMode('all')"
          >
            {{ t('system.webBindAll') }}
          </button>
          <button
            type="button"
            class="k-seg-btn"
            :class="{ 'k-seg-btn--active': listenMode === 'custom' }"
            :disabled="webConfigBusy"
            @click="selectListenMode('custom')"
          >
            {{ t('system.webBindCustom') }}
          </button>
        </div>
      </div>

      <div class="k-grid-2">
        <label v-if="listenMode === 'custom'" class="k-field">
          <span class="k-field-label">{{ t('system.webBindAddress') }}</span>
          <input
            v-model="webBind"
            class="k-input k-mono"
            placeholder="0.0.0.0"
            :disabled="webConfigBusy"
          />
        </label>
        <label class="k-field">
          <span class="k-field-label">{{ t('system.webPort') }}</span>
          <input
            v-model.number="webPort"
            type="number"
            min="0"
            max="65535"
            class="k-input k-mono"
            :disabled="webConfigBusy"
          />
          <span class="k-field-hint">{{ t('system.webPortHint') }}</span>
        </label>
      </div>

      <label class="k-field">
        <span class="k-field-label">{{ t('system.webAllowedHosts') }}</span>
        <input
          v-model="allowedHostsText"
          class="k-input k-mono"
          placeholder="*.ts.net, kasumi.internal"
          :disabled="webConfigBusy"
        />
        <span class="k-field-hint">{{ t('system.webAllowedHostsHint') }}</span>
      </label>

      <label class="k-row k-row--sm">
        <input v-model="skipHostCheck" type="checkbox" :disabled="webConfigBusy" />
        <span>
          <span class="k-field-label">{{ t('system.webSkipHostCheck') }}</span>
          <span class="k-field-hint"> — {{ t('system.webSkipHostCheckHint') }}</span>
        </span>
      </label>

      <div class="k-row k-row--between">
        <span />
        <button type="submit" class="k-btn k-btn--primary k-btn--compact" :disabled="webConfigBusy">
          {{ webConfigBusy ? t('common.loading') : t('system.webSave') }}
        </button>
      </div>
    </form>

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
