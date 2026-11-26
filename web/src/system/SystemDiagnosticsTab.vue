<script setup>
import { onMounted, ref } from 'vue'
import StatusBadge from '../components/StatusBadge.vue'
import { fetchDiagnostics } from '../api/profiles.js'
import { formatBytes } from '../utils/format.js'
import { t } from '../i18n/index.js'

const data = ref(null)
const loading = ref(false)
const error = ref('')

function formatRclone(rclone) {
  if (!rclone?.found) return t('diagnostics.notDetected')
  const ver = rclone.version ? String(rclone.version).replace(/^v/i, '') : '?'
  const suffix = rclone.meets_minimum === false && rclone.minimum_version
    ? ` (${t('diagnostics.minimum', { version: rclone.minimum_version })})`
    : ''
  return `v${ver}${suffix}`
}

function formatIgnoreStatus(entry) {
  if (!entry?.ignore_file_present) return t('diagnostics.ignoreNone')
  if (entry.ignore_file_valid === false) {
    return entry.ignore_error_detail
      ? `${t('diagnostics.ignoreInvalid')} (${entry.ignore_error_line}: ${entry.ignore_error_detail})`
      : t('diagnostics.ignoreInvalid')
  }
  return t('diagnostics.ignorePresent')
}

function formatHealth(entry) {
  if (entry?.healthy) return 'OK'
  const parts = [entry?.detail, entry?.daemon_error].filter(Boolean)
  return parts.length ? parts.join('; ') : t('diagnostics.issues')
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    data.value = await fetchDiagnostics()
  } catch (err) {
    error.value = err?.message || t('diagnostics.loadFailed')
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="k-stack">
    <div class="k-row k-row--between">
      <StatusBadge
        v-if="data"
        :state="data.overall_ok ? 'ok' : 'warning'"
        :label="data.overall_ok ? 'OK' : t('diagnostics.issues')"
      />
      <button type="button" class="k-btn k-btn--compact" :disabled="loading" @click="load">
        {{ t('common.refresh') }}
      </button>
    </div>

    <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>
    <div v-if="loading" class="k-muted">{{ t('common.loading') }}</div>

    <template v-else-if="data">
      <div class="k-grid-2">
        <div class="k-card k-card-body k-stack--sm">
          <span class="k-field-label">{{ t('diagnostics.os') }}</span>
          <span class="k-mono">{{ data.os_name || '—' }}</span>
        </div>
        <div class="k-card k-card-body k-stack--sm">
          <span class="k-field-label">{{ t('diagnostics.freeSpace') }}</span>
          <span class="k-mono">{{ formatBytes(data.app_data_free_bytes) }}</span>
        </div>
        <div class="k-card k-card-body k-stack--sm">
          <span class="k-field-label">{{ t('diagnostics.dataFolder') }}</span>
          <span class="k-mono k-truncate" :title="data.app_data_dir">{{ data.app_data_dir || '—' }}</span>
        </div>
        <div class="k-card k-card-body k-stack--sm">
          <span class="k-field-label">rclone</span>
          <span class="k-mono">{{ formatRclone(data.rclone) }}</span>
        </div>
      </div>

      <table v-if="Array.isArray(data.profiles) && data.profiles.length > 0" class="k-table">
        <thead>
          <tr>
            <th>{{ t('diagnostics.profile') }}</th>
            <th>{{ t('diagnostics.keyStorage') }}</th>
            <th>.kasumiignore</th>
            <th>{{ t('diagnostics.health') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in data.profiles" :key="p.profile?.name || p.detail">
            <td class="k-mono">{{ p.profile?.name || '—' }}</td>
            <td class="k-mono">{{ p.profile?.key_storage || '—' }}</td>
            <td class="k-mono">{{ formatIgnoreStatus(p) }}</td>
            <td>{{ formatHealth(p) }}</td>
          </tr>
        </tbody>
      </table>
    </template>
  </div>
</template>
