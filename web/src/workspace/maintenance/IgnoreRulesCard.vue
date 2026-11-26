<script setup>
import { onUnmounted, ref, watch } from 'vue'
import ConfirmModal from '../../components/ConfirmModal.vue'
import StatusBadge from '../../components/StatusBadge.vue'
import { checkIgnorePaths, initIgnoreFile } from '../../api/profiles.js'
import { pushToast } from '../../composables/useToasts.js'
import { t } from '../../i18n/index.js'

const props = defineProps({
  profile: { type: String, required: true },
  disabled: Boolean,
})

const pathsInput = ref('build/app.exe\nnode_modules/pkg/index.js\nsrc/main.cpp\ndesktop.ini')
const results = ref([])
const ignoreFilePresent = ref(null)
const ignoreFilePath = ref('')
const preset = ref('default')
const initPreview = ref('')
const busy = ref(false)
const error = ref('')
const confirmOverwrite = ref(false)
let activeRequest = null
let requestToken = 0

function abortActiveRequest() {
  requestToken += 1
  activeRequest?.abort()
  activeRequest = null
}

watch(() => props.profile, () => {
  abortActiveRequest()
  busy.value = false
  results.value = []
  ignoreFilePresent.value = null
  ignoreFilePath.value = ''
  initPreview.value = ''
  error.value = ''
  confirmOverwrite.value = false
})

onUnmounted(abortActiveRequest)

function normalizeInputPaths(rawText) {
  return rawText
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/^["']|["']$/g, '').trim())
    .map((line) => line.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/^\/+/, ''))
    .filter(Boolean)
}

function ruleDisplay(item) {
  if (item.reserved_internal) return t('ignore.reservedInternal')
  if (item.matched_rule) {
    return item.rule_line > 0 ? `L${item.rule_line}: ${item.rule_text}` : (item.rule_text || '—')
  }
  return item.rule || item.pattern || '—'
}

function displayPath(item) {
  const path = item.logical_path || item.path || item.input_path || ''
  return item.is_directory && !path.endsWith('/') ? `${path}/` : path
}

async function runCheck() {
  const paths = normalizeInputPaths(pathsInput.value)
  if (paths.length === 0) return
  abortActiveRequest()
  const controller = new AbortController()
  activeRequest = controller
  const token = requestToken
  const targetProfile = props.profile
  busy.value = true
  error.value = ''
  try {
    const res = await checkIgnorePaths(targetProfile, paths, { signal: controller.signal })
    if (controller.signal.aborted || token !== requestToken || props.profile !== targetProfile) return
    results.value = Array.isArray(res?.items)
      ? res.items
      : Array.isArray(res?.results)
        ? res.results
        : []
    if (typeof res?.ignore_file_present === 'boolean') {
      ignoreFilePresent.value = res.ignore_file_present
    }
    if (res?.ignore_file) {
      ignoreFilePath.value = res.ignore_file
    }
  } catch (err) {
    if (!controller.signal.aborted && token === requestToken && props.profile === targetProfile) {
      error.value = err?.message || t('ignore.checkFailed')
    }
  } finally {
    if (token === requestToken && props.profile === targetProfile) {
      busy.value = false
    }
  }
}

async function runInit(dryRun, force = false) {
  if (busy.value || props.disabled) return
  abortActiveRequest()
  const controller = new AbortController()
  activeRequest = controller
  const token = requestToken
  const targetProfile = props.profile
  busy.value = true
  error.value = ''
  try {
    const res = await initIgnoreFile(targetProfile, {
      preset: preset.value,
      dryRun,
      force,
      signal: controller.signal,
    })
    if (controller.signal.aborted || token !== requestToken || props.profile !== targetProfile) return
    initPreview.value = res?.content || JSON.stringify(res, null, 2)
    if (res?.ignore_file) ignoreFilePath.value = res.ignore_file
    if (!dryRun) {
      ignoreFilePresent.value = true
      confirmOverwrite.value = false
      pushToast(t('ignore.written', { preset: preset.value }), 'ok')
    }
  } catch (err) {
    if (controller.signal.aborted || token !== requestToken || props.profile !== targetProfile) return
    if (!dryRun && !force && err?.status === 409) {
      confirmOverwrite.value = true
    } else {
      error.value = err?.message || t('ignore.initFailed')
    }
  } finally {
    if (token === requestToken && props.profile === targetProfile) {
      busy.value = false
    }
  }
}

function requestWrite() {
  if (ignoreFilePresent.value === true) {
    confirmOverwrite.value = true
    return
  }
  runInit(false, false)
}
</script>

<template>
  <details class="k-disclosure">
    <summary>{{ t('maintenance.ignoreTitle') }}</summary>
    <div class="k-disclosure-body k-stack">
      <div v-if="error" class="k-alert k-alert--error" role="alert">{{ error }}</div>

      <div v-if="ignoreFilePresent !== null" class="k-row k-row--between k-row--wrap k-text-xs k-muted">
        <span>
          {{ t(ignoreFilePresent ? 'ignore.filePresent' : 'ignore.fileMissing') }}
          <code v-if="ignoreFilePath" class="k-mono">{{ ignoreFilePath }}</code>
        </span>
      </div>

      <div class="k-field">
        <label for="kasumi-ignore-paths" class="k-field-label">{{ t('ignore.inputLabel') }}</label>
        <textarea id="kasumi-ignore-paths" v-model="pathsInput" class="k-textarea" rows="3" />
      </div>

      <div class="k-row k-row--wrap">
        <button type="button" class="k-btn k-btn--primary k-btn--compact" :disabled="busy" @click="runCheck">
          {{ t('ignore.testButton') }}
        </button>
        <select v-model="preset" class="k-select k-select--compact" :aria-label="t('ignore.presetLabel')">
          <option value="default">{{ t('ignore.preset.default') }}</option>
          <option value="dev">{{ t('ignore.preset.dev') }}</option>
          <option value="office">{{ t('ignore.preset.office') }}</option>
          <option value="minimal">{{ t('ignore.preset.minimal') }}</option>
        </select>
        <button type="button" class="k-btn k-btn--compact" :disabled="busy || disabled" @click="runInit(true, false)">
          {{ t('ignore.previewPreset') }}
        </button>
        <button type="button" class="k-btn k-btn--compact" :disabled="busy || disabled" @click="requestWrite">
          {{ t('ignore.writeButton') }}
        </button>
      </div>

      <div v-if="results.length > 0" class="k-table-scroll">
        <table class="k-data-table">
          <thead>
            <tr>
              <th>{{ t('ignore.colPath') }}</th>
              <th>{{ t('ignore.colStatus') }}</th>
              <th>{{ t('ignore.colRule') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(item, idx) in results" :key="`${displayPath(item)}:${idx}`">
              <td class="k-mono">{{ displayPath(item) }}</td>
              <td><StatusBadge :state="item.disposition || 'managed'" /></td>
              <td class="k-mono k-muted">{{ ruleDisplay(item) }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="initPreview" class="k-stack--sm">
        <span class="k-field-label">{{ t('ignore.previewHeading', { preset }) }}</span>
        <pre class="k-code-block k-scroll-sm">{{ initPreview }}</pre>
      </div>
    </div>
    <ConfirmModal
      :open="confirmOverwrite"
      :busy="busy"
      :title="t('ignore.overwriteTitle')"
      :message="t('ignore.overwriteBody')"
      danger
      @close="confirmOverwrite = false"
      @confirm="runInit(false, true)"
    />
  </details>
</template>
