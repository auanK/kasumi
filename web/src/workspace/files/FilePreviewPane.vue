<script setup>
import { computed, onBeforeUnmount, onDeactivated, onUnmounted, ref, watch } from 'vue'
import FileTypeIcon from '../../components/FileTypeIcon.vue'
import {
  buildLocalDownloadUrl,
  buildLocalThumbnailUrl,
  buildRemoteDownloadUrl,
  buildRemoteThumbnailUrl,
  fetchRemoteFileLog,
  readFileChunk,
} from '../../api/remote.js'
import { formatBytes, formatTimestamp, friendlyBusyError, shortHash } from '../../utils/format.js'
import { t } from '../../i18n/index.js'
import { classifyFile } from './fileTypes.js'

const props = defineProps({
  profile: { type: String, required: true },
  path: { type: String, default: '' },
  commit: { type: String, default: '' },
  entry: { type: Object, default: null },
  local: Boolean,
  disabled: Boolean,
})

const emit = defineEmits(['select-commit'])

const fileLog = ref([])
const logLoading = ref(false)
const logLoaded = ref(false)
const logError = ref('')
let logRequest
const textContent = ref('')
const textTruncated = ref(false)
const loading = ref(false)
const error = ref('')
const mediaState = ref('idle')
const mediaEl = ref(null)
const thumbFallback = ref(false)
const retryCount = ref(0)
let textRequest
let textOffset = 0
let decoder

const downloadUrl = computed(() =>
  props.local ? buildLocalDownloadUrl(props.profile, props.path)
    : buildRemoteDownloadUrl(props.profile, { path: props.path, commit: props.commit })
)

const fileClassification = computed(() => classifyFile(props.path))
const fileCategory = computed(() => fileClassification.value.category)
const previewKind = computed(() => fileClassification.value.previewKind)

const usingScaledImage = computed(() => {
  if (!props.path || thumbFallback.value) return false
  const info = fileClassification.value
  if (info.previewKind !== 'image' || !info.isThumbnailable || info.ext === 'svg' || info.ext === 'gif') {
    return false
  }
  if (props.local) {
    return (props.entry?.size || 0) > 512 * 1024
  }
  return Boolean(props.entry?.logical_hash) && (props.entry?.size || 0) > 512 * 1024
})

const previewMediaUrl = computed(() => {
  if (!props.path) return ''
  if (usingScaledImage.value) {
    return props.local
      ? buildLocalThumbnailUrl(props.profile, props.path, 1280)
      : buildRemoteThumbnailUrl(props.profile, { path: props.path, hash: props.entry.logical_hash, size: 1280 })
  }
  return downloadUrl.value
})

const videoPosterUrl = computed(() => {
  if (!props.path || previewKind.value !== 'video') return ''
  if (props.local) {
    return buildLocalThumbnailUrl(props.profile, props.path, 640)
  }
  return props.entry?.logical_hash
    ? buildRemoteThumbnailUrl(props.profile, { path: props.path, hash: props.entry.logical_hash, size: 640 })
    : ''
})

function onImageError() {
  if (usingScaledImage.value) {
    thumbFallback.value = true
    mediaState.value = 'loading'
    return
  }
  mediaState.value = 'error'
}

function retryPreview() {
  thumbFallback.value = false
  retryCount.value++
  mediaState.value = 'loading'
}

function releaseMediaElement() {
  const el = mediaEl.value
  if (el && (el.tagName === 'VIDEO' || el.tagName === 'AUDIO')) {
    el.pause()
    el.removeAttribute('src')
    el.load()
  }
}

watch(previewMediaUrl, () => {
  releaseMediaElement()
}, { flush: 'sync' })

watch(downloadUrl, () => {
  logRequest?.abort()
  fileLog.value = []
  logLoading.value = false
  logLoaded.value = false
  logError.value = ''
  textRequest?.abort()
  error.value = ''
  textContent.value = ''
  textTruncated.value = false
  textOffset = 0
  thumbFallback.value = false
  retryCount.value = 0
  decoder = new TextDecoder()
  loading.value = false
  mediaState.value = ['image', 'video', 'audio'].includes(previewKind.value) ? 'loading' : 'idle'
  if (previewKind.value === 'text' && (props.local || props.entry?.size !== 0)) loadText()
}, { immediate: true })

function cleanupPreview() {
  releaseMediaElement()
  logRequest?.abort()
  textRequest?.abort()
}

onDeactivated(cleanupPreview)
onBeforeUnmount(releaseMediaElement)

async function loadText() {
  if (loading.value) return
  textRequest = new AbortController()
  const { signal } = textRequest
  loading.value = true
  error.value = ''
  try {
    const { bytes, done } = await readFileChunk(props.profile, downloadUrl.value, textOffset, 256 * 1024, signal)
    if (!signal.aborted) {
      textOffset += bytes.length
      textContent.value += decoder.decode(bytes, { stream: !done })
      textTruncated.value = !done
    }
  } catch (err) {
    if (!signal.aborted) error.value = err.message
  } finally {
    if (!signal.aborted) loading.value = false
  }
}

async function loadLog() {
  if (loading.value || logLoading.value || props.disabled) return
  logRequest = new AbortController()
  const { signal } = logRequest
  logLoading.value = true
  logError.value = ''
  try {
    const result = await fetchRemoteFileLog(props.profile, props.path, signal)
    if (signal.aborted) return
    fileLog.value = result.entries || []
    logLoaded.value = true
  } catch (err) {
    if (!signal.aborted) logError.value = err.message
  } finally {
    if (!signal.aborted) logLoading.value = false
  }
}
onUnmounted(() => {
  logRequest?.abort()
  textRequest?.abort()
})
</script>

<template>
  <div class="k-readable-canvas">
    <div v-if="!path" class="k-card k-card-body k-muted">
      {{ t('files.selectPrompt') }}
    </div>

    <template v-else>
      <div class="k-row k-row--between k-row--wrap">
        <div class="k-row k-min-w-0">
          <FileTypeIcon :category="fileCategory" size="sm" />
          <div class="k-min-w-0">
            <strong class="k-mono">{{ path }}</strong>
            <div v-if="entry" class="k-faint k-text-sm">
              {{ local ? t('files.mappedSize', { size: formatBytes(entry.size) }) : formatBytes(entry.size) }}
              <span v-if="commit" class="k-mono">· {{ shortHash(commit, 10) }}</span>
            </div>
          </div>
        </div>

        <a
          :href="downloadUrl"
          download
          rel="noopener noreferrer"
          class="k-btn k-btn--primary k-btn--compact"
        >
          {{ t('common.download') }}
        </a>
      </div>

      <div v-if="error" class="k-alert k-alert--error" role="alert">{{ friendlyBusyError(null, t, error) }}</div>
      <div v-if="loading && !textContent" class="k-muted">{{ t('common.loading') }}</div>

      <template v-else>
        <template v-if="previewKind === 'image'">
          <div v-if="mediaState === 'error'" class="k-alert k-alert--error k-row k-row--between k-row--wrap" role="alert">
            <span>{{ t('files.previewFailed') }}</span>
            <button type="button" class="k-btn k-btn--compact" @click="retryPreview">{{ t('common.retry') }}</button>
          </div>
          <div v-else-if="mediaState === 'loading'" class="k-muted" role="status">
            {{ t('common.loading') }}
          </div>
          <img
            v-if="mediaState !== 'error'"
            :key="`${previewMediaUrl}:${retryCount}`"
            ref="mediaEl"
            :src="previewMediaUrl"
            :alt="path"
            decoding="async"
            class="k-preview-media"
            :class="{ 'k-preview-media--loading': mediaState !== 'loaded' }"
            @load="mediaState = 'loaded'"
            @error="onImageError"
          />
        </template>

        <template v-else-if="previewKind === 'video'">
          <div v-if="mediaState === 'error'" class="k-alert k-alert--error k-row k-row--between k-row--wrap" role="alert">
            <span>{{ t('files.previewFailed') }}</span>
            <button type="button" class="k-btn k-btn--compact" @click="retryPreview">{{ t('common.retry') }}</button>
          </div>
          <video
            v-else
            :key="`${previewMediaUrl}:${retryCount}`"
            ref="mediaEl"
            :src="previewMediaUrl"
            :poster="videoPosterUrl || undefined"
            controls
            preload="metadata"
            class="k-preview-media"
            @loadeddata="mediaState = 'loaded'"
            @error="mediaState = 'error'"
          />
        </template>

        <template v-else-if="previewKind === 'audio'">
          <div v-if="mediaState === 'error'" class="k-alert k-alert--error k-row k-row--between k-row--wrap" role="alert">
            <span>{{ t('files.previewFailed') }}</span>
            <button type="button" class="k-btn k-btn--compact" @click="retryPreview">{{ t('common.retry') }}</button>
          </div>
          <audio
            v-else
            :key="`${previewMediaUrl}:${retryCount}`"
            ref="mediaEl"
            :src="previewMediaUrl"
            controls
            preload="metadata"
            class="k-w-full"
            @loadeddata="mediaState = 'loaded'"
            @error="mediaState = 'error'"
          />
        </template>

        <div v-else-if="previewKind === 'pdf'" class="k-alert k-alert--info">
          <a :href="downloadUrl" target="_blank" rel="noopener noreferrer">{{ t('files.openPdf') }} ↗</a>
        </div>

        <div v-else-if="previewKind === 'text'" class="k-stack">
          <pre class="k-code-block">{{ textContent }}</pre>
          <div v-if="textTruncated || error">
            <button type="button" class="k-btn k-btn--compact" :disabled="loading" @click="loadText">
              {{ t(loading ? 'common.loading' : 'files.readMore') }}
            </button>
          </div>
        </div>

        <div v-else-if="previewKind === 'binary'" class="k-alert k-alert--info">{{ t('files.binaryNotice') }}</div>
      </template>
      <details v-if="!local" :key="path" class="k-disclosure">
          <summary>{{ t('files.historyTitle') }}</summary>
          <div class="k-disclosure-body k-stack--sm">
            <div v-if="logError" class="k-alert k-alert--error" role="alert">{{ friendlyBusyError(null, t, logError) }}</div>
            <button v-if="!logLoaded" type="button" class="k-btn k-btn--compact"
              :disabled="loading || logLoading || disabled" @click="loadLog">
              {{ t(logLoading ? 'common.loading' : 'files.loadVersions') }}
            </button>
            <p v-else-if="fileLog.length === 0" class="k-muted">{{ t('common.none') }}</p>
            <button
              v-for="item in fileLog"
              :key="item.commit_id || item.id"
              type="button"
              class="k-list-row"
              @click="emit('select-commit', item.commit_id || item.id)"
            >
              <span class="k-mono">
                {{ shortHash(item.commit_id || item.id, 10) }} · {{ item.change || item.kind || 'commit' }}
              </span>
              <span class="k-faint k-mono k-text-sm">
                {{ formatTimestamp(item.created_at_unix ?? item.created_at) }}
              </span>
            </button>
          </div>
      </details>
    </template>
  </div>
</template>
