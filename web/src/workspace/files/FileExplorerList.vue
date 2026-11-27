<script setup>
import { computed, ref, watch } from 'vue'
import FileTypeIcon from '../../components/FileTypeIcon.vue'
import { buildLocalThumbnailUrl, buildRemoteThumbnailUrl } from '../../api/remote.js'
import { t } from '../../i18n/index.js'
import { formatBytes } from '../../utils/format.js'
import { classifyFile, formatFileTypeLabel } from './fileTypes.js'

const props = defineProps({
  items: { type: Array, required: true },
  selectedPath: { type: String, default: '' },
  view: { type: String, required: true },
  profile: { type: String, default: '' },
  local: { type: Boolean, default: false },
  commit: { type: String, default: '' },
  thumbRevisions: { type: Object, default: () => ({}) },
  savedThumbs: { type: Object, default: () => ({}) },
})
const emit = defineEmits(['select-item', 'open-folder'])

const MAX_CONCURRENT_REMOTE_THUMBS = 2
const MAX_KNOWN_LOADED_THUMBS = 512
const remoteLoadedHashes = new Set()

const failedThumbs = ref(new Set())
const settledRemoteKeys = ref(new Set())
watch([() => props.profile, () => props.local, () => props.items, () => props.commit], () => {
  failedThumbs.value = new Set()
  settledRemoteKeys.value = new Set()
})

function thumbKey(item) {
  if (props.local) return item.path
  const rev = item.logical_hash ? (props.thumbRevisions[item.logical_hash] || 0) : 0
  return `${item.path}|${item.logical_hash || ''}|${props.commit || ''}|${rev}`
}

function thumbUrl(item) {
  if (!props.profile) return ''
  if (props.local) {
    return buildLocalThumbnailUrl(props.profile, item.path, 160)
  }
  if (item.logical_hash && props.savedThumbs[item.logical_hash]) {
    return props.savedThumbs[item.logical_hash]
  }
  return item.logical_hash
    ? buildRemoteThumbnailUrl(props.profile, {
        path: item.path,
        hash: item.logical_hash,
        commit: props.commit || undefined,
        size: 160,
        rev: props.thumbRevisions[item.logical_hash] || undefined,
      })
    : ''
}

const rows = computed(() => {
  let inFlight = 0
  return props.items.map((item) => {
    const info = classifyFile(item)
    const url = props.view === 'icons' && info.isThumbnailable ? thumbUrl(item) : ''
    const key = thumbKey(item)
    const failed = failedThumbs.value.has(key)
    let allowed = Boolean(url) && !failed
    if (allowed && !props.local && !url.startsWith('data:')) {
      const hashKey = item.logical_hash ? `${props.profile}|${item.logical_hash}` : ''
      const loaded = Boolean(hashKey) && remoteLoadedHashes.has(hashKey)
      if (!loaded && !settledRemoteKeys.value.has(key)) {
        if (inFlight >= MAX_CONCURRENT_REMOTE_THUMBS) {
          allowed = false
        } else {
          inFlight++
        }
      }
    }
    return {
      item,
      info,
      thumbUrl: url,
      thumbKey: key,
      showThumb: allowed,
    }
  })
})

function recordRemoteLoadedHash(hash) {
  if (!props.profile || !hash) return
  const key = `${props.profile}|${hash}`
  if (remoteLoadedHashes.has(key)) remoteLoadedHashes.delete(key)
  remoteLoadedHashes.add(key)
  while (remoteLoadedHashes.size > MAX_KNOWN_LOADED_THUMBS) {
    const oldest = remoteLoadedHashes.values().next().value
    if (oldest === undefined) break
    remoteLoadedHashes.delete(oldest)
  }
}

function settleRemoteKey(row) {
  if (props.local || settledRemoteKeys.value.has(row.thumbKey)) return
  const next = new Set(settledRemoteKeys.value)
  next.add(row.thumbKey)
  settledRemoteKeys.value = next
}

function markThumbLoaded(row) {
  if (!props.local && row.item.logical_hash) {
    recordRemoteLoadedHash(row.item.logical_hash)
  }
  settleRemoteKey(row)
}

function markThumbFailed(row) {
  const next = new Set(failedThumbs.value)
  next.add(row.thumbKey)
  failedThumbs.value = next
  settleRemoteKey(row)
}

function activate(item, event) {
  if (item.kind === 'directory' && (event.pointerType === 'touch' || event.detail === 0)) {
    emit('open-folder', item.path)
  } else {
    emit('select-item', item)
  }
}
</script>

<template>
  <div class="k-explorer">
    <div v-if="view === 'details' && rows.length" class="k-explorer-columns k-muted k-text-xs" aria-hidden="true">
      <span>{{ t('files.nameColumn') }}</span>
      <span>{{ t('files.typeColumn') }}</span>
      <span>{{ t('files.sizeColumn') }}</span>
    </div>
    <div :class="'k-explorer-' + view">
      <button v-for="row in rows" :key="row.item.path" type="button" class="k-list-row"
        :class="{ 'k-list-row--active': row.item.path === selectedPath }"
        :aria-pressed="row.item.path === selectedPath"
        :title="row.item.path" @click="activate(row.item, $event)"
        @dblclick="row.item.kind === 'directory' && emit('open-folder', row.item.path)">
        <span class="k-explorer-name">
          <span v-if="view === 'icons' && row.showThumb" class="k-explorer-thumb-frame">
            <img
              :src="row.thumbUrl"
              alt=""
              loading="lazy"
              decoding="async"
              class="k-explorer-thumb"
              @load="markThumbLoaded(row)"
              @error="markThumbFailed(row)"
            />
            <span
              v-if="row.info.isVideo"
              class="k-explorer-video-badge"
              aria-hidden="true"
            >▶</span>
          </span>
          <span v-else-if="view === 'icons'" class="k-explorer-icon-slot">
            <FileTypeIcon
              :category="row.info.category"
              size="xl"
            />
          </span>
          <FileTypeIcon
            v-else
            :category="row.info.category"
            size="sm"
          />
          <span class="k-explorer-label" :class="view === 'icons' ? 'k-clamp-2' : 'k-truncate'">{{ row.item.name }}</span>
        </span>
        <template v-if="view === 'details'">
          <span class="k-faint k-text-xs">{{ formatFileTypeLabel(row.item, t) }}</span>
          <span class="k-faint k-mono k-text-xs">{{ row.item.kind === 'file' ? formatBytes(row.item.size) : '—' }}</span>
        </template>
      </button>
    </div>
  </div>
</template>

<style scoped>
.k-explorer { padding: 4px; }

.k-explorer-columns,
.k-explorer-details .k-list-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) clamp(4rem, 16%, 9rem) clamp(4rem, 17%, 8rem);
  align-items: center;
  gap: 6px;
  padding-inline: 8px;
}

.k-explorer-columns {
  padding-block: 6px;
  border-bottom: 1px solid var(--k-border-subtle);
}

.k-explorer-columns > :last-child,
.k-explorer-details .k-list-row > :last-child {
  text-align: right;
}

.k-explorer-name {
  display: flex;
  align-items: center;
  min-width: 0;
  gap: 8px;
}

.k-explorer-icons {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(128px, 1fr));
  gap: 8px;
}

.k-explorer-icons .k-list-row {
  min-width: 0;
  justify-content: center;
  align-items: flex-start;
  padding: 10px 6px;
}

.k-explorer-icons .k-explorer-name {
  flex-direction: column;
  width: 100%;
  gap: 7px;
}

.k-explorer-thumb-frame,
.k-explorer-icon-slot {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 104px;
  height: 76px;
  flex: none;
}

.k-explorer-thumb-frame {
  border-radius: var(--k-radius-xs);
  border: 1px solid var(--k-border-subtle);
  background: var(--k-surface-recessed);
  overflow: hidden;
}

.k-explorer-icon-slot {
  background: transparent;
  border: none;
}

.k-explorer-thumb {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
}

.k-explorer-video-badge {
  position: absolute;
  right: 5px;
  bottom: 5px;
  padding: 1px 5px;
  border-radius: 2px;
  background: rgba(17, 18, 22, 0.82);
  color: var(--k-text);
  font-size: 9px;
  line-height: 1.3;
  pointer-events: none;
}

.k-clamp-2 {
  display: -webkit-box;
  max-width: 100%;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  text-align: center;
  overflow-wrap: anywhere;
  font-size: 12px;
  line-height: 1.3;
}
</style>
