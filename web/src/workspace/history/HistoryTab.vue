<script setup>
import { computed, onUnmounted, ref, watch } from 'vue'
import FileTypeIcon from '../../components/FileTypeIcon.vue'
import StatusBadge from '../../components/StatusBadge.vue'
import {
  buildRemoteDownloadUrl,
  cachedRemoteDiff,
  cachedRemoteReading,
  fetchRemoteCommits,
  fetchRemoteDiff,
} from '../../api/remote.js'
import { useProfileActivity } from '../../composables/useProfileActivity.js'
import { formatBytes, formatTimestamp, friendlyBusyError, shortHash, translateWithFallback } from '../../utils/format.js'
import { t } from '../../i18n/index.js'
import { classifyFile } from '../files/fileTypes.js'
import TextDiffViewer from './TextDiffViewer.vue'

const props = defineProps({
  profile: { type: String, required: true },
})

const emit = defineEmits(['restore-commit', 'browse-commit'])
const { serverBusy, blockedReason } = useProfileActivity(() => props.profile)

const commits = ref([])
const selectedIndex = ref(0)
const compareFrom = ref('')
const compareTarget = ref('')
const changes = ref([])
const selectedFile = ref('')
const fileDiff = ref(null)
const selectedChangeKind = ref('')
const loading = ref(false)
const loadingDiff = ref(false)
const loadingFileDiff = ref(false)
const diffLoaded = ref(false)
const error = ref('')
let historyRequest
let diffRequest
let fileDiffRequest

const activeCommit = computed(() => commits.value[selectedIndex.value] || null)
const activeCommitId = computed(
  () => activeCommit.value?.id || activeCommit.value?.commit_id || ''
)
const defaultParentId = computed(() => activeCommit.value?.parent_ids?.[0] || '')
const commitById = computed(() => {
  const map = new Map()
  for (const c of commits.value) {
    const id = c.id || c.commit_id
    if (id) map.set(id, c)
  }
  return map
})

const previousCommit = computed(() => {
  if (defaultParentId.value && commitById.value.has(defaultParentId.value)) {
    return commitById.value.get(defaultParentId.value)
  }
  return commits.value[selectedIndex.value + 1] || null
})

const sizeDeltaText = computed(() => {
  const cur = activeCommit.value?.total_bytes
  const prev = previousCommit.value?.total_bytes
  if (typeof cur !== 'number' || typeof prev !== 'number') return ''
  const diff = cur - prev
  if (diff === 0) return t('history.noDelta')
  return (diff > 0 ? '+' : '-') + formatBytes(Math.abs(diff))
})

const itemDeltaText = computed(() => {
  const cur = activeCommit.value?.entry_count
  const prev = previousCommit.value?.entry_count
  if (typeof cur !== 'number' || typeof prev !== 'number') return ''
  const diff = cur - prev
  if (diff === 0) return t('history.noDelta')
  return (diff > 0 ? '+' : '') + String(diff)
})

const compareCandidates = computed(() => {
  const active = activeCommitId.value
  return commits.value.filter((c) => (c.id || c.commit_id) !== active)
})

const changeStats = computed(() => {
  let added = 0
  let modified = 0
  let deleted = 0
  for (const ch of changes.value) {
    const k = ch.kind || ch.change
    if (k === 'added') added++
    else if (k === 'deleted' || k === 'removed') deleted++
    else modified++
  }
  return { added, modified, deleted }
})

const selectedFileClassification = computed(() => classifyFile(selectedFile.value))
const isSelectedImage = computed(() => selectedFileClassification.value.previewKind === 'image')

function formatOperationLabel(op) {
  if (!op || op === 'unknown') return '—'
  return translateWithFallback(t, 'operation.' + op, op)
}

function resetDiffState() {
  diffRequest?.abort()
  fileDiffRequest?.abort()
  fileDiff.value = null
  selectedFile.value = ''
  selectedChangeKind.value = ''
  compareFrom.value = ''
  changes.value = []
  diffLoaded.value = false
  loadingDiff.value = false
  loadingFileDiff.value = false
}

function syncCachedTreeDiff() {
  const baseId = compareTarget.value || defaultParentId.value
  if (!props.profile || !baseId || !activeCommitId.value) return false
  const cached = cachedRemoteDiff(props.profile, {
    from: baseId,
    to: activeCommitId.value,
  })
  if (!cached?.fresh) return false
  compareFrom.value = baseId
  changes.value = Array.isArray(cached.value?.changes) ? cached.value.changes : []
  diffLoaded.value = true
  return true
}

async function loadHistory(refresh = false) {
  if (!props.profile) return
  historyRequest?.abort()
  error.value = ''

  if (!refresh) {
    const cached = cachedRemoteReading(props.profile, 'commits')
    if (cached) {
      const previousId = activeCommitId.value
      commits.value = Array.isArray(cached.value?.commits) ? cached.value.commits : []
      if (commits.value.length > 0) {
        const idx = previousId
          ? Math.max(0, commits.value.findIndex((entry) => (entry.id || entry.commit_id) === previousId))
          : 0
        selectedIndex.value = idx
        if (!compareTarget.value) compareTarget.value = defaultParentId.value
        syncCachedTreeDiff()
      }
      if (cached.fresh) {
        loading.value = false
        return
      }
    }
  }

  if (serverBusy.value) {
    loading.value = false
    return
  }

  historyRequest = new AbortController()
  const { signal } = historyRequest
  loading.value = commits.value.length === 0
  try {
    const previousId = activeCommitId.value
    const res = await fetchRemoteCommits(props.profile, signal, { refresh })
    if (signal.aborted) return
    commits.value = Array.isArray(res?.commits) ? res.commits : []
    selectedIndex.value = previousId
      ? Math.max(0, commits.value.findIndex((entry) => (entry.id || entry.commit_id) === previousId))
      : 0
    if (refresh || !commits.value.some((entry) => (entry.id || entry.commit_id) === previousId)) {
      resetDiffState()
      compareTarget.value = defaultParentId.value
      syncCachedTreeDiff()
    } else if (!compareTarget.value) {
      compareTarget.value = defaultParentId.value
    }
  } catch (err) {
    if (!signal.aborted) error.value = err.message
  } finally {
    if (!signal.aborted) loading.value = false
  }
}

async function loadDiffForSelected() {
  const targetFrom = compareTarget.value || defaultParentId.value
  resetDiffState()
  if (!activeCommitId.value || !targetFrom || serverBusy.value) return
  compareFrom.value = targetFrom
  diffRequest = new AbortController()
  const { signal } = diffRequest
  loadingDiff.value = true
  try {
    const res = await fetchRemoteDiff(props.profile, {
      from: targetFrom,
      to: activeCommitId.value,
      signal,
    })
    if (!signal.aborted) {
      changes.value = Array.isArray(res?.changes) ? res.changes : []
      diffLoaded.value = true
    }
  } catch (err) {
    if (!signal.aborted) error.value = err.message
  } finally {
    if (!signal.aborted) loadingDiff.value = false
  }
}

function selectCommitById(commitId) {
  const idx = commits.value.findIndex((c) => (c.id || c.commit_id) === commitId)
  if (idx >= 0) selectCommit(idx)
}

function selectCommit(index) {
  selectedIndex.value = index
  resetDiffState()
  compareTarget.value = defaultParentId.value
  syncCachedTreeDiff()
}

async function inspectPath(ch) {
  const path = ch?.path
  if (!path || serverBusy.value || !compareFrom.value || !activeCommitId.value) return
  fileDiffRequest?.abort()
  selectedFile.value = path
  selectedChangeKind.value = ch.kind || ch.change || 'modified'
  fileDiff.value = null
  if (classifyFile(path).previewKind === 'image') {
    loadingFileDiff.value = false
    return
  }
  fileDiffRequest = new AbortController()
  const { signal } = fileDiffRequest
  loadingFileDiff.value = true
  try {
    const diff = await fetchRemoteDiff(props.profile, {
      from: compareFrom.value,
      to: activeCommitId.value,
      path,
      signal,
    })
    if (!signal.aborted) fileDiff.value = diff
  } catch (err) {
    if (!signal.aborted) error.value = err.message
  } finally {
    if (!signal.aborted) loadingFileDiff.value = false
  }
}

watch(() => props.profile, () => {
  commits.value = []
  selectedIndex.value = 0
  compareTarget.value = ''
  resetDiffState()
  loadHistory()
}, { immediate: true })

watch(serverBusy, (busy, wasBusy) => {
  if (wasBusy && !busy) loadHistory(true)
})

onUnmounted(() => {
  historyRequest?.abort()
  diffRequest?.abort()
  fileDiffRequest?.abort()
})
</script>

<template>
  <div class="k-workspace-body">
    <aside class="k-sidebar-pane">
      <div class="k-sidebar-head">
        <div class="k-row k-row--between">
          <strong class="k-text-sm">{{ t('history.title') }} ({{ commits.length }})</strong>
          <button
            type="button"
            class="k-btn k-btn--ghost k-btn--compact"
            :disabled="loading || serverBusy"
            @click="loadHistory(true)"
          >
            {{ t('common.refresh') }}
          </button>
        </div>
      </div>

      <div class="k-sidebar-scroll">
        <div v-if="serverBusy" class="k-alert k-alert--info" role="status">{{ blockedReason }}</div>
        <div v-else-if="loading" class="k-muted k-card-body--compact">{{ t('common.loading') }}</div>
        <div v-else-if="commits.length === 0" class="k-muted k-card-body--compact">
          {{ t('common.none') }}
        </div>

        <button
          v-for="(c, idx) in commits"
          :key="c.id || c.commit_id"
          type="button"
          class="k-list-row"
          :class="{ 'k-list-row--active': idx === selectedIndex }"
          @click="selectCommit(idx)"
        >
          <div class="k-min-w-0 k-stack--sm">
            <div class="k-row k-row--between">
              <strong class="k-mono">{{ shortHash(c.id || c.commit_id, 10) }}</strong>
              <span class="k-faint k-mono k-text-xs">v{{ c.height ?? '?' }}</span>
            </div>
            <span class="k-faint k-text-xs">
              {{ formatTimestamp(c.created_at_unix ?? c.created_at) }}
            </span>
            <span v-if="c.authorship?.machine_name || typeof c.entry_count === 'number'" class="k-muted k-text-xs k-truncate">
              <template v-if="typeof c.entry_count === 'number'">{{ c.entry_count }} {{ t('files.itemsUnit') }}</template>
              <template v-if="typeof c.entry_count === 'number' && c.authorship?.machine_name"> · </template>
              <template v-if="c.authorship?.machine_name">{{ c.authorship.machine_name }}</template>
            </span>
          </div>
        </button>
      </div>
    </aside>

    <main class="k-main-pane">
      <div class="k-readable-canvas">
        <div v-if="error" class="k-alert k-alert--error">{{ friendlyBusyError(null, t, error) }}</div>

        <div v-if="!activeCommit" class="k-card k-card-body k-muted">
          {{ t('history.selectCommit') }}
        </div>

        <template v-else>
          <section class="k-card k-card-body k-stack">
            <div class="k-row k-row--between k-row--wrap">
              <div class="k-stack--sm">
                <div class="k-row k-row--wrap">
                  <strong>v{{ activeCommit.height ?? '?' }}</strong>
                  <code class="k-mono k-muted">{{ shortHash(activeCommitId, 16) }}</code>
                  <StatusBadge v-if="activeCommit.logical_head" state="ok" :label="t('history.currentHead')" />
                  <StatusBadge v-if="activeCommit.physically_marked || activeCommit.ancestral_marked" state="info" :label="t('history.protectedBase')" />
                </div>
                <div class="k-muted k-text-sm">
                  {{ formatTimestamp(activeCommit.created_at_unix ?? activeCommit.created_at) }}
                  <span v-if="activeCommit.authorship?.machine_name">
                    · {{ activeCommit.authorship.machine_name }}
                  </span>
                </div>
              </div>
              <div class="k-row k-row--wrap">
                <button
                  type="button"
                  class="k-btn k-btn--compact"
                  @click="emit('browse-commit', activeCommitId)"
                >
                  {{ t('history.exploreFiles') }}
                </button>
                <button
                  type="button"
                  class="k-btn k-btn--primary k-btn--compact"
                  @click="emit('restore-commit', activeCommitId)"
                >
                  {{ t('history.restoreSnapshot') }}
                </button>
              </div>
            </div>

            <div class="k-grid-3">
              <div class="k-card k-card-body k-stack--sm">
                <span class="k-field-label">{{ t('history.snapshotSize') }}</span>
                <strong class="k-mono">
                  {{ typeof activeCommit.total_bytes === 'number' ? formatBytes(activeCommit.total_bytes) : '—' }}
                </strong>
                <span v-if="sizeDeltaText" class="k-faint k-text-xs">{{ sizeDeltaText }}</span>
              </div>
              <div class="k-card k-card-body k-stack--sm">
                <span class="k-field-label">{{ t('history.snapshotItems') }}</span>
                <strong class="k-mono">
                  {{ typeof activeCommit.entry_count === 'number' ? activeCommit.entry_count : '—' }}
                </strong>
                <span v-if="itemDeltaText" class="k-faint k-text-xs">{{ itemDeltaText }}</span>
              </div>
              <div class="k-card k-card-body k-stack--sm">
                <span class="k-field-label">{{ t('history.originDevice') }}</span>
                <strong>{{ formatOperationLabel(activeCommit.authorship?.operation) }}</strong>
                <span class="k-faint k-text-xs">{{ activeCommit.authorship?.machine_name || '—' }}</span>
              </div>
            </div>

            <div v-if="compareCandidates.length > 0" class="k-row k-row--between k-row--wrap">
              <label class="k-row k-row--sm">
                <span class="k-field-label">{{ t('history.compareWith') }}</span>
                <select v-model="compareTarget" class="k-select k-select--compact" @change="resetDiffState(); syncCachedTreeDiff()">
                  <option v-for="cand in compareCandidates" :key="cand.id || cand.commit_id" :value="cand.id || cand.commit_id">
                    v{{ cand.height ?? '?' }} · {{ shortHash(cand.id || cand.commit_id, 10) }}
                  </option>
                </select>
              </label>
              <button
                type="button"
                class="k-btn k-btn--compact"
                :disabled="loadingDiff || serverBusy || !compareTarget"
                @click="loadDiffForSelected()"
              >
                {{ loadingDiff ? t('common.loading') : t('history.viewChanges') }}
              </button>
            </div>

            <details class="k-disclosure">
              <summary>{{ t('history.technicalDetails') }}</summary>
              <div class="k-disclosure-body k-stack--sm k-text-sm">
                <div><span class="k-muted">{{ t('history.commitId') }}:</span> <code class="k-mono">{{ activeCommitId }}</code></div>
                <div v-if="activeCommit.root_hash"><span class="k-muted">{{ t('history.rootHash') }}:</span> <code class="k-mono">{{ activeCommit.root_hash }}</code></div>
                <div v-if="activeCommit.parent_ids?.length" class="k-row k-row--wrap">
                  <span class="k-muted">{{ t('history.parents') }}:</span>
                  <button
                    v-for="pid in activeCommit.parent_ids"
                    :key="pid"
                    type="button"
                    class="k-btn k-btn--ghost k-btn--compact k-mono"
                    @click="selectCommitById(pid)"
                  >
                    {{ shortHash(pid, 12) }}
                  </button>
                </div>
              </div>
            </details>
          </section>

          <section v-if="diffLoaded && changes.length === 0" class="k-card k-card-body k-muted">
            {{ t('history.noChanges') }}
          </section>

          <section v-if="changes.length > 0" class="k-card">
            <header class="k-card-header">
              <strong>{{ t('history.changedFiles', { count: changes.length }) }}</strong>
              <span class="k-faint k-text-xs">
                +{{ changeStats.added }} · ~{{ changeStats.modified }} · -{{ changeStats.deleted }}
              </span>
            </header>
            <div class="k-card-body k-card-body--compact k-scroll-sm">
              <button
                v-for="ch in changes"
                :key="ch.path"
                type="button"
                class="k-list-row"
                :disabled="serverBusy"
                :class="{ 'k-list-row--active': ch.path === selectedFile }"
                @click="inspectPath(ch)"
              >
                <span class="k-row k-min-w-0">
                  <FileTypeIcon :category="classifyFile(ch.path).category" size="sm" />
                  <span class="k-mono k-truncate">{{ ch.path }}</span>
                </span>
                <span class="k-faint k-mono k-text-xs">{{ ch.kind || ch.change }}</span>
              </button>
            </div>
          </section>

          <div v-if="loadingFileDiff" class="k-muted">{{ t('common.loading') }}</div>

          <section v-else-if="selectedFile && isSelectedImage" class="k-card k-card-body k-stack">
            <div class="k-grid-2">
              <div v-if="selectedChangeKind !== 'added' && compareFrom" class="k-stack--sm">
                <span class="k-field-label">{{ t('history.before') }} ({{ shortHash(compareFrom, 8) }})</span>
                <img
                  :key="`from:${compareFrom}:${selectedFile}`"
                  :src="buildRemoteDownloadUrl(profile, { path: selectedFile, commit: compareFrom })"
                  :alt="selectedFile"
                  class="k-preview-media"
                />
              </div>
              <div v-if="selectedChangeKind !== 'deleted' && selectedChangeKind !== 'removed'" class="k-stack--sm">
                <span class="k-field-label">{{ t('history.after') }} ({{ shortHash(activeCommitId, 8) }})</span>
                <img
                  :key="`to:${activeCommitId}:${selectedFile}`"
                  :src="buildRemoteDownloadUrl(profile, { path: selectedFile, commit: activeCommitId })"
                  :alt="selectedFile"
                  class="k-preview-media"
                />
              </div>
            </div>
          </section>

          <TextDiffViewer
            v-else-if="fileDiff"
            :left-text="fileDiff.from?.text ?? ''"
            :right-text="fileDiff.to?.text ?? ''"
            :left-label="`${selectedFile} (${shortHash(compareFrom, 8)})`"
            :right-label="`${selectedFile} (${shortHash(activeCommitId, 8)})`"
          />
        </template>
      </div>
    </main>
  </div>
</template>
