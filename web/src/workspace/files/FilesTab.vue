<script setup>
import { computed, nextTick, onUnmounted, ref, shallowRef, watch } from 'vue'
import {
  cachedLocalTree,
  cachedRemoteReading,
  cachedRemoteTree,
  clearSavedRemoteThumbnails,
  fetchLocalTree,
  fetchRemoteCommits,
  fetchRemoteTree,
  getSavedRemoteThumbnail,
  saveRemoteThumbnail,
} from '../../api/remote.js'
import { useProfileActivity } from '../../composables/useProfileActivity.js'
import { formatTimestamp, friendlyBusyError } from '../../utils/format.js'
import { t } from '../../i18n/index.js'
import FileExplorerList from './FileExplorerList.vue'
import FileFolderTree from './FileFolderTree.vue'
import FilePreviewPane from './FilePreviewPane.vue'
import FileSnapshots from './FileSnapshots.vue'
import RestoreModal from './RestoreModal.vue'
import { indexFileTree, parentFolder } from './fileTree.js'

const props = defineProps({
  profile: { type: String, required: true },
  locked: Boolean,
  pendingRestore: {
    type: Object,
    default: () => ({ open: false, commit: '', prefix: '' }),
  },
})

const emit = defineEmits(['clear-pending-restore'])
const { serverBusy } = useProfileActivity(() => props.profile)
const currentPrefix = defineModel('folder', { type: String, default: '' })
const source = defineModel('source', { type: String, default: 'local' })
const isVault = computed(() => source.value === 'vault')

const commits = ref([])
const selectedCommit = defineModel('snapshot', { type: String, default: '' })
const tree = shallowRef(null)
let indexedSource = null
let indexedResult = indexFileTree([])
const fileIndex = computed(() => {
  const entries = tree.value?.entries || []
  if (entries === indexedSource) return indexedResult
  indexedSource = entries
  indexedResult = indexFileTree(entries)
  return indexedResult
})
const listedCommit = computed(() => isVault.value ? tree.value?.commit_id || selectedCommit.value : '')
const listedAt = ref(null)
const showingCache = ref(false)
const selectedPath = ref('')
const search = ref('')
const folderHistory = ref([currentPrefix.value])
const historyIndex = ref(0)
const showFolders = ref(false)
const listPane = ref(null)
const addressBar = ref(null)
const addressInput = ref(null)
const editingAddress = ref(false)
const addressDraft = ref('')
const addressError = ref('')
const views = ['icons', 'details', 'list']
const viewKey = 'kasumi.files.view.v2'
function readSavedView() {
  try {
    return localStorage.getItem(viewKey)
  } catch {
    return null
  }
}
const savedView = readSavedView()
const view = ref(views.includes(savedView) ? savedView : 'icons')
watch(view, (value) => {
  try {
    localStorage.setItem(viewKey, value)
  } catch {
  }
})
const loading = ref(false)
const error = ref('')
const snapshotsOpen = ref(false)
const loadingVersions = ref(false)
const versionError = ref('')
const reload = ref(0)
const visibleLimit = ref(100)
const restoreModal = ref({ open: false, prefix: '' })
let versionsRequest
let pathToPreserve = ''
const selectedEntry = computed(() => fileIndex.value.files.get(selectedPath.value))
const thumbRevisions = ref({})
const savedThumbs = ref({})

function onPreviewReady(payload) {
  const hash = payload?.hash
  if (!hash) return
  if (payload.dataUrl) {
    saveRemoteThumbnail(props.profile, hash, payload.dataUrl)
    savedThumbs.value = { ...savedThumbs.value, [hash]: payload.dataUrl }
  }
  thumbRevisions.value = {
    ...thumbRevisions.value,
    [hash]: (thumbRevisions.value[hash] || 0) + 1,
  }
}

async function loadVersions() {
  if (loadingVersions.value || props.locked) return
  const cached = cachedRemoteReading(props.profile, 'commits')
  if (cached) {
    commits.value = cached.value?.commits || []
    if (cached.fresh) {
      versionError.value = ''
      return
    }
  }
  const controller = new AbortController()
  versionsRequest = controller
  loadingVersions.value = true
  versionError.value = ''
  try {
    const result = await fetchRemoteCommits(props.profile, controller.signal)
    if (controller.signal.aborted) return
    commits.value = result.commits || []
  } catch (err) {
    if (!controller.signal.aborted) versionError.value = err.message
  } finally {
    if (!controller.signal.aborted) loadingVersions.value = false
  }
}
onUnmounted(() => versionsRequest?.abort())

async function loadTree([profile, mode, commit, version], [oldProfile, oldMode, oldCommit, oldVersion], onCleanup) {
  const controller = new AbortController()
  onCleanup(() => controller.abort())
  if (profile !== oldProfile || mode !== oldMode || commit !== oldCommit) {
    tree.value = null
    listedAt.value = null
    selectedPath.value = ''
  }
  loading.value = false
  error.value = ''
  showingCache.value = Boolean(tree.value)
  if (mode === 'vault' && props.locked) return
  const query = { commit: commit || undefined }
  const cached = mode === 'vault' ? cachedRemoteTree(profile, query) : cachedLocalTree(profile)
  const refresh = oldVersion !== undefined && version !== oldVersion
  function show(result, time, fromCache) {
    const previousPath = selectedPath.value || pathToPreserve
    pathToPreserve = ''
    tree.value = result
    listedAt.value = time
    showingCache.value = fromCache
    const { files, folders } = fileIndex.value
    selectedPath.value = files.has(previousPath) || folders.has(previousPath) ? previousPath : ''
    const nextFolder = nearestFolder(currentPrefix.value)
    if (nextFolder !== currentPrefix.value) {
      currentPrefix.value = nextFolder
      folderHistory.value[historyIndex.value] = nextFolder
    }
  }

  if (cached) show(cached.value, cached.readAt, true)
  if (cached?.fresh && !refresh) return

  loading.value = true
  try {
    const options = { refresh, signal: controller.signal }
    const result = mode === 'vault'
      ? await fetchRemoteTree(profile, { ...query, ...options })
      : await fetchLocalTree(profile, options)
    if (!controller.signal.aborted) {
      show(result, Date.now(), false)
    }
  } catch (err) {
    if (!controller.signal.aborted) {
      error.value = err.message
      if (err.status === 401 || err.status === 403) {
        tree.value = null
        listedAt.value = null
        selectedPath.value = ''
        currentPrefix.value = ''
      }
    }
  } finally {
    if (!controller.signal.aborted) loading.value = false
  }
}

watch(() => props.locked, (locked) => {
  if (!locked) return
  source.value = 'local'
  selectedCommit.value = ''
  versionsRequest?.abort()
  commits.value = []
  snapshotsOpen.value = false
  loadingVersions.value = false
  versionError.value = ''
  clearSavedRemoteThumbnails(props.profile)
  savedThumbs.value = {}
  thumbRevisions.value = {}
}, { immediate: true })
watch([() => props.profile, source, selectedCommit, reload], loadTree, { immediate: true })
watch(serverBusy, (busy, wasBusy) => {
  if (wasBusy && !busy) reload.value++
})
watch(source, (mode) => {
  if (mode === 'local') restoreModal.value = { open: false, prefix: '' }
  folderHistory.value = [currentPrefix.value]
  historyIndex.value = 0
  search.value = ''
}, { flush: 'sync' })

const breadcrumbs = computed(() => {
  const parts = currentPrefix.value ? currentPrefix.value.split('/') : []
  return [{ name: t('files.root'), path: '' },
    ...parts.map((name, index) => ({ name, path: parts.slice(0, index + 1).join('/') }))]
})

const visibleItems = computed(() => {
  const { folders, files } = fileIndex.value
  const query = search.value.trim().toLowerCase()
  if (!query) return folders.get(currentPrefix.value)?.items || []
  const prefix = currentPrefix.value ? `${currentPrefix.value}/` : ''
  const matches = []
  for (const item of folders.values()) {
    if (item.path && item.path.startsWith(prefix) && item.pathLower.slice(prefix.length).includes(query)) {
      matches.push({ ...item, name: item.path.slice(prefix.length) })
    }
  }
  for (const item of files.values()) {
    if (item.path.startsWith(prefix) && item.pathLower.slice(prefix.length).includes(query)) {
      matches.push({ ...item, name: item.path.slice(prefix.length) })
    }
  }
  return matches.sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name, undefined, { numeric: true }))
})

watch([() => props.profile, visibleItems, isVault], ([profile], oldArgs) => {
  const prevProfile = oldArgs?.[0]
  if (prevProfile !== undefined && profile !== prevProfile) {
    savedThumbs.value = {}
    thumbRevisions.value = {}
  }
  if (!isVault.value || !profile) return
  const next = { ...savedThumbs.value }
  let changed = false
  for (const item of visibleItems.value) {
    if (!item.logical_hash || next[item.logical_hash]) continue
    const cached = getSavedRemoteThumbnail(profile, item.logical_hash)
    if (cached) {
      next[item.logical_hash] = cached
      changed = true
    }
  }
  if (changed) savedThumbs.value = next
}, { immediate: true })

function nearestFolder(path) {
  while (path && !fileIndex.value.folders.has(path)) path = parentFolder(path)
  return path
}

function showLocation(path, selection = '') {
  currentPrefix.value = path
  search.value = ''
  selectedPath.value = selection
  showFolders.value = false
}

function openFolder(path, selection) {
  if (path !== currentPrefix.value) {
    folderHistory.value = [...folderHistory.value.slice(0, historyIndex.value + 1), path]
    historyIndex.value++
  }
  showLocation(path, selection)
}

function moveHistory(offset) {
  const index = historyIndex.value + offset
  if (index < 0 || index >= folderHistory.value.length) return
  historyIndex.value = index
  showLocation(nearestFolder(folderHistory.value[index]))
}

function levelUp() {
  if (currentPrefix.value) openFolder(parentFolder(currentPrefix.value), currentPrefix.value)
}

async function openFromList(path) {
  openFolder(path)
  await nextTick()
  listPane.value?.focus({ preventScroll: true })
}

function cancelAddressEdit() {
  editingAddress.value = false
  addressError.value = ''
}

function resolveAddressTarget(raw) {
  let cleaned = String(raw || '').trim().replace(/\\+/g, '/').replace(/^\/+|\/+$/g, '')
  const rootNames = new Set(['root', t('files.root').toLowerCase()])
  const firstSlash = cleaned.indexOf('/')
  if (firstSlash === -1) {
    if (!cleaned || rootNames.has(cleaned.toLowerCase())) return { folder: '' }
  } else if (rootNames.has(cleaned.slice(0, firstSlash).toLowerCase())) {
    cleaned = cleaned.slice(firstSlash + 1).replace(/^\/+/, '')
    if (!cleaned) return { folder: '' }
  }

  const { folders, files } = fileIndex.value
  if (folders.has(cleaned)) return { folder: cleaned }
  const lower = cleaned.toLowerCase()
  for (const key of folders.keys()) {
    if (key.toLowerCase() === lower) return { folder: key }
  }
  if (files.has(cleaned)) return { folder: parentFolder(cleaned), select: cleaned }
  for (const key of files.keys()) {
    if (key.toLowerCase() === lower) return { folder: parentFolder(key), select: key }
  }
  return null
}

async function openAddressEditor() {
  if (!tree.value) return
  editingAddress.value = true
  addressError.value = ''
  addressDraft.value = currentPrefix.value || '/'
  await nextTick()
  const el = addressInput.value
  if (el) {
    el.focus()
    el.select()
  }
}

function submitAddress() {
  const match = resolveAddressTarget(addressDraft.value)
  if (!match) {
    addressError.value = t('files.pathNotFound')
    nextTick(() => addressInput.value?.select())
    return
  }
  editingAddress.value = false
  addressError.value = ''
  openFolder(match.folder, match.select || '')
  nextTick(() => listPane.value?.focus({ preventScroll: true }))
}

const addressSuggestions = computed(() => {
  const paths = []
  for (const key of fileIndex.value.folders.keys()) {
    if (key) paths.push(key)
    if (paths.length >= 100) break
  }
  return paths
})

function onNavigationKey(event) {
  const key = event.key.toLowerCase()
  if ((event.altKey && key === 'd') || ((event.ctrlKey || event.metaKey) && key === 'l')) {
    event.preventDefault()
    openAddressEditor()
    return
  }
  if (!event.altKey || event.target.matches('input, select, textarea')) return
  if (event.key === 'ArrowUp') levelUp()
  else if (event.key === 'ArrowLeft') moveHistory(-1)
  else if (event.key === 'ArrowRight') moveHistory(1)
  else return
  event.preventDefault()
}

function selectSnapshot(commit) {
  if (isVault.value && commit === selectedCommit.value) return
  pathToPreserve = selectedPath.value
  source.value = 'vault'
  selectedCommit.value = commit
}

watch([() => props.profile, source, selectedCommit], cancelAddressEdit)

watch([search, currentPrefix, selectedCommit], () => {
  visibleLimit.value = 100
  if (listPane.value) listPane.value.scrollTop = 0
})

watch(currentPrefix, () => {
  const bar = addressBar.value
  if (bar) bar.scrollLeft = bar.scrollWidth
}, { flush: 'post' })

watch(
  () => props.pendingRestore,
  (req) => {
    if (req?.open) {
      if (props.locked) {
        emit('clear-pending-restore')
        return
      }
      source.value = 'vault'
      selectedCommit.value = req.commit || ''
      restoreModal.value = { open: true, prefix: req.prefix || '' }
      emit('clear-pending-restore')
    }
  },
  { immediate: true }
)
</script>

<template>
  <div class="k-file-browser" @keydown="onNavigationKey">
    <header class="k-explorer-toolbar">
      <div class="k-explorer-address-row">
        <div class="k-row k-explorer-controls" role="group" :aria-label="t('files.folderNavigation')">
          <button type="button" class="k-btn k-btn--ghost k-btn--compact"
            :disabled="historyIndex === 0" :aria-label="t('files.back')" :title="t('files.back')"
            @click="moveHistory(-1)">←</button>
          <button type="button" class="k-btn k-btn--ghost k-btn--compact"
            :disabled="historyIndex + 1 >= folderHistory.length" :aria-label="t('files.forward')" :title="t('files.forward')"
            @click="moveHistory(1)">→</button>
          <button type="button" class="k-btn k-btn--ghost k-btn--compact"
            :disabled="!currentPrefix" :aria-label="t('files.up')" :title="t('files.up')" @click="levelUp">↑</button>
          <button type="button" class="k-btn k-btn--ghost k-btn--compact"
            :disabled="loading" :aria-label="t('common.refresh')" :title="t('common.refresh')"
            @click="reload++">↻</button>
        </div>
        <nav
          v-if="!editingAddress"
          ref="addressBar"
          class="k-explorer-path"
          :aria-label="t('files.folderPath')"
          @click="openAddressEditor"
        >
          <template v-for="(folder, index) in breadcrumbs" :key="folder.path">
            <span v-if="index > 0" class="k-faint" aria-hidden="true">›</span>
            <span v-if="index === breadcrumbs.length - 1" class="k-current-folder" aria-current="location">{{ folder.name }}</span>
            <button v-else type="button" class="k-path-button" @click.stop="openFolder(folder.path)">{{ folder.name }}</button>
          </template>
        </nav>
        <form
          v-else
          class="k-explorer-path k-explorer-path--editing"
          :class="{ 'k-explorer-path--invalid': Boolean(addressError) }"
          @submit.prevent="submitAddress"
        >
          <input
            ref="addressInput"
            v-model="addressDraft"
            type="text"
            class="k-explorer-path-input"
            :list="addressSuggestions.length ? `kasumi-folders-${profile}` : undefined"
            :aria-label="t('files.pathInput')"
            :title="addressError || undefined"
            @input="addressError = ''"
            @keydown.escape.stop.prevent="cancelAddressEdit"
            @blur="cancelAddressEdit"
          />
          <datalist v-if="addressSuggestions.length" :id="`kasumi-folders-${profile}`">
            <option v-for="folderPath in addressSuggestions" :key="folderPath" :value="folderPath" />
          </datalist>
        </form>
        <input v-model="search" type="search" class="k-input k-input--compact k-folder-search"
          :placeholder="t('files.searchFolder')" :aria-label="t('files.searchFolder')" />
      </div>

      <div class="k-row k-row--between k-row--wrap k-explorer-tools">
        <div class="k-row k-row--wrap">
          <div class="k-segmented" role="group" :aria-label="t('files.source')">
            <button type="button" class="k-seg-btn" :class="{ 'k-seg-btn--active': !isVault }"
              :aria-pressed="!isVault" @click="source = 'local'">{{ t('files.local') }}</button>
            <button type="button" class="k-seg-btn" :class="{ 'k-seg-btn--active': isVault }"
              :aria-pressed="isVault" :disabled="locked" :title="locked ? t('files.lockedListing') : undefined"
              @click="source = 'vault'">{{ t('files.vault') }}</button>
          </div>
          <button v-if="tree" type="button" class="k-btn k-btn--compact k-folder-toggle"
            :aria-expanded="showFolders" @click="showFolders = !showFolders">{{ t('files.folders') }}</button>
          <div class="k-segmented" role="group" :aria-label="t('files.viewMode')">
            <button v-for="mode in views" :key="mode" type="button" class="k-seg-btn"
              :class="{ 'k-seg-btn--active': view === mode }" :aria-pressed="view === mode" @click="view = mode">
              {{ t('files.view.' + mode) }}
            </button>
          </div>
        </div>
      </div>
      <FileSnapshots v-model:open="snapshotsOpen" :vault="isVault" :locked="locked"
        :snapshot="tree" :listed-at="listedAt"
        :loading-tree="loading" :selected="selectedCommit" :versions="commits"
        :loading-versions="loadingVersions" :version-error="versionError"
        @load="loadVersions" @select="selectSnapshot"
        @restore="restoreModal = { open: true, prefix: currentPrefix }" />
    </header>

    <div class="k-folder-browser" :class="{ 'k-folder-browser--tree-open': showFolders }">
      <aside class="k-folder-sidebar">
        <FileFolderTree v-if="tree" :root="fileIndex.folders.get('')" :current="currentPrefix" @open-folder="openFolder" />
      </aside>
      <section ref="listPane" class="k-folder-contents" tabindex="-1" :aria-label="t('files.folderContents')">
        <div v-if="error" class="k-alert k-alert--error" role="alert">
          {{ friendlyBusyError(null, t, error) }}
        </div>
        <div v-else-if="loading && !tree" class="k-muted k-card-body--compact" role="status">{{ t('common.loading') }}</div>
        <div v-else-if="tree && !visibleItems.length" class="k-muted k-card-body--compact">
          {{ t(search.trim() ? 'files.noSearchResults' : 'files.emptyFolder') }}
        </div>

        <FileExplorerList v-if="tree" :view="view" :items="visibleItems.slice(0, visibleLimit)"
          :selected-path="selectedPath" :profile="profile" :local="!isVault"
          :commit="listedCommit" :thumb-revisions="thumbRevisions" :saved-thumbs="savedThumbs"
          @select-item="selectedPath = $event.path" @open-folder="openFromList" />
        <button v-if="visibleItems.length > visibleLimit" type="button" class="k-btn k-btn--compact"
          @click="visibleLimit += 100">{{ t('files.showMore', { remaining: visibleItems.length - visibleLimit }) }}</button>
      </section>
      <aside v-if="selectedEntry" class="k-explorer-preview" :aria-label="t('files.filePreview')">
        <header class="k-row k-row--between">
          <span class="k-field-label">{{ t('files.filePreview') }}</span>
          <button type="button" class="k-btn k-btn--ghost k-btn--compact"
            :aria-label="t('files.closePreview')" :title="t('files.closePreview')"
            @click="selectedPath = ''; listPane?.focus()">×</button>
        </header>
        <FilePreviewPane
          :profile="profile"
          :local="!isVault"
          :path="selectedEntry.path"
          :commit="listedCommit"
          :entry="selectedEntry"
          :disabled="loadingVersions"
          @select-commit="selectSnapshot"
          @preview-ready="onPreviewReady"
        />
      </aside>
    </div>

    <footer v-if="tree" class="k-row k-row--between k-explorer-footer k-text-xs k-muted">
      <span>{{ t('files.itemCount', { count: visibleItems.length }) }}</span>
      <span v-if="isVault || showingCache" role="status">
        {{ t(showingCache ? 'files.cachedListing' : 'files.listedAt', { time: formatTimestamp(listedAt) }) }}
      </span>
    </footer>

    <RestoreModal
      :open="restoreModal.open"
      :profile="profile"
      :commit="listedCommit"
      :initial-prefix="restoreModal.prefix"
      @close="restoreModal = { open: false, prefix: '' }"
    />
  </div>
</template>

<style scoped>
.k-file-browser {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  min-height: 0;
}

.k-explorer-toolbar {
  flex: none;
  padding: 8px 12px;
  background: var(--k-surface);
  border-bottom: 1px solid var(--k-border);
}

.k-explorer-address-row { display: flex; align-items: center; gap: 8px; }
.k-explorer-controls { gap: 1px; flex: none; }
.k-explorer-controls .k-btn { font-size: 16px; padding: 2px 8px; }

.k-explorer-path {
  display: flex;
  align-items: center;
  flex: 1;
  gap: 3px;
  padding: 2px 7px;
  min-width: 0;
  min-height: 31px;
  overflow-x: auto;
  scrollbar-width: thin;
  white-space: nowrap;
  background: var(--k-input-bg);
  border: 1px solid var(--k-border);
  border-radius: var(--k-radius-xs);
  font-size: 13px;
  cursor: text;
}
.k-explorer-path--editing {
  padding: 0;
  border-color: var(--k-primary-strong);
}
.k-explorer-path--invalid {
  border-color: var(--k-error);
}
.k-explorer-path-input {
  width: 100%;
  min-width: 0;
  padding: 5px 8px;
  border: 0;
  background: transparent;
  color: var(--k-text);
  font: inherit;
  outline: none;
}

.k-path-button {
  padding: 3px 5px;
  background: transparent;
  color: var(--k-text-muted);
  border: 0;
  cursor: pointer;
}
.k-path-button:hover { background: var(--k-hover); color: var(--k-text); }
.k-current-folder { padding: 3px 5px; }
.k-folder-search { width: clamp(11rem, 22vw, 20rem); }
.k-explorer-tools { margin-top: 6px; }
.k-folder-toggle { display: none; }

.k-folder-browser {
  flex: 1;
  display: flex;
  min-width: 0;
  min-height: 0;
}

.k-folder-sidebar {
  flex: 0 0 clamp(10rem, 17vw, 15rem);
  background: var(--k-surface-recessed);
  border-right: 1px solid var(--k-border);
  overflow: auto;
}

.k-folder-contents { flex: 1; min-width: 0; overflow: auto; padding: 5px; }
.k-folder-contents:focus-visible {
  outline: 1px solid var(--k-active-border);
  outline-offset: -1px;
}
.k-folder-contents > .k-alert { margin: 4px 4px 6px; }

.k-explorer-preview {
  flex: 0 0 clamp(17rem, 35vw, 34rem);
  min-width: 0;
  overflow: auto;
  padding: 7px 14px 14px;
  background: var(--k-surface-recessed);
  border-left: 1px solid var(--k-border);
  overflow-wrap: anywhere;
}
.k-explorer-preview header { margin-bottom: 6px; }

.k-explorer-footer {
  flex: none;
  padding: 4px 12px;
  background: var(--k-surface);
  border-top: 1px solid var(--k-border);
}

@media (max-width: 860px) {
  .k-folder-toggle { display: inline-flex; }
  .k-folder-browser { flex-direction: column; }
  .k-folder-sidebar { display: none; }
  .k-folder-browser--tree-open .k-folder-sidebar {
    display: block;
    flex: 0 1 auto;
    max-height: 9rem;
    border-right: 0;
    border-bottom: 1px solid var(--k-border);
  }
  .k-explorer-preview {
    flex: 0 1 auto;
    max-height: 45%;
    border-left: 0;
    border-top: 1px solid var(--k-border);
  }
}

@media (max-width: 550px) {
  .k-explorer-toolbar { padding-inline: 7px; }
  .k-explorer-address-row { flex-wrap: wrap; gap: 5px; }
  .k-folder-search { width: 100%; }
}
</style>
