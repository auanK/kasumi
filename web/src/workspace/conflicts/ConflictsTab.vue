<script setup>
import { computed, onUnmounted, ref, watch } from 'vue'
import EmptyState from '../../components/EmptyState.vue'
import TextDiffViewer from '../history/TextDiffViewer.vue'
import { fetchConflictDiff, listConflicts, resolveConflict } from '../../api/conflicts.js'
import { pushToast } from '../../composables/useToasts.js'
import { useProfileActivity } from '../../composables/useProfileActivity.js'
import {
  decodeHexToBytes,
  decodeHexToText,
  formatBytes,
  isProbablyBinary,
} from '../../utils/format.js'
import { t } from '../../i18n/index.js'

const props = defineProps({
  profile: { type: String, required: true },
})

const emit = defineEmits(['updated', 'count'])

const groups = ref([])
const selectedIndex = ref(0)
const selectedArtifact = ref('')
const diffData = ref(null)
const dryRunPreview = ref(null)
const loading = ref(false)
const loaded = ref(false)
const busy = ref(false)
const error = ref('')
const { blockedReason } = useProfileActivity(() => props.profile)
let listController = null
let diffController = null
let listRequestId = 0
let diffRequestId = 0

const activeGroup = computed(() => groups.value[selectedIndex.value] || null)
const artifacts = computed(() => activeGroup.value?.artifacts || [])

const canonicalBytes = computed(() =>
  decodeHexToBytes(diffData.value?.canonical_hex || diffData.value?.canonical?.hex || '')
)
const artifactBytes = computed(() =>
  decodeHexToBytes(diffData.value?.artifact_hex || diffData.value?.artifact?.hex || '')
)
const isBinary = computed(
  () => isProbablyBinary(canonicalBytes.value) || isProbablyBinary(artifactBytes.value)
)

async function loadConflicts() {
  const profile = props.profile
  if (!profile) return
  listController?.abort()
  diffController?.abort()
  listController = new AbortController()
  const { signal } = listController
  const reqId = ++listRequestId
  ++diffRequestId
  loading.value = true
  error.value = ''
  diffData.value = null
  dryRunPreview.value = null
  try {
    const res = await listConflicts(profile, { signal })
    if (signal.aborted || reqId !== listRequestId || profile !== props.profile) return
    const nextGroups = Array.isArray(res?.groups)
      ? res.groups
      : Array.isArray(res?.conflicts)
        ? res.conflicts
        : []
    groups.value = nextGroups
    loaded.value = true
    selectedIndex.value = 0
    emit('count', nextGroups.length)
    pickFirstArtifact()
  } catch (err) {
    if (signal.aborted || err?.name === 'AbortError' || reqId !== listRequestId || profile !== props.profile) return
    groups.value = []
    loaded.value = false
    error.value = err?.message || 'Failed to check conflicts'
  } finally {
    if (reqId === listRequestId && profile === props.profile) {
      loading.value = false
    }
  }
}

function pickFirstArtifact() {
  const first = artifacts.value[0]
  selectedArtifact.value = first ? first.path || first.artifact_path || first : ''
  if (activeGroup.value && selectedArtifact.value) {
    loadDiff()
  } else {
    diffController?.abort()
    ++diffRequestId
    diffData.value = null
  }
}

async function loadDiff() {
  const profile = props.profile
  const group = activeGroup.value
  const artifact = selectedArtifact.value
  if (!group || !artifact) return
  diffController?.abort()
  diffController = new AbortController()
  const { signal } = diffController
  const reqId = ++diffRequestId
  diffData.value = null
  dryRunPreview.value = null
  try {
    const data = await fetchConflictDiff(profile, {
      path: group.canonical_path || group.path,
      artifact,
      signal,
    })
    if (signal.aborted || reqId !== diffRequestId || profile !== props.profile || artifact !== selectedArtifact.value) return
    diffData.value = data
  } catch (err) {
    if (signal.aborted || err?.name === 'AbortError' || reqId !== diffRequestId || profile !== props.profile || artifact !== selectedArtifact.value) return
    error.value = err?.message || 'Failed to inspect conflict difference'
  }
}

async function handleResolve(choice, dryRun) {
  if (!activeGroup.value || busy.value || blockedReason.value) return
  busy.value = true
  error.value = ''
  try {
    const targetPath = activeGroup.value.canonical_path || activeGroup.value.path
    const res = await resolveConflict(props.profile, {
      path: targetPath,
      choice,
      artifact: choice === 'keep_artifact' ? selectedArtifact.value : undefined,
      dryRun,
    })
    if (dryRun) {
      dryRunPreview.value = res
    } else {
      const recovery = res?.recovery_directory
      pushToast(recovery ? `Resolved ${targetPath}. Other versions are in ${recovery}.` : `Resolved conflict: ${targetPath}`, 'ok')
      emit('updated')
      await loadConflicts()
    }
  } catch (err) {
    error.value = err?.message || 'Failed to resolve conflict'
  } finally {
    busy.value = false
  }
}

watch(
  () => props.profile,
  () => {
    groups.value = []
    selectedIndex.value = 0
    selectedArtifact.value = ''
    diffData.value = null
    dryRunPreview.value = null
    error.value = ''
    loaded.value = false
    loadConflicts()
  },
  { immediate: true }
)

onUnmounted(() => {
  listController?.abort()
  diffController?.abort()
})
</script>

<template>
  <div v-if="loading && groups.length === 0" class="k-workspace-scroll">
    <div class="k-readable-canvas k-muted" role="status">{{ t('common.loading') }}</div>
  </div>

  <div v-else-if="error && groups.length === 0" class="k-workspace-scroll">
    <div class="k-readable-canvas">
      <div class="k-alert k-alert--error k-row k-row--between" role="alert">
        <span>{{ error }}</span>
        <button type="button" class="k-btn k-btn--compact" @click="loadConflicts">{{ t('common.refresh') }}</button>
      </div>
    </div>
  </div>

  <div v-else-if="loaded && groups.length === 0" class="k-workspace-scroll">
    <div class="k-readable-canvas">
      <EmptyState :title="t('conflicts.emptyTitle')" :description="t('conflicts.emptyHint')" />
    </div>
  </div>

  <div v-else class="k-workspace-body">
    <aside class="k-sidebar-pane">
      <div class="k-sidebar-head">
        <div class="k-row k-row--between">
          <strong class="k-text-sm">{{ t('workspace.tab.conflicts') }} ({{ groups.length }})</strong>
          <button type="button" class="k-btn k-btn--ghost k-btn--compact" @click="loadConflicts">
            {{ t('common.refresh') }}
          </button>
        </div>
      </div>

      <div class="k-sidebar-scroll">
        <button
          v-for="(g, idx) in groups"
          :key="g.canonical_path || g.path"
          type="button"
          class="k-list-row"
          :class="{ 'k-list-row--active': idx === selectedIndex }"
          @click="() => { selectedIndex = idx; pickFirstArtifact() }"
        >
          <span class="k-mono k-truncate">{{ g.canonical_path || g.path }}</span>
          <span class="k-faint k-text-xs">{{ (g.artifacts || []).length }}</span>
        </button>
      </div>
    </aside>

    <main class="k-main-pane">
      <div v-if="activeGroup" class="k-readable-canvas">
        <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>

        <section class="k-card k-card-body k-stack">
          <div>
            <div class="k-faint k-text-sm">{{ t('conflicts.chooseCopy') }}</div>
            <strong class="k-mono">{{ activeGroup.canonical_path || activeGroup.path }}</strong>
          </div>

          <div class="k-field">
            <label class="k-field-label">{{ t('conflicts.copyLabel') }}</label>
            <select v-model="selectedArtifact" class="k-select k-mono" @change="loadDiff">
              <option v-for="art in artifacts" :key="art.path || art" :value="art.path || art">
                {{ art.path || art }} ({{ formatBytes(art.size) }})
              </option>
            </select>
          </div>

          <div v-if="blockedReason" class="k-alert k-alert--info" role="status">{{ blockedReason }}</div>
          <div class="k-row k-row--wrap">
            <button
              type="button"
              class="k-btn k-btn--primary k-btn--compact"
              :disabled="busy || Boolean(blockedReason)"
              @click="handleResolve('keep_canonical', false)"
            >
              {{ t('conflicts.keepCurrent') }}
            </button>
            <button
              type="button"
              class="k-btn k-btn--danger k-btn--compact"
              :disabled="busy || Boolean(blockedReason) || !selectedArtifact"
              @click="handleResolve('keep_artifact', false)"
            >
              {{ t('conflicts.keepArtifact') }}
            </button>
            <button
              type="button"
              class="k-btn k-btn--ghost k-btn--compact"
              :disabled="busy || Boolean(blockedReason)"
              @click="handleResolve('keep_canonical', true)"
            >
              {{ t('common.preview') }}
            </button>
          </div>

          <div v-if="dryRunPreview" class="k-alert k-alert--info k-text-sm">
            Dry run: {{ dryRunPreview.removed_artifacts?.length ?? artifacts.length }} conflict artifact(s) would be cleaned up.
          </div>
        </section>

        <template v-if="diffData">
          <div v-if="isBinary" class="k-alert k-alert--info">
            Binary file conflict · current {{ formatBytes(diffData.canonical_size ?? canonicalBytes.length) }} vs copy {{ formatBytes(diffData.artifact_size ?? artifactBytes.length) }}.
          </div>
          <TextDiffViewer
            v-else
            :left-text="decodeHexToText(diffData.canonical_hex || diffData.canonical?.hex || '')"
            :right-text="decodeHexToText(diffData.artifact_hex || diffData.artifact?.hex || '')"
            left-label="Current file"
            right-label="Conflict copy"
          />
        </template>
      </div>
    </main>
  </div>
</template>
