<script setup>
import BaseModal from '../../components/BaseModal.vue'
import { t } from '../../i18n/index.js'
import { formatTimestamp, shortHash } from '../../utils/format.js'

defineProps({
  vault: Boolean,
  locked: Boolean,
  snapshot: { type: Object, default: null },
  listedAt: { type: Number, default: null },
  loadingTree: Boolean,
  selected: { type: String, default: '' },
  versions: { type: Array, default: () => [] },
  loadingVersions: Boolean,
  versionError: { type: String, default: '' },
})

const open = defineModel('open', { type: Boolean, default: false })
const emit = defineEmits(['load', 'select', 'restore'])

function showSnapshots() {
  open.value = true
  emit('load')
}

function select(commit) {
  emit('select', commit)
  open.value = false
}
</script>

<template>
  <div class="k-file-snapshots">
    <div class="k-row k-row--wrap k-snapshot-context" role="status">
      <template v-if="vault">
        <strong>{{ t('files.snapshotInUse') }}</strong>
        <template v-if="snapshot?.commit_id">
          <code :title="snapshot.commit_id">{{ shortHash(snapshot.commit_id) }}</code>
          <span v-if="snapshot.height" class="k-muted">v{{ snapshot.height }}</span>
          <span>{{ formatTimestamp(snapshot.created_at) }}</span>
        </template>
        <span v-else class="k-muted">
          {{ t(loadingTree ? 'common.loading' : snapshot ? 'files.noVaultSnapshot' : 'files.snapshotUnavailable') }}
        </span>
      </template>
      <template v-else>
        <strong>{{ t('files.localCurrent') }}</strong>
        <span v-if="listedAt" class="k-muted">{{ t('files.readAt', { time: formatTimestamp(listedAt) }) }}</span>
        <span class="k-snapshot-reference">
          {{ t('files.localReference') }}
          <template v-if="snapshot?.commit_id">
            <code :title="snapshot.commit_id">{{ shortHash(snapshot.commit_id) }}</code>
            <span v-if="Number.isInteger(snapshot.height)">v{{ snapshot.height }}</span>
            <span>{{ formatTimestamp(snapshot.created_at) }}</span>
          </template>
          <span v-else>{{ t(loadingTree ? 'common.loading' : 'files.noLocalSnapshot') }}</span>
        </span>
      </template>
    </div>
    <div class="k-row k-snapshot-actions">
      <button type="button" class="k-btn k-btn--compact" aria-haspopup="dialog"
        :disabled="locked" :title="locked ? t('files.lockedListing') : undefined"
        @click="showSnapshots">{{ t('files.browseSnapshots') }}</button>
      <button v-if="vault" type="button" class="k-btn k-btn--ghost k-btn--compact"
        :disabled="!snapshot?.commit_id || loadingTree" @click="emit('restore')">{{ t('files.restore') }}</button>
    </div>

    <BaseModal :open="open && !locked" :title="t('files.vaultSnapshots')" @close="open = false">
      <div class="k-stack--sm">
        <button type="button" class="k-list-row"
          :class="{ 'k-list-row--active': vault && !selected }"
          :aria-current="vault && !selected ? 'true' : undefined" @click="select('')">
          {{ t('files.latest') }}
        </button>
        <div v-if="versionError" class="k-alert k-alert--error k-stack--sm" role="alert">
          <span>{{ versionError }}</span>
          <button type="button" class="k-btn k-btn--compact" @click="emit('load')">{{ t('common.refresh') }}</button>
        </div>
        <div v-if="loadingVersions" class="k-muted" role="status">{{ t('common.loading') }}</div>
        <p v-else-if="!versions.length && !versionError" class="k-muted">{{ t('files.noVaultSnapshot') }}</p>
        <button v-for="version in versions" :key="version.commit_id" type="button"
          class="k-list-row k-row--wrap"
          :class="{ 'k-list-row--active': vault && selected === version.commit_id }"
          :aria-current="vault && selected === version.commit_id ? 'true' : undefined"
          @click="select(version.commit_id)">
          <span>
            <span v-if="version.height">v{{ version.height }} · </span>
            <code :title="version.commit_id">{{ shortHash(version.commit_id) }}</code>
          </span>
          <span class="k-muted k-text-xs">{{ formatTimestamp(version.created_at) }}</span>
        </button>
      </div>
    </BaseModal>
  </div>
</template>

<style scoped>
.k-file-snapshots {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 5px 12px;
  margin-top: 6px;
  padding: 4px 6px 4px 8px;
  border: 1px solid var(--k-border-subtle);
  background: var(--k-surface-recessed);
  border-radius: var(--k-radius-xs);
  font-size: 12px;
}
.k-snapshot-context { gap: 5px 8px; min-width: 0; }
.k-snapshot-context code { color: var(--k-lavender); }
.k-snapshot-reference {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 3px 7px;
  color: var(--k-text-muted);
}
.k-snapshot-actions { gap: 5px; }
</style>
