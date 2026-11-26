<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import EmptyState from '../components/EmptyState.vue'
import JobProgressPanel from '../components/JobProgressPanel.vue'
import SystemModal from '../system/SystemModal.vue'
import { useDaemonStream } from '../composables/useDaemonStream.js'
import { useProfiles } from '../composables/useProfiles.js'
import { t } from '../i18n/index.js'
import PreviewChangesModal from './PreviewChangesModal.vue'
import ProfileOverview from './ProfileOverview.vue'
import SyncProgressPanel from '../components/SyncProgressPanel.vue'
import WorkspaceTopbar from './WorkspaceTopbar.vue'
import ConflictsTab from './conflicts/ConflictsTab.vue'
import FilesTab from './files/FilesTab.vue'
import HistoryTab from './history/HistoryTab.vue'
import MaintenanceTab from './maintenance/MaintenanceTab.vue'
import SettingsTab from './settings/SettingsTab.vue'
import UnlockModal from './settings/UnlockModal.vue'

const route = useRoute()
const router = useRouter()
const { profiles, loaded, error, daemonMap, refreshProfiles } = useProfiles()
const stream = useDaemonStream()

const systemOpen = ref(false)
const unlockOpen = ref(false)
const previewTarget = ref('')
const conflictCount = ref(0)
const restoreRequest = ref({ open: false, commit: '', prefix: '' })
const fileFolder = ref('')
const fileSource = ref('local')
const fileSnapshot = ref('')

const profileName = computed(() => String(route.params.name || ''))
const activeTab = computed(() => String(route.params.tab || 'overview'))
const activeProfile = computed(
  () => profiles.value.find((p) => p.name === profileName.value) || null
)
const activeDaemonState = computed(() => daemonMap.value.get(profileName.value) || activeProfile.value?.daemon || null)
const activeJob = computed(() =>
  (stream.jobs || []).find(
    (job) => job.profile === profileName.value && job.state === 'running' && job.operation !== 'preview'
  ) || null
)

function selectTab(tab) {
  router.replace({ name: 'workspace', params: { name: profileName.value, tab } })
}

function switchProfile(nextName) {
  router.push({ name: 'workspace', params: { name: nextName, tab: activeTab.value } })
}

function refresh() {
  return refreshProfiles().catch(() => {})
}

function openRestoreForCommit(commitId) {
  restoreRequest.value = { open: true, commit: commitId, prefix: '' }
  selectTab('files')
}

function openFilesForCommit(commitId) {
  fileSource.value = 'vault'
  fileSnapshot.value = commitId || ''
  fileFolder.value = ''
  selectTab('files')
}

watch(profileName, () => {
  previewTarget.value = ''
  conflictCount.value = 0
  fileFolder.value = ''
  fileSource.value = 'local'
  fileSnapshot.value = ''
  restoreRequest.value = { open: false, commit: '', prefix: '' }
})

onMounted(async () => {
  if (!loaded.value) {
    await refresh()
  }
})
</script>

<template>
  <div class="k-workspace-shell">
    <WorkspaceTopbar
      :profile-name="profileName"
      :profiles="profiles"
      :daemon-state="activeDaemonState"
      :active-tab="activeTab"
      :conflict-count="conflictCount"
      @select-tab="selectTab"
      @switch-profile="switchProfile"
      @open-unlock="unlockOpen = true"
      @open-system="systemOpen = true"
      @preview="previewTarget = profileName"
      @refresh="refresh"
    />

    <div v-if="loaded && !activeProfile" class="k-workspace-scroll">
      <div class="k-readable-canvas">
        <EmptyState :title="t('overview.notFound', { name: profileName })">
          <RouterLink to="/" class="k-btn k-btn--primary">← {{ t('workspace.backToProfiles') }}</RouterLink>
        </EmptyState>
      </div>
    </div>

    <SyncProgressPanel v-if="activeDaemonState?.state === 'running_sync'" :live="activeDaemonState" />
    <JobProgressPanel v-else-if="activeJob" :job="activeJob" />
    <main v-if="activeProfile || !loaded" class="k-workspace-body">
      <div v-if="!activeProfile" class="k-workspace-scroll" role="status">
        {{ error || t('common.loading') }}
        <button v-if="error" type="button" class="k-btn k-btn--compact" @click="refresh">{{ t('common.refresh') }}</button>
      </div>
      <KeepAlive v-else :max="6">
        <div v-if="activeTab === 'overview'" :key="`${profileName}:overview`" class="k-workspace-scroll">
          <div class="k-card k-workspace-overview">
            <ProfileOverview :profile="activeProfile" :daemon-state="activeDaemonState" />
          </div>
        </div>
        <FilesTab
          v-else-if="activeTab === 'files'"
          v-model:folder="fileFolder"
          v-model:source="fileSource"
          v-model:snapshot="fileSnapshot"
          :key="`${profileName}:files`"
          :profile="profileName"
          :locked="Boolean(activeDaemonState?.locked)"
          :pending-restore="restoreRequest"
          @clear-pending-restore="restoreRequest = { open: false, commit: '', prefix: '' }"
        />
        <HistoryTab
          v-else-if="activeTab === 'history'"
          :key="`${profileName}:history`"
          :profile="profileName"
          @restore-commit="openRestoreForCommit"
          @browse-commit="openFilesForCommit"
        />
        <ConflictsTab
          v-else-if="activeTab === 'conflicts'"
          :key="`${profileName}:conflicts`"
          :profile="profileName"
          @count="conflictCount = $event"
        />
        <MaintenanceTab
          v-else-if="activeTab === 'maintenance'"
          :key="`${profileName}:maintenance`"
          :profile="profileName"
        />
        <SettingsTab
          v-else
          :key="`${profileName}:settings`"
          :profile="activeProfile"
          :daemon-state="activeDaemonState"
          @refresh="refresh"
          @open-unlock="unlockOpen = true"
          @deleted="() => { refresh(); router.replace('/') }"
          @renamed="async (next) => { await refresh(); router.replace({ name: 'workspace', params: { name: next, tab: 'settings' } }) }"
        />
      </KeepAlive>
    </main>

    <SystemModal :open="systemOpen" @close="systemOpen = false" />
    <PreviewChangesModal :profile="previewTarget" @close="previewTarget = ''" />
    <UnlockModal
      :open="unlockOpen"
      :profile="activeProfile"
      @close="unlockOpen = false"
      @unlocked="refresh"
    />
  </div>
</template>
