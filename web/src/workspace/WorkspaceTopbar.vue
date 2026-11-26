<script setup>
import { computed, ref } from 'vue'
import HubTopbar from '../hub/HubTopbar.vue'
import StatusBadge from '../components/StatusBadge.vue'
import VaultIcon from '../components/VaultIcon.vue'
import { cancelProfileSync, triggerSync } from '../api/daemon.js'
import { pushToast } from '../composables/useToasts.js'
import { useProfileActivity } from '../composables/useProfileActivity.js'
import { t } from '../i18n/index.js'

const props = defineProps({
  profileName: { type: String, required: true },
  profiles: { type: Array, default: () => [] },
  daemonState: { type: Object, default: null },
  activeTab: { type: String, default: 'overview' },
  conflictCount: { type: Number, default: 0 },
})
const emit = defineEmits(['select-tab', 'switch-profile', 'open-unlock', 'open-system', 'preview', 'refresh'])
const busy = ref(false)
const tabs = ['overview', 'files', 'history', 'conflicts', 'settings']
const activeProfile = computed(() => props.profiles.find((profile) => profile.name === props.profileName) || null)
const state = computed(() => props.daemonState?.state || 'unknown')
const isRunning = computed(() => state.value === 'running_sync')
const isLocked = computed(() => props.daemonState?.locked || state.value === 'locked')
const { runningJob, externalBusy, blockedReason } = useProfileActivity(() => props.profileName)
const badgeState = computed(() => {
  if (isRunning.value) return 'running_sync'
  if (runningJob.value) return 'running'
  if (externalBusy.value) {
    return props.daemonState?.active_operation === 'external' ? 'external' : 'running'
  }
  return state.value
})
const previewBlocked = computed(() => isRunning.value ? t('workspace.syncInProgress') : blockedReason.value)

async function sync() {
  if (busy.value || (blockedReason.value && !isRunning.value && !isLocked.value)) return
  if (isLocked.value) {
    emit('open-unlock')
    return
  }
  busy.value = true
  try {
    const response = isRunning.value
      ? await cancelProfileSync(props.profileName)
      : await triggerSync({ profile: props.profileName })
    const failure = response?.failures?.[0]
    pushToast(failure ? failure.detail || t('overview.actionFailed') :
      t(isRunning.value ? 'overview.syncCancelled' : 'overview.syncQueued'), failure ? 'error' : 'ok')
    emit('refresh')
  } catch (error) {
    pushToast(error?.message || t('overview.actionFailed'), 'error')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <HubTopbar @open-system="emit('open-system')" />
  <header class="k-workspace-header">
    <RouterLink :to="{ name: 'hub', query: { profile: profileName } }" class="k-back-link">← {{ t('workspace.backToProfiles') }}</RouterLink>
    <div class="k-section-header k-workspace-heading">
      <div class="k-row">
        <VaultIcon :profile="profileName" :icon="activeProfile?.icon" size="md" />
        <h1>{{ profileName }}</h1>
        <StatusBadge :state="badgeState" />
      </div>
      <div v-if="profiles.some((profile) => profile.name === profileName)" class="k-row k-workspace-actions">
        <select v-if="profiles.length > 1" class="k-input k-profile-picker" :value="profileName"
          :aria-label="t('overview.switchProfile')" @change="emit('switch-profile', $event.target.value)">
          <option v-for="profile in profiles" :key="profile.name" :value="profile.name">{{ profile.name }}</option>
        </select>
        <button type="button" class="k-btn" :disabled="Boolean(previewBlocked)" :title="previewBlocked || undefined"
          @click="emit('preview')">{{ t('overview.preview') }}</button>
        <button type="button" class="k-btn" :class="isRunning ? 'k-btn--danger' : 'k-btn--primary'"
          :disabled="busy || (!isRunning && !isLocked && (daemonState?.paused || Boolean(blockedReason)))"
          :title="!isRunning && !isLocked ? blockedReason || undefined : undefined" @click="sync">
          {{ isLocked ? t('profile.unlock') : isRunning ? t('profile.cancelSync') : t('profile.syncNow') }}
        </button>
      </div>
    </div>
    <div class="k-workspace-nav">
      <nav class="k-tabs" :aria-label="t('overview.profileSections')">
        <button v-for="tab in tabs" :key="tab" type="button" class="k-tab"
          :class="{ 'k-tab--active': activeTab === tab }" :aria-current="activeTab === tab ? 'page' : undefined"
          @click="emit('select-tab', tab)">
          {{ t('workspace.tab.' + tab) }}
          <span v-if="tab === 'conflicts' && conflictCount > 0" class="k-tab-count">{{ conflictCount }}</span>
        </button>
      </nav>
      <button
        type="button"
        class="k-tab k-maintenance-link"
        :class="{ 'k-tab--active': activeTab === 'maintenance', 'k-maintenance-link--busy': Boolean(runningJob) }"
        :aria-current="activeTab === 'maintenance' ? 'page' : undefined"
        @click="emit('select-tab', 'maintenance')"
      >
        <svg viewBox="0 0 20 20" fill="none" class="k-maintenance-ico" aria-hidden="true">
          <path
            d="M12.7 3.7a4.2 4.2 0 00-5.4 5.4L3.6 12.8a1.4 1.4 0 002 2l3.7-3.7a4.2 4.2 0 005.4-5.4l-2.1 2.1-2-2 2.1-2.1z"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linejoin="round"
          />
        </svg>
        <span>{{ t('workspace.tab.maintenance') }}</span>
        <span v-if="runningJob" class="k-maintenance-dot" aria-hidden="true" />
      </button>
    </div>
  </header>
</template>
