<script setup>
import { computed, ref } from 'vue'
import StatusBadge from '../components/StatusBadge.vue'
import SyncProgressPanel from '../components/SyncProgressPanel.vue'
import VaultIcon from '../components/VaultIcon.vue'
import ProfileOverview from '../workspace/ProfileOverview.vue'
import { cancelProfileSync, pauseProfile, resumeProfile, triggerSync } from '../api/daemon.js'
import { pushToast } from '../composables/useToasts.js'
import { useProfileActivity } from '../composables/useProfileActivity.js'
import { formatDurationMs, formatTimestamp } from '../utils/format.js'
import { resolveJobDurationMs } from '../utils/jobFormat.js'
import { t } from '../i18n/index.js'

const props = defineProps({
  profile: { type: Object, required: true },
  daemonState: { type: Object, default: null },
  expanded: Boolean,
})
const emit = defineEmits(['toggle', 'edit', 'browse', 'preview', 'unlock', 'refresh'])
const busy = ref(false)
const live = computed(() => props.daemonState || props.profile.daemon || {})
const isPaused = computed(() => Boolean(live.value.paused ?? props.profile.paused))
const isLocked = computed(() => live.value.locked || live.value.state === 'locked')
const { runningJob, blockedReason } = useProfileActivity(() => props.profile.name)
const isRunning = computed(() => ['running_sync', 'syncing'].includes(live.value.state || props.profile.state))
const state = computed(() => {
  if (isRunning.value) return 'running_sync'
  if (runningJob.value) return 'running'
  if (live.value.busy) return live.value.active_operation === 'external' ? 'external' : 'running'
  if (isLocked.value) return 'locked'
  if (isPaused.value) return 'paused'
  if ((!live.value.state || live.value.state === 'idle') && ['initialized', 'problem'].includes(props.profile.state)) {
    return props.profile.state
  }
  return live.value.state || props.profile.state || 'unknown'
})
const previewBlocked = computed(() => isRunning.value ? t('workspace.syncInProgress') : blockedReason.value)
const lastSync = computed(() => props.profile.activity?.last_complete_sync?.finished_at || live.value.last_sync_finished_at)
const lastSyncDuration = computed(() =>
  resolveJobDurationMs(
    props.profile.activity?.last_complete_sync,
    live.value.last_sync_finished_at,
    live.value.last_sync_started_at
  )
)
const rowId = computed(() => 'profile-' + props.profile.name)

async function runAction(action, label) {
  busy.value = true
  try {
    const response = await action()
    if (response?.failures?.length) {
      pushToast(response.failures[0].detail || t('overview.actionFailed'), 'error')
    } else {
      pushToast(props.profile.name + ' · ' + label, 'ok')
    }
    emit('refresh')
  } catch (error) {
    pushToast(error?.message || t('overview.actionFailed'), 'error')
  } finally {
    busy.value = false
  }
}

function sync() {
  if (isLocked.value) emit('unlock', props.profile)
  else if (isRunning.value) runAction(() => cancelProfileSync(props.profile.name), t('overview.syncCancelled'))
  else if (!blockedReason.value) runAction(() => triggerSync({ profile: props.profile.name }), t('overview.syncQueued'))
}
</script>

<template>
  <article class="k-profile-row" :class="{ 'is-open': expanded }">
    <button :id="'summary-' + profile.name" type="button" class="k-profile-summary" :aria-expanded="expanded"
      :aria-controls="expanded ? rowId : undefined" @click="emit('toggle', profile.name)">
      <span class="k-profile-ident">
        <VaultIcon :profile="profile.name" :icon="profile.icon" size="sm" />
        <span class="k-truncate">{{ profile.name }}</span>
      </span>
      <span class="k-profile-last">
        {{ lastSync ? formatTimestamp(lastSync) : t('profile.neverSynced') }}
        <span v-if="lastSync && lastSyncDuration != null" class="k-faint"> · {{ formatDurationMs(lastSyncDuration) }}</span>
      </span>
      <span class="k-profile-state"><StatusBadge :state="state" /></span>
      <span class="k-chevron" aria-hidden="true"></span>
    </button>
    <SyncProgressPanel v-if="isRunning" :live="live" />
    <div v-if="expanded" :id="rowId" class="k-profile-body">
      <ProfileOverview :profile="profile" :daemon-state="daemonState" />
      <footer class="k-profile-actions">
        <button type="button" class="k-btn k-btn--primary"
          :disabled="busy || (!isLocked && !isRunning && (isPaused || Boolean(blockedReason)))"
          :title="!isLocked && !isRunning ? blockedReason || undefined : undefined" @click="sync">
          {{ isLocked ? t('profile.unlock') : isRunning ? t('profile.cancelSync') : t('profile.syncNow') }}
        </button>
        <button type="button" class="k-btn" :disabled="busy"
          @click="runAction(() => isPaused ? resumeProfile(profile.name) : pauseProfile(profile.name), t(isPaused ? 'overview.resumed' : 'overview.paused'))">
          {{ t(isPaused ? 'profile.resume' : 'profile.pause') }}
        </button>
        <button type="button" class="k-btn" :disabled="Boolean(previewBlocked)" :title="previewBlocked || undefined"
          @click="emit('preview', profile)">{{ t('overview.preview') }}</button>
        <button type="button" class="k-btn" @click="emit('edit', profile)">{{ t('overview.edit') }}</button>
        <button type="button" class="k-btn k-btn--ghost" @click="emit('browse', profile)">{{ t('overview.browse') }} <span aria-hidden="true">↗</span></button>
      </footer>
    </div>
  </article>
</template>
