<script setup>
import { computed, onUnmounted, reactive, ref, watch } from 'vue'
import ConfirmModal from '../../components/ConfirmModal.vue'
import VaultIcon from '../../components/VaultIcon.vue'
import { lockProfile } from '../../api/daemon.js'
import {
  deleteProfile,
  deleteProfileIcon,
  listRcloneRemotes,
  testProfileConnection,
  updateProfile,
  uploadProfileIcon,
} from '../../api/profiles.js'
import { pushToast } from '../../composables/useToasts.js'
import { useProfileActivity } from '../../composables/useProfileActivity.js'
import { t } from '../../i18n/index.js'
import ProfileCloneRenameModal from './ProfileCloneRenameModal.vue'
import ProfileKeyModal from './ProfileKeyModal.vue'
import ProfileStorageModal from './ProfileStorageModal.vue'

const props = defineProps({
  profile: { type: Object, default: null },
  daemonState: { type: Object, default: null },
})

const emit = defineEmits(['refresh', 'open-unlock', 'deleted', 'renamed'])

const remotes = ref([])
const busy = ref(false)
const testResult = ref(null)
const error = ref('')
const { blockedReason } = useProfileActivity(() => props.profile?.name)
const disabled = computed(() => busy.value || Boolean(blockedReason.value))

const storageModalOpen = ref(false)
const keyModalOpen = ref(false)
const cloneRenameModal = ref({ open: false, mode: 'clone' })
const deleteOpen = ref(false)

const form = reactive({
  local_dir: '',
  remote_dir: '',
  min_history_depth: 50,
  min_history_age_hours: 168,
  sync_interval_seconds: 300,
  watch_enabled: true,
  paused: false,
  bandwidth_limit: '',
  transfer_concurrency: '',
  rclone_config: '',
  allow_empty_local: false,
  icon: '',
})

const iconFileInput = ref(null)
const isCustomIcon = computed(() => form.icon.startsWith('custom:'))
const iconOptions = [
  { value: '', key: 'settings.iconAuto' },
  { value: 'preset:default', key: 'settings.iconDefault' },
  { value: 'preset:vault', key: 'settings.iconVault' },
  { value: 'preset:folder', key: 'settings.iconFolder' },
  { value: 'preset:code', key: 'settings.iconCode' },
  { value: 'preset:docs', key: 'settings.iconDocs' },
  { value: 'preset:photos', key: 'settings.iconPhotos' },
  { value: 'preset:music', key: 'settings.iconMusic' },
  { value: 'preset:archive', key: 'settings.iconArchive' },
  { value: 'preset:shield', key: 'settings.iconShield' },
]

const isLocked = computed(() => Boolean(props.daemonState?.locked))
const isMemoryMode = computed(() => props.profile?.key_storage === 'memory')

let remotesRequest = null
let actionRequest = null

function abortRequests() {
  remotesRequest?.abort()
  remotesRequest = null
  actionRequest?.abort()
  actionRequest = null
}

onUnmounted(abortRequests)

watch(
  () => props.profile?.name,
  async (name) => {
    abortRequests()
    busy.value = false
    error.value = ''
    testResult.value = null
    const prof = props.profile
    if (!name || !prof) return
    form.local_dir = prof.local_dir || ''
    form.remote_dir = prof.remote_dir || ''
    form.min_history_depth = prof.min_history_depth ?? 50
    form.min_history_age_hours = prof.min_history_age_hours ?? 168
    form.sync_interval_seconds = prof.sync_interval_seconds ?? 300
    form.watch_enabled = prof.watch_enabled ?? true
    form.paused = Boolean(prof.paused)
    form.bandwidth_limit = prof.bandwidth_limit || ''
    form.transfer_concurrency = prof.transfer_concurrency ?? ''
    form.rclone_config = prof.rclone_config || ''
    form.allow_empty_local = false
    form.icon = prof.icon === 'auto' ? '' : (prof.icon || '')
    const controller = new AbortController()
    remotesRequest = controller
    try {
      const res = await listRcloneRemotes({ signal: controller.signal })
      if (!controller.signal.aborted && props.profile?.name === name) {
        remotes.value = Array.isArray(res?.remotes) ? res.remotes : []
      }
    } catch {
      if (!controller.signal.aborted && props.profile?.name === name) {
        remotes.value = []
      }
    }
  },
  { immediate: true }
)

async function saveSettings() {
  if (!props.profile || disabled.value) return
  const targetName = props.profile.name
  busy.value = true
  error.value = ''
  try {
    await updateProfile(targetName, {
      local_dir: form.local_dir.trim(),
      remote_dir: form.remote_dir.trim(),
      min_history_depth: Number(form.min_history_depth),
      min_history_age_hours: Number(form.min_history_age_hours),
      sync_interval_seconds: Number(form.sync_interval_seconds),
      watch_enabled: Boolean(form.watch_enabled),
      paused: Boolean(form.paused),
      bandwidth_limit: form.bandwidth_limit.trim() ? form.bandwidth_limit.trim() : null,
      transfer_concurrency:
        form.transfer_concurrency === '' ? null : Number(form.transfer_concurrency),
      rclone_config: form.rclone_config.trim() ? form.rclone_config.trim() : null,
      allow_empty_local: Boolean(form.allow_empty_local),
      icon: form.icon || '',
    })
    if (props.profile?.name !== targetName) return
    pushToast(t('settings.saved'), 'ok')
    emit('refresh')
  } catch (err) {
    if (props.profile?.name === targetName) {
      error.value = err?.message || 'Failed to save changes'
    }
  } finally {
    if (props.profile?.name === targetName) busy.value = false
  }
}

async function runConnectionTest() {
  if (!props.profile || disabled.value) return
  actionRequest?.abort()
  const controller = new AbortController()
  actionRequest = controller
  const targetName = props.profile.name
  busy.value = true
  testResult.value = null
  try {
    const res = await testProfileConnection(targetName, { signal: controller.signal })
    if (controller.signal.aborted || props.profile?.name !== targetName) return
    testResult.value = {
      ok: Boolean(res?.ready),
      text: res?.ready ? t('settings.connected') :
        res?.detail || t('settings.connectionProblem', { state: res?.vault_state || '—' }),
    }
  } catch (err) {
    if (!controller.signal.aborted && props.profile?.name === targetName) {
      testResult.value = { ok: false, text: err?.message || 'Connection test failed.' }
    }
  } finally {
    if (actionRequest === controller && props.profile?.name === targetName) busy.value = false
  }
}

async function handleLock() {
  if (!props.profile || disabled.value) return
  const targetName = props.profile.name
  busy.value = true
  try {
    await lockProfile(targetName)
    if (props.profile?.name !== targetName) return
    pushToast(`Locked "${targetName}"`, 'ok')
    emit('refresh')
  } catch (err) {
    if (props.profile?.name === targetName) {
      pushToast(err?.message || 'Failed to lock profile', 'error')
    }
  } finally {
    if (props.profile?.name === targetName) busy.value = false
  }
}

function openIconPicker() {
  if (disabled.value) return
  iconFileInput.value?.click()
}

async function handleIconFile(event) {
  const file = event?.target?.files?.[0]
  if (event?.target) event.target.value = ''
  if (!file || !props.profile || disabled.value) return
  if (file.size > 512 * 1024) {
    error.value = t('settings.iconTooLarge')
    return
  }
  const targetName = props.profile.name
  busy.value = true
  error.value = ''
  try {
    const res = await uploadProfileIcon(targetName, file)
    if (props.profile?.name !== targetName) return
    if (res?.icon) form.icon = res.icon
    pushToast(t('settings.saved'), 'ok')
    emit('refresh')
  } catch (err) {
    if (props.profile?.name === targetName) {
      error.value = err?.message || t('settings.iconInvalid')
    }
  } finally {
    if (props.profile?.name === targetName) busy.value = false
  }
}

async function handleRemoveCustomIcon() {
  if (!props.profile || disabled.value) return
  const targetName = props.profile.name
  busy.value = true
  error.value = ''
  try {
    const res = await deleteProfileIcon(targetName)
    if (props.profile?.name !== targetName) return
    form.icon = res?.icon || ''
    pushToast(t('settings.saved'), 'ok')
    emit('refresh')
  } catch (err) {
    if (props.profile?.name === targetName) {
      error.value = err?.message || 'Failed to remove custom icon'
    }
  } finally {
    if (props.profile?.name === targetName) busy.value = false
  }
}

async function confirmDelete() {
  if (!props.profile || disabled.value) return
  busy.value = true
  try {
    await deleteProfile(props.profile.name)
    deleteOpen.value = false
    pushToast(`Deleted profile "${props.profile.name}"`, 'ok')
    emit('deleted')
  } catch (err) {
    pushToast(err?.message || 'Failed to delete profile', 'error')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div v-if="profile" class="k-workspace-scroll">
    <div v-if="blockedReason" class="k-alert k-alert--info k-settings-status" role="status">{{ blockedReason }}</div>
    <div class="k-settings-layout">
      <section class="k-card">
        <header class="k-card-header">
          <strong>{{ t('settings.foldersTitle') }}</strong>
          <button
            type="button"
            class="k-btn k-btn--compact"
            :disabled="disabled"
            @click="runConnectionTest"
          >
            {{ t('settings.testConnection') }}
          </button>
        </header>

        <form class="k-card-body k-stack" @submit.prevent="saveSettings">
          <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>
          <div
            v-if="testResult"
            class="k-alert"
            :class="testResult.ok ? 'k-alert--ok' : 'k-alert--error'"
          >
            {{ testResult.text }}
          </div>

          <div class="k-grid-2">
            <div class="k-field">
              <label for="settings-local" class="k-field-label">{{ t('wizard.localDir') }}</label>
              <input id="settings-local" v-model="form.local_dir" class="k-input k-mono" required />
            </div>
            <div class="k-field">
              <label for="settings-remote" class="k-field-label">{{ t('wizard.remoteDir') }}</label>
              <input id="settings-remote" v-model="form.remote_dir" class="k-input k-mono" required />
              <div v-if="remotes.length > 0" class="k-row k-row--wrap">
                <span class="k-field-hint">rclone:</span>
                <button
                  v-for="r in remotes"
                  :key="r"
                  type="button"
                  class="k-btn k-btn--ghost k-btn--compact"
                  @click="form.remote_dir = `${r.endsWith(':') ? r : `${r}:`}kasumi/${profile.name}`"
                >
                  {{ r }}
                </button>
              </div>
            </div>
          </div>

          <div class="k-grid-2 k-settings-schedule">
            <div class="k-stack--sm">
              <label class="k-row">
                <input v-model="form.watch_enabled" type="checkbox" />
                <span>{{ t('settings.watch') }}</span>
              </label>
              <label class="k-row">
                <input v-model="form.paused" type="checkbox" />
                <span>{{ t('status.paused') }}</span>
              </label>
            </div>
            <label class="k-field">
              <span class="k-field-label">{{ t('settings.interval') }}</span>
              <input v-model.number="form.sync_interval_seconds" type="number" min="0" max="86400" class="k-input" />
              <span class="k-field-hint">{{ t('settings.intervalHint') }}</span>
            </label>
          </div>

          <details class="k-disclosure">
            <summary>{{ t('settings.advancedSync') }}</summary>
            <div class="k-disclosure-body k-grid-2">
              <div class="k-field">
                <label class="k-field-label">{{ t('settings.bandwidth') }}</label>
                <input v-model="form.bandwidth_limit" class="k-input k-mono" :placeholder="t('settings.unlimited')" />
              </div>
              <div class="k-field">
                <label class="k-field-label">{{ t('settings.depth') }}</label>
                <input
                  v-model.number="form.min_history_depth"
                  type="number"
                  min="1"
                  max="4096"
                  class="k-input"
                />
              </div>
              <div class="k-field">
                <label class="k-field-label">{{ t('settings.age') }}</label>
                <input
                  v-model.number="form.min_history_age_hours"
                  type="number"
                  min="1"
                  max="8760"
                  class="k-input"
                />
              </div>
              <div class="k-field">
                <label class="k-field-label">{{ t('settings.concurrency') }}</label>
                <input
                  v-model="form.transfer_concurrency"
                  type="number"
                  min="1"
                  max="16"
                  class="k-input"
                  :placeholder="t('settings.defaultValue')"
                />
              </div>
              <div class="k-field">
                <label class="k-field-label">{{ t('settings.rcloneConfig') }}</label>
                <input v-model="form.rclone_config" class="k-input k-mono" :placeholder="t('settings.defaultValue')" />
              </div>
              <label class="k-row k-text-sm">
                <input v-model="form.allow_empty_local" type="checkbox" />
                <span>{{ t('settings.emptyLocal') }}</span>
              </label>
            </div>
          </details>

          <div class="k-field">
            <label for="settings-icon" class="k-field-label">{{ t('settings.iconLabel') }}</label>
            <div class="k-row k-row--wrap">
              <VaultIcon :profile="profile.name" :icon="form.icon" size="md" />
              <select id="settings-icon" v-model="form.icon" class="k-input k-icon-select">
                <option v-if="isCustomIcon" :value="form.icon">
                  {{ t('settings.iconCustom') }}
                </option>
                <option v-for="opt in iconOptions" :key="opt.value || 'auto'" :value="opt.value">
                  {{ t(opt.key) }}
                </option>
              </select>
              <input
                ref="iconFileInput"
                type="file"
                accept=".png,.ico,.webp,.jpg,.jpeg,.bmp"
                class="k-sr-only"
                @change="handleIconFile"
              />
              <button type="button" class="k-btn k-btn--compact" :disabled="disabled" @click="openIconPicker">
                {{ t('settings.iconChooseFile') }}
              </button>
              <button
                v-if="isCustomIcon"
                type="button"
                class="k-btn k-btn--compact"
                :disabled="disabled"
                @click="handleRemoveCustomIcon"
              >
                {{ t('settings.iconRemoveCustom') }}
              </button>
            </div>
            <span class="k-field-hint">{{ t('settings.iconHint') }}</span>
          </div>

          <div class="k-row">
            <button type="submit" class="k-btn k-btn--primary" :disabled="disabled">
              {{ t('common.save') }}
            </button>
          </div>
        </form>
      </section>

      <aside class="k-stack">
        <details class="k-disclosure">
          <summary>{{ t('settings.securityTitle') }}</summary>
          <div class="k-card-body k-row k-row--wrap">
            <button
              v-if="isLocked"
              type="button"
              class="k-btn k-btn--primary k-btn--compact"
              @click="emit('open-unlock')"
            >
              {{ t('profile.unlock') }}
            </button>
            <button
              v-else-if="isMemoryMode"
              type="button"
              class="k-btn k-btn--compact"
              :disabled="disabled"
              @click="handleLock"
            >
              {{ t('profile.lock') }}
            </button>
            <button type="button" class="k-btn k-btn--compact" :disabled="disabled" @click="storageModalOpen = true">
              {{ t('settings.storageChange') }}
            </button>
            <button type="button" class="k-btn k-btn--compact" :disabled="disabled" @click="keyModalOpen = true">
              {{ t('settings.updateKey') }}
            </button>
          </div>
        </details>

        <details class="k-disclosure">
          <summary>{{ t('settings.manageTitle') }}</summary>
          <div class="k-card-body k-row k-row--wrap">
            <button
              type="button"
              class="k-btn k-btn--compact"
              :disabled="disabled"
              @click="cloneRenameModal = { open: true, mode: 'clone' }"
            >
              {{ t('settings.clone') }}
            </button>
            <button
              type="button"
              class="k-btn k-btn--compact"
              :disabled="disabled"
              @click="cloneRenameModal = { open: true, mode: 'rename' }"
            >
              {{ t('settings.rename') }}
            </button>
            <button type="button" class="k-btn k-btn--danger k-btn--compact" :disabled="disabled" @click="deleteOpen = true">
              {{ t('settings.delete') }}
            </button>
          </div>
        </details>
      </aside>

      <ProfileStorageModal
        :open="storageModalOpen"
        :profile="profile"
        :blocked-reason="blockedReason"
        @close="storageModalOpen = false"
        @saved="emit('refresh')"
      />
      <ProfileKeyModal
        :open="keyModalOpen"
        :profile="profile"
        :blocked-reason="blockedReason"
        @close="keyModalOpen = false"
        @saved="emit('refresh')"
      />
      <ProfileCloneRenameModal
        :open="cloneRenameModal.open"
        :mode="cloneRenameModal.mode"
        :profile="profile"
        :blocked-reason="blockedReason"
        @close="cloneRenameModal = { open: false, mode: 'clone' }"
        @cloned="emit('refresh')"
        @renamed="(next) => emit('renamed', next)"
      />
      <ConfirmModal
        :open="deleteOpen"
        :title="t('settings.deleteTitle', { name: profile.name })"
        :message="t('settings.deleteBody')"
        :confirm-label="t('common.delete')"
        danger
        :busy="busy"
        :blocked-reason="blockedReason"
        @close="deleteOpen = false"
        @confirm="confirmDelete"
      />
    </div>
  </div>
</template>

<style scoped>
.k-settings-status { margin-bottom: 12px; }
.k-icon-select { flex: 1 1 200px; min-width: 0; }
.k-sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
</style>
