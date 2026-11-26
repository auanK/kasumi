<script setup>
import { computed, onUnmounted, reactive, ref, watch } from 'vue'
import BaseModal from '../components/BaseModal.vue'
import PasswordField from '../components/PasswordField.vue'
import { createProfile, listRcloneRemotes } from '../api/profiles.js'
import { pushToast } from '../composables/useToasts.js'
import { t } from '../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'created'])

const step = ref(1)
const remotes = ref([])
const busy = ref(false)
const error = ref('')

const form = reactive({
  name: '',
  local_dir: '',
  remote_dir: '',
  key_storage: 'vault',
  credMode: 'password',
  password: '',
  salt_password: '',
  master_key: '',
  verify: true,
  watch_enabled: true,
  sync_interval_seconds: 300,
  min_history_depth: 50,
  min_history_age_hours: 168,
  bandwidth_limit: '',
  transfer_concurrency: '',
  rclone_config: '',
})

function clearSecrets() {
  form.password = ''
  form.salt_password = ''
  form.master_key = ''
}

onUnmounted(clearSecrets)

watch(
  () => props.open,
  async (open) => {
    clearSecrets()
    error.value = ''
    step.value = 1
    if (!open) return
    Object.assign(form, {
      name: '',
      local_dir: '',
      remote_dir: '',
      key_storage: 'vault',
      credMode: 'password',
      verify: true,
      watch_enabled: true,
      sync_interval_seconds: 300,
      min_history_depth: 50,
      min_history_age_hours: 168,
      bandwidth_limit: '',
      transfer_concurrency: '',
      rclone_config: '',
    })
    try {
      const res = await listRcloneRemotes()
      remotes.value = Array.isArray(res?.remotes) ? res.remotes : []
    } catch {
      remotes.value = []
    }
  },
  { immediate: true }
)

const canProceedStep1 = computed(() =>
  Boolean(form.name.trim() && form.local_dir.trim() && form.remote_dir.trim())
)

function applyRemote(remoteName) {
  const clean = remoteName.endsWith(':') ? remoteName : `${remoteName}:`
  form.remote_dir = `${clean}kasumi/${form.name.trim() || 'vault'}`
}

async function onSubmit() {
  error.value = ''
  busy.value = true
  try {
    const payload = {
      name: form.name.trim(),
      local_dir: form.local_dir.trim(),
      remote_dir: form.remote_dir.trim(),
      key_storage: form.key_storage,
      verify: Boolean(form.verify),
      watch_enabled: Boolean(form.watch_enabled),
      sync_interval_seconds: Number(form.sync_interval_seconds),
      min_history_depth: Number(form.min_history_depth),
      min_history_age_hours: Number(form.min_history_age_hours),
    }
    if (form.bandwidth_limit.trim()) payload.bandwidth_limit = form.bandwidth_limit.trim()
    if (form.transfer_concurrency !== '') {
      payload.transfer_concurrency = Number(form.transfer_concurrency)
    }
    if (form.rclone_config.trim()) payload.rclone_config = form.rclone_config.trim()
    if (form.credMode === 'master_key') {
      payload.master_key = form.master_key.trim()
    } else {
      payload.password = form.password
      payload.salt_password = form.salt_password
    }
    await createProfile(payload)
    clearSecrets()
    pushToast(`Profile "${payload.name}" created`, 'ok')
    emit('created', payload.name)
    emit('close')
  } catch (err) {
    error.value = err?.message || 'Failed to create profile'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <BaseModal :open="open" :title="t('hub.newProfile')" @close="emit('close')">
    <div class="k-segmented k-wizard-steps">
      <button
        type="button"
        class="k-seg-btn"
        :class="{ 'k-seg-btn--active': step === 1 }"
        @click="step = 1"
      >
        {{ t('wizard.step1') }}
      </button>
      <button
        type="button"
        class="k-seg-btn"
        :class="{ 'k-seg-btn--active': step === 2 }"
        :disabled="!canProceedStep1"
        @click="canProceedStep1 && (step = 2)"
      >
        {{ t('wizard.step2') }}
      </button>
    </div>

    <div v-if="error" class="k-alert k-alert--error">{{ error }}</div>

    <div v-if="step === 1" class="k-stack">
      <div class="k-field">
        <label class="k-field-label">{{ t('wizard.name') }}</label>
        <input
          v-model="form.name"
          data-testid="wizard-name"
          class="k-input"
          placeholder="work"
          :disabled="busy"
        />
      </div>

      <div class="k-field">
        <label class="k-field-label">{{ t('wizard.localDir') }}</label>
        <input
          v-model="form.local_dir"
          data-testid="wizard-local"
          class="k-input k-mono"
          placeholder="/home/user/Documents"
          :disabled="busy"
        />
      </div>

      <div class="k-field">
        <label class="k-field-label">{{ t('wizard.remoteDir') }}</label>
        <input
          v-model="form.remote_dir"
          data-testid="wizard-remote"
          class="k-input k-mono"
          placeholder="gdrive:kasumi/work"
          :disabled="busy"
        />
        <div v-if="remotes.length > 0" class="k-row k-row--wrap">
          <span class="k-field-hint">{{ t('wizard.remoteSuggestions') }}</span>
          <button
            v-for="r in remotes"
            :key="r"
            type="button"
            class="k-btn k-btn--ghost k-btn--compact"
            @click="applyRemote(r)"
          >
            {{ r }}
          </button>
        </div>
      </div>
    </div>

    <form v-else id="wizard-create-form" class="k-stack" @submit.prevent="onSubmit">
      <div class="k-field">
        <span class="k-field-label">{{ t('wizard.storageTitle') }}</span>
        <div class="k-grid-3">
          <button
            type="button"
            class="k-choice-card"
            :class="{ 'k-choice-card--active': form.key_storage === 'vault' }"
            @click="form.key_storage = 'vault'"
          >
            <strong>{{ t('wizard.storageVault') }}</strong>
            <span class="k-faint k-text-xs">{{ t('wizard.storageVaultDesc') }}</span>
          </button>
          <button
            type="button"
            class="k-choice-card"
            :class="{ 'k-choice-card--active': form.key_storage === 'file' }"
            @click="form.key_storage = 'file'"
          >
            <strong>{{ t('wizard.storageFile') }}</strong>
            <span class="k-faint k-text-xs">{{ t('wizard.storageFileDesc') }}</span>
          </button>
          <button
            type="button"
            class="k-choice-card"
            :class="{ 'k-choice-card--active': form.key_storage === 'memory' }"
            @click="form.key_storage = 'memory'"
          >
            <strong>{{ t('wizard.storageMemory') }}</strong>
            <span class="k-faint k-text-xs">{{ t('wizard.storageMemoryDesc') }}</span>
          </button>
        </div>
      </div>

      <div class="k-row k-row--lg">
        <label class="k-row">
          <input v-model="form.credMode" type="radio" value="password" />
          <span>{{ t('wizard.credPassword') }}</span>
        </label>
        <label class="k-row">
          <input v-model="form.credMode" type="radio" value="master_key" />
          <span>{{ t('wizard.credMasterKey') }}</span>
        </label>
      </div>

      <div v-if="form.credMode === 'password'" class="k-grid-2">
        <PasswordField
          v-model="form.password"
          label="Vault Password (min 12 chars)"
          autocomplete="new-password"
          required
          :disabled="busy"
        />
        <PasswordField
          v-model="form.salt_password"
          label="Salt Password (min 16 chars)"
          autocomplete="new-password"
          required
          :disabled="busy"
        />
      </div>
      <PasswordField
        v-else
        v-model="form.master_key"
        :label="t('wizard.credMasterKey')"
        autocomplete="off"
        required
        :disabled="busy"
      />

      <label class="k-row k-text-sm">
        <input v-model="form.verify" type="checkbox" />
        <span>{{ t('wizard.verifyBeforeSave') }}</span>
      </label>

      <details class="k-disclosure">
        <summary>{{ t('wizard.advanced') }}</summary>
        <div class="k-disclosure-body k-stack">
          <div class="k-grid-2">
            <div class="k-field">
              <label class="k-field-label">Sync interval (seconds, 0 = manual)</label>
              <input
                v-model.number="form.sync_interval_seconds"
                type="number"
                min="0"
                max="86400"
                class="k-input"
              />
            </div>
            <div class="k-field">
              <label class="k-field-label">Bandwidth limit (e.g. 5M)</label>
              <input v-model="form.bandwidth_limit" class="k-input k-mono" placeholder="unlimited" />
            </div>
            <div class="k-field">
              <label class="k-field-label">Min history depth</label>
              <input
                v-model.number="form.min_history_depth"
                type="number"
                min="1"
                max="4096"
                class="k-input"
              />
            </div>
            <div class="k-field">
              <label class="k-field-label">Min history age (hours)</label>
              <input
                v-model.number="form.min_history_age_hours"
                type="number"
                min="1"
                max="8760"
                class="k-input"
              />
            </div>
            <div class="k-field">
              <label class="k-field-label">Concurrency (1..16)</label>
              <input
                v-model="form.transfer_concurrency"
                type="number"
                min="1"
                max="16"
                class="k-input"
                placeholder="default"
              />
            </div>
            <div class="k-field">
              <label class="k-field-label">rclone config path</label>
              <input v-model="form.rclone_config" class="k-input k-mono" placeholder="default" />
            </div>
          </div>
          <label class="k-row k-text-sm">
            <input v-model="form.watch_enabled" type="checkbox" />
            <span>Watch local folder automatically</span>
          </label>
        </div>
      </details>
    </form>

    <template #footer>
      <button type="button" class="k-btn" :disabled="busy" @click="emit('close')">
        {{ t('common.cancel') }}
      </button>
      <button
        v-if="step === 1"
        type="button"
        data-testid="wizard-next"
        class="k-btn k-btn--primary"
        :disabled="!canProceedStep1"
        @click="step = 2"
      >
        {{ t('common.next') }} →
      </button>
      <template v-else>
        <button type="button" class="k-btn" :disabled="busy" @click="step = 1">
          ← {{ t('common.back') }}
        </button>
        <button type="submit" form="wizard-create-form" class="k-btn k-btn--primary" :disabled="busy">
          {{ busy ? t('common.loading') : t('common.create') }}
        </button>
      </template>
    </template>
  </BaseModal>
</template>

<style scoped>
.k-wizard-steps {
  align-self: flex-start;
}

.k-choice-card {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 5px;
  padding: 12px;
  border: 1px solid var(--k-border);
  border-radius: var(--k-radius-sm);
  background: var(--k-input-bg);
  text-align: left;
  cursor: pointer;
}

.k-choice-card:hover {
  border-color: var(--k-text-faint);
}

.k-choice-card--active {
  border-color: var(--k-primary);
  background: var(--k-active);
}
</style>
