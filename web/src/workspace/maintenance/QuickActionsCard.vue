<script setup>
import { computed, onUnmounted, reactive, ref, watch } from 'vue'
import ConfirmModal from '../../components/ConfirmModal.vue'
import { startMaintenanceJob } from '../../api/maintenance.js'
import { fetchRemoteWriters } from '../../api/remote.js'
import { pushToast } from '../../composables/useToasts.js'
import { friendlyBusyError } from '../../utils/format.js'
import { t } from '../../i18n/index.js'

const props = defineProps({
  profile: { type: String, required: true },
  blockedReason: { type: String, default: '' },
})
const emit = defineEmits(['job-created', 'working'])
const submitting = ref(false)
const recovery = ref(null)
const recoveryBusy = ref(false)
const working = computed(() => submitting.value || recoveryBusy.value)
const busy = computed(() => Boolean(props.blockedReason) || working.value)
watch(working, (value) => emit('working', value), { flush: 'sync' })
const recoveryError = ref('')
const selectedWriter = ref('')
const selectedBarrier = ref('')
const confirmation = ref(null)
const sync = reactive({
  mode: '', audit: false, allowEmpty: false, bandwidth: '', concurrency: '',
})

const actions = [
  { id: 'fsck', title: 'fsckTitle', description: 'fsckDesc' },
  { id: 'gc', title: 'gcTitle', description: 'gcDesc' },
  { id: 'repack', title: 'repackTitle', description: 'repackDesc' },
]

async function queue(operation, payload) {
  if (busy.value) return false
  submitting.value = true
  try {
    const job = await startMaintenanceJob(props.profile, operation, payload)
    const toastKey = payload?.dry_run
      ? 'maintenance.simulationQueued'
      : operation === 'fsck'
        ? 'maintenance.queued'
        : 'maintenance.executionQueued'
    pushToast(t(toastKey), 'info')
    emit('job-created', job)
    return true
  } catch (err) {
    pushToast(err?.message || t('overview.actionFailed'), 'error')
    return false
  } finally {
    submitting.value = false
  }
}

function runSync() {
  if (busy.value) return
  const payload = {
    initial: sync.mode === 'initial',
    repair: sync.mode === 'repair',
    audit_inventory: sync.mode !== 'initial' && sync.audit,
    allow_empty_local: sync.allowEmpty,
  }
  if (sync.bandwidth.trim()) payload.bandwidth_limit = sync.bandwidth.trim()
  if (sync.concurrency !== '') payload.transfer_concurrency = Number(sync.concurrency)
  if (payload.allow_empty_local) ask('sync', payload)
  else queue('sync', payload)
}

function ask(operation, payload = { dry_run: false, confirm: true }) {
  confirmation.value = { operation, payload }
}

async function runConfirmed() {
  if (busy.value || !confirmation.value) return
  const { operation, payload } = confirmation.value
  if (await queue(operation, payload)) {
    confirmation.value = null
    if (operation === 'remove-writer') selectedWriter.value = ''
    if (operation === 'remove-barrier') selectedBarrier.value = ''
  }
}

let recoveryRequest = null

function resetRecoveryState() {
  recoveryRequest?.abort()
  recoveryRequest = null
  recoveryBusy.value = false
  recovery.value = null
  recoveryError.value = ''
  selectedWriter.value = ''
  selectedBarrier.value = ''
}

watch(() => props.profile, resetRecoveryState)
onUnmounted(resetRecoveryState)

async function loadRecovery() {
  if (busy.value) return
  recoveryRequest?.abort()
  const controller = new AbortController()
  recoveryRequest = controller
  const targetProfile = props.profile
  recoveryBusy.value = true
  recoveryError.value = ''
  recovery.value = null
  selectedWriter.value = ''
  selectedBarrier.value = ''
  try {
    const res = await fetchRemoteWriters(targetProfile, controller.signal)
    if (controller.signal.aborted || props.profile !== targetProfile) return
    recovery.value = res
  } catch (err) {
    if (!controller.signal.aborted && props.profile === targetProfile) {
      recoveryError.value = friendlyBusyError(err, t)
    }
  } finally {
    if (recoveryRequest === controller && props.profile === targetProfile) {
      recoveryBusy.value = false
    }
  }
}

function markerLabel(marker) {
  return marker.machine_name ? marker.machine_name + ' · ' + marker.identifier : marker.identifier
}
</script>

<template>
  <section class="k-card">
    <header class="k-card-header"><strong>{{ t('maintenance.actionsTitle') }}</strong></header>
    <div class="k-card-body k-stack">
      <div class="k-grid-3">
        <div v-for="action in actions" :key="action.id" class="k-action-tile">
          <strong>{{ t('maintenance.' + action.title) }}</strong>
          <p class="k-muted">{{ t('maintenance.' + action.description) }}</p>
          <div class="k-row k-row--wrap">
            <button v-if="action.id !== 'fsck'" type="button" class="k-btn k-btn--compact"
              :disabled="busy" :title="t('maintenance.simulateHint')"
              @click="queue(action.id, { dry_run: true })">{{ t('maintenance.simulate') }}</button>
            <button v-if="action.id === 'fsck'" type="button" class="k-btn k-btn--primary k-btn--compact"
              :disabled="busy" @click="queue('fsck', {})">{{ t('maintenance.run') }}</button>
            <button v-else type="button" class="k-btn k-btn--primary k-btn--compact"
              :disabled="busy" @click="ask(action.id)">{{ t('maintenance.run') }}</button>
          </div>
        </div>
      </div>
      <details class="k-disclosure">
        <summary>{{ t('maintenance.advancedSync') }}</summary>
        <form class="k-disclosure-body k-stack" @submit.prevent="runSync">
          <div class="k-grid-3">
            <label class="k-field">
              <span>{{ t('maintenance.syncMode') }}</span>
              <select v-model="sync.mode" class="k-input">
                <option value="">{{ t('maintenance.normalSync') }}</option>
                <option value="initial">{{ t('maintenance.initialSync') }}</option>
                <option value="repair">{{ t('maintenance.repairSync') }}</option>
              </select>
            </label>
            <label class="k-field">
              <span>{{ t('settings.bandwidth') }}</span>
              <input v-model="sync.bandwidth" class="k-input" :placeholder="t('settings.defaultValue')" />
            </label>
            <label class="k-field">
              <span>{{ t('settings.concurrency') }}</span>
              <input v-model="sync.concurrency" class="k-input" type="number" min="1" max="16" />
            </label>
          </div>
          <label class="k-row">
            <input v-model="sync.audit" type="checkbox" :disabled="sync.mode === 'initial'" />
            {{ t('maintenance.auditInventory') }}
          </label>
          <label class="k-row"><input v-model="sync.allowEmpty" type="checkbox" />{{ t('maintenance.allowEmpty') }}</label>
          <div><button type="submit" class="k-btn" :disabled="busy">{{ t('profile.syncNow') }}</button></div>
        </form>
      </details>

      <details class="k-disclosure">
        <summary>{{ t('maintenance.recovery') }}</summary>
        <div class="k-disclosure-body k-stack">
          <section class="k-stack--sm">
            <strong>{{ t('operation.resolve_missing') }}</strong>
            <div class="k-row k-row--wrap">
              <button type="button" class="k-btn k-btn--compact" :disabled="busy" :title="t('maintenance.simulateHint')"
                @click="queue('resolve-missing', { dry_run: true })">{{ t('maintenance.simulate') }}</button>
              <button type="button" class="k-btn k-btn--danger k-btn--compact" :disabled="busy"
                @click="ask('resolve-missing')">{{ t('maintenance.run') }}</button>
            </div>
          </section>
          <p class="k-alert k-alert--warn">{{ t('maintenance.recoveryWarning') }}</p>
          <div>
            <button type="button" class="k-btn k-btn--compact" :disabled="busy"
              @click="loadRecovery">{{ t('maintenance.inspectMarkers') }}</button>
          </div>
          <div v-if="recoveryError" class="k-alert k-alert--error" role="alert">{{ recoveryError }}</div>
          <div v-if="recovery" class="k-grid-2">
            <div class="k-stack--sm">
              <label class="k-field">
                <span>{{ t('maintenance.writer') }}</span>
                <select v-model="selectedWriter" class="k-input" :disabled="!recovery.writers.length">
                  <option value="">{{ t(recovery.writers.length ? 'maintenance.selectMarker' : 'maintenance.noMarkers') }}</option>
                  <option v-for="writer in recovery.writers" :key="writer.identifier" :value="writer.identifier">{{ markerLabel(writer) }}</option>
                </select>
              </label>
              <button type="button" class="k-btn k-btn--danger k-btn--compact" :disabled="busy || !selectedWriter"
                @click="ask('remove-writer', { writer_id: selectedWriter })">{{ t('operation.remove_writer') }}</button>
            </div>
            <div class="k-stack--sm">
              <label class="k-field">
                <span>{{ t('maintenance.barrier') }}</span>
                <select v-model="selectedBarrier" class="k-input" :disabled="!recovery.barriers.length">
                  <option value="">{{ t(recovery.barriers.length ? 'maintenance.selectMarker' : 'maintenance.noMarkers') }}</option>
                  <option v-for="barrier in recovery.barriers" :key="barrier.identifier" :value="barrier.identifier">{{ markerLabel(barrier) }}</option>
                </select>
              </label>
              <button type="button" class="k-btn k-btn--danger k-btn--compact" :disabled="busy || !selectedBarrier"
                @click="ask('remove-barrier', { barrier_id: selectedBarrier, confirm_abandoned: true })">{{ t('operation.remove_barrier') }}</button>
            </div>
          </div>
        </div>
      </details>
    </div>
    <ConfirmModal :open="Boolean(confirmation)" :busy="working" :blocked-reason="blockedReason" :title="t('operation.' + confirmation?.operation)"
      :message="t('maintenance.confirm.' + confirmation?.operation)" danger
      @close="confirmation = null" @confirm="runConfirmed" />
  </section>
</template>

<style scoped>
.k-action-tile {
  display: flex;
  flex-direction: column;
  align-items: start;
  padding: 14px;
  border: 1px solid var(--k-border-subtle);
  border-radius: var(--k-radius-sm);
  background: var(--k-input-bg);
}
.k-action-tile p {
  margin: 5px 0 12px;
  flex: 1;
}
</style>
