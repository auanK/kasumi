<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import EmptyState from '../components/EmptyState.vue'
import SystemModal from '../system/SystemModal.vue'
import PreviewChangesModal from '../workspace/PreviewChangesModal.vue'
import UnlockModal from '../workspace/settings/UnlockModal.vue'
import CreateProfileWizardModal from './CreateProfileWizardModal.vue'
import HubToolbar from './HubToolbar.vue'
import HubTopbar from './HubTopbar.vue'
import ProfileCard from './ProfileCard.vue'
import ServicePanel from './ServicePanel.vue'
import { triggerSync } from '../api/daemon.js'
import { useProfiles } from '../composables/useProfiles.js'
import { pushToast } from '../composables/useToasts.js'
import { t } from '../i18n/index.js'

const router = useRouter()
const route = useRoute()
const { profiles, loading, loaded, error, daemonMap, refreshProfiles } = useProfiles()
const search = ref('')
const filter = ref('all')
const selected = ref(typeof route.query.profile === 'string' ? route.query.profile : '')
const systemTab = ref('')
const wizardOpen = ref(false)
const unlockTarget = ref(null)
const previewTarget = ref('')
const syncingAll = ref(false)

const rows = computed(() => profiles.value.map((profile) => {
  const live = daemonMap.value.get(profile.name) || profile.daemon || {}
  return {
    profile,
    live,
    paused: Boolean(live.paused ?? profile.paused),
    attention: ['needs_attention', 'backoff', 'locked'].includes(live.state) ||
      Boolean(live.last_error || live.locked) || profile.state === 'problem',
  }
}))
const counts = computed(() => {
  const paused = rows.value.filter((row) => row.paused).length
  return { all: rows.value.length, paused, active: rows.value.length - paused,
    attention: rows.value.filter((row) => row.attention).length }
})
const filteredRows = computed(() => {
  const query = search.value.trim().toLowerCase()
  return rows.value.filter(({ profile, paused, attention }) => {
    if (filter.value === 'active' && paused) return false
    if (filter.value === 'paused' && !paused) return false
    if (filter.value === 'attention' && !attention) return false
    return !query || [profile.name, profile.local_dir, profile.remote_dir].join(' ').toLowerCase().includes(query)
  })
})
const expandedName = computed(() => selected.value)

function toggleProfile(name) {
  selected.value = selected.value === name ? '' : name
}

function revealProfile(name) {
  if (!profiles.value.some((profile) => profile.name === name)) return
  search.value = ''
  filter.value = 'all'
  selected.value = name
  nextTick(() => document.getElementById('summary-' + name)?.focus())
}

function openProfile(profile, tab) {
  router.push({ name: 'workspace', params: { name: profile.name, tab } })
}

function refresh() {
  return refreshProfiles().catch(() => {})
}

async function onCreated(name) {
  await refresh()
  revealProfile(name)
}

async function handleSyncAll() {
  syncingAll.value = true
  try {
    const response = await triggerSync({ wait: false })
    const failures = response?.failures || []
    pushToast(failures.length ? failures[0].detail || t('overview.actionFailed') : t('overview.syncQueued'),
      failures.length ? 'error' : 'ok')
    await refresh()
  } catch (err) {
    pushToast(err?.message || t('overview.actionFailed'), 'error')
  } finally {
    syncingAll.value = false
  }
}

watch([search, filter], () => {
  if (selected.value && !filteredRows.value.some(({ profile }) => profile.name === selected.value)) selected.value = ''
})
onMounted(() => {
  if (!loaded.value) refresh()
})
</script>

<template>
  <div class="k-hub-shell">
    <HubTopbar @open-system="systemTab = 'daemon'" />
    <main class="k-hub-content">
      <div v-if="error" class="k-alert k-alert--error" role="alert">
        {{ error }}
        <button type="button" class="k-btn k-btn--compact" @click="refresh">{{ t('common.refresh') }}</button>
      </div>

      <div class="k-dashboard">
        <section class="k-profile-list" aria-labelledby="profiles-heading">
          <header class="k-section-header">
            <h1 id="profiles-heading">{{ t('hub.title') }}</h1>
            <div class="k-row">
              <button v-if="profiles.length > 1" type="button" class="k-btn"
                :disabled="syncingAll || counts.active === 0" @click="handleSyncAll">{{ t('hub.syncAll') }}</button>
              <button v-if="profiles.length" type="button" class="k-btn k-btn--primary" @click="wizardOpen = true">+ {{ t('hub.newProfile') }}</button>
            </div>
          </header>

          <p v-if="loading && profiles.length === 0" class="k-muted" role="status">{{ t('common.loading') }}</p>
          <EmptyState v-else-if="profiles.length === 0 && !error" :title="t('hub.emptyTitle')" :description="t('hub.emptyHint')">
            <button type="button" class="k-btn k-btn--primary" @click="wizardOpen = true">+ {{ t('hub.newProfile') }}</button>
          </EmptyState>
          <template v-else-if="profiles.length">
            <HubToolbar v-if="profiles.length > 1" v-model:search="search" v-model:filter="filter" :counts="counts" />
            <EmptyState v-if="filteredRows.length === 0" :title="t('hub.filterEmptyTitle')" :description="t('hub.filterEmptyHint')" />
            <div v-else class="k-profile-table">
              <div class="k-profile-columns" aria-hidden="true">
                <span>{{ t('wizard.name') }}</span>
                <span class="k-profile-last">{{ t('profile.lastSync') }}</span>
                <span>{{ t('overview.status') }}</span>
              </div>
              <ProfileCard v-for="{ profile, live } in filteredRows" :key="profile.name"
                :profile="profile" :daemon-state="live" :expanded="expandedName === profile.name"
                @toggle="toggleProfile" @edit="openProfile($event, 'settings')" @browse="openProfile($event, 'files')"
                @preview="previewTarget = $event.name" @unlock="unlockTarget = $event" @refresh="refresh" />
            </div>
          </template>
        </section>

        <ServicePanel @open-system="systemTab = $event" @open-profile="revealProfile" />
      </div>
    </main>
    <SystemModal :open="Boolean(systemTab)" :initial-tab="systemTab" @close="systemTab = ''" />
    <PreviewChangesModal :profile="previewTarget" @close="previewTarget = ''" />
    <CreateProfileWizardModal :open="wizardOpen" @close="wizardOpen = false" @created="onCreated" />
    <UnlockModal :open="Boolean(unlockTarget)" :profile="unlockTarget" @close="unlockTarget = null" @unlocked="refresh" />
  </div>
</template>
