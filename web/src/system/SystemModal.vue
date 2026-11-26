<script setup>
import { ref, watch } from 'vue'
import BaseModal from '../components/BaseModal.vue'
import SystemDaemonTab from './SystemDaemonTab.vue'
import SystemDiagnosticsTab from './SystemDiagnosticsTab.vue'
import SystemLogsTab from './SystemLogsTab.vue'
import { t } from '../i18n/index.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  initialTab: { type: String, default: 'daemon' },
})

const emit = defineEmits(['close'])
const activeTab = ref('daemon')
watch(() => props.open, (open) => {
  if (open) activeTab.value = props.initialTab
}, { immediate: true })
</script>

<template>
  <BaseModal :open="open" :title="t('system.title')" wide @close="emit('close')">
    <div class="k-segmented">
      <button
        type="button"
        class="k-seg-btn"
        :class="{ 'k-seg-btn--active': activeTab === 'daemon' }"
        @click="activeTab = 'daemon'"
      >
        {{ t('system.tabDaemon') }}
      </button>
      <button
        type="button"
        class="k-seg-btn"
        :class="{ 'k-seg-btn--active': activeTab === 'logs' }"
        @click="activeTab = 'logs'"
      >
        {{ t('system.tabLogs') }}
      </button>
      <button
        type="button"
        class="k-seg-btn"
        :class="{ 'k-seg-btn--active': activeTab === 'diagnostics' }"
        @click="activeTab = 'diagnostics'"
      >
        {{ t('system.tabDiagnostics') }}
      </button>
    </div>

    <SystemDaemonTab v-if="activeTab === 'daemon'" />
    <SystemLogsTab v-else-if="activeTab === 'logs'" />
    <SystemDiagnosticsTab v-else />

    <template #footer>
      <button type="button" class="k-btn" @click="emit('close')">{{ t('common.close') }}</button>
    </template>
  </BaseModal>
</template>
