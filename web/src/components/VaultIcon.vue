<script setup>
import { computed, ref, watch } from 'vue'
import { encodeSegment } from '../api/http.js'

const props = defineProps({
  profile: { type: String, required: true },
  icon: { type: String, default: '' },
  size: { type: String, default: 'sm' },
})

const imageFailed = ref(false)
watch([() => props.profile, () => props.icon], () => {
  imageFailed.value = false
})

const isPreset = computed(() => props.icon?.startsWith('preset:'))
const isRemoteImage = computed(() => !isPreset.value && !imageFailed.value)
const iconUrl = computed(() => {
  const version = props.icon || 'auto'
  return `/v1/profiles/${encodeSegment(props.profile)}/icon?v=${encodeURIComponent(version)}`
})
const preset = computed(() => (isPreset.value ? props.icon.slice(7) : 'default'))
</script>

<template>
  <span class="k-vault-icon" :class="`k-vault-icon--${size}`" aria-hidden="true">
    <img
      v-if="isRemoteImage"
      :src="iconUrl"
      alt=""
      class="k-vault-icon-img"
      @error="imageFailed = true"
    />
    <svg v-else-if="preset === 'vault'" viewBox="0 0 20 20" fill="none" class="k-vault-icon-svg">
      <rect x="2.5" y="3.5" width="15" height="13" rx="2.2" stroke="currentColor" stroke-width="1.5" />
      <circle cx="10" cy="10" r="3" stroke="currentColor" stroke-width="1.5" />
      <path d="M10 7v1.5M10 11.5V13M7 10h1.5M11.5 10H13" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
    </svg>
    <svg v-else-if="preset === 'code'" viewBox="0 0 20 20" fill="none" class="k-vault-icon-svg">
      <path d="M7.5 6.5L3.5 10l4 3.5M12.5 6.5l4 3.5-4 3.5M11 4.5l-2 11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    <svg v-else-if="preset === 'docs'" viewBox="0 0 20 20" fill="none" class="k-vault-icon-svg">
      <path d="M5.5 3.5h6l3.5 3.5v9.5a1 1 0 01-1 1h-8.5a1 1 0 01-1-1v-12a1 1 0 011-1z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
      <path d="M7.5 10.5h5M7.5 13.5h3.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
    </svg>
    <svg v-else-if="preset === 'photos'" viewBox="0 0 20 20" fill="none" class="k-vault-icon-svg">
      <rect x="2.5" y="4" width="15" height="12" rx="2" stroke="currentColor" stroke-width="1.5" />
      <circle cx="7.5" cy="8" r="1.2" fill="currentColor" />
      <path d="M4.5 14l4-4 3 2.5 2-1.8 2.5 3.3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    <svg v-else-if="preset === 'music'" viewBox="0 0 20 20" fill="none" class="k-vault-icon-svg">
      <path d="M8 14.5V5.5l8-1.5v9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
      <circle cx="6" cy="14.5" r="2" stroke="currentColor" stroke-width="1.5" />
      <circle cx="14" cy="13" r="2" stroke="currentColor" stroke-width="1.5" />
    </svg>
    <svg v-else-if="preset === 'archive'" viewBox="0 0 20 20" fill="none" class="k-vault-icon-svg">
      <rect x="2.5" y="4" width="15" height="3.5" rx="1" stroke="currentColor" stroke-width="1.5" />
      <path d="M4 7.5v8a1 1 0 001 1h10a1 1 0 001-1v-8M8.5 11h3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
    </svg>
    <svg v-else-if="preset === 'shield'" viewBox="0 0 20 20" fill="none" class="k-vault-icon-svg">
      <path d="M10 2.8l6 2.4v4.6c0 3.7-2.5 6.3-6 7.4-3.5-1.1-6-3.7-6-7.4V5.2l6-2.4z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
      <path d="M7.8 10.2l1.6 1.6 3-3.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    <svg v-else viewBox="0 0 20 20" fill="none" class="k-vault-icon-svg">
      <path d="M2.5 6a1.5 1.5 0 011.5-1.5h3.8l1.6 1.8h6.6a1.5 1.5 0 011.5 1.5v6.7a1.5 1.5 0 01-1.5 1.5H4a1.5 1.5 0 01-1.5-1.5V6z" fill="var(--k-folder-bg)" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
    </svg>
  </span>
</template>

<style scoped>
.k-vault-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--k-folder);
  flex: none;
}

.k-vault-icon--sm {
  width: 20px;
  height: 20px;
}

.k-vault-icon--md {
  width: 24px;
  height: 24px;
}

.k-vault-icon-svg,
.k-vault-icon-img {
  width: 100%;
  height: 100%;
  object-fit: contain;
  border-radius: 3px;
}
</style>
