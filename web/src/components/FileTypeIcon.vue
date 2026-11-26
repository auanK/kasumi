<script setup>
defineProps({
  category: { type: String, default: 'binary' },
  size: { type: String, default: 'sm' },
})
</script>

<template>
  <span
    class="k-ftype-icon"
    :class="[`k-ftype-icon--${size}`, `k-ftype-icon--${category}`]"
    :data-category="category"
    aria-hidden="true"
  >
    <svg v-if="category === 'directory'" viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <path d="M2.5 5.8a1.5 1.5 0 011.5-1.5h3.7l1.5 1.7H16a1.5 1.5 0 011.5 1.5v6.8a1.5 1.5 0 01-1.5 1.5H4a1.5 1.5 0 01-1.5-1.5V5.8z"
        fill="var(--k-folder-bg)" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
    </svg>
    <svg v-else-if="category === 'image'" viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <rect x="2.8" y="3.8" width="14.4" height="12.4" rx="2" stroke="currentColor" stroke-width="1.45" />
      <circle cx="7.4" cy="7.8" r="1.25" fill="currentColor" />
      <path d="M4.2 14l3.7-3.8 2.8 2.4 2.1-1.9 3 3.3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    <svg v-else-if="category === 'video'" viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <rect x="2.8" y="4.2" width="14.4" height="11.6" rx="2" stroke="currentColor" stroke-width="1.45" />
      <path d="M8.5 7.6l4.8 2.4-4.8 2.4V7.6z" fill="currentColor" />
    </svg>
    <svg v-else-if="category === 'audio'" viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <path d="M8.2 14.4V5.6l7.3-1.4v8.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
      <circle cx="6.2" cy="14.6" r="2" stroke="currentColor" stroke-width="1.45" />
      <circle cx="13.5" cy="13.2" r="2" stroke="currentColor" stroke-width="1.45" />
    </svg>
    <svg v-else-if="category === 'pdf'" viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <path d="M5.2 3h6.1l3.5 3.5v10a1 1 0 01-1 1H5.2a1 1 0 01-1-1V4a1 1 0 011-1z" stroke="currentColor" stroke-width="1.45" stroke-linejoin="round" />
      <path d="M11.2 3v3.6h3.6" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
      <path d="M7.2 13.5v-3h1.3a1 1 0 010 2H7.2M11 10.5h1.5M11 12h1.2" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" />
    </svg>
    <svg v-else-if="category === 'code'" viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <path d="M7.2 6.8L3.7 10l3.5 3.2M12.8 6.8l3.5 3.2-3.5 3.2M11 5l-2 10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    <svg v-else-if="category === 'text' || category === 'document'" viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <path d="M5.2 3h6.1l3.5 3.5v10a1 1 0 01-1 1H5.2a1 1 0 01-1-1V4a1 1 0 011-1z" stroke="currentColor" stroke-width="1.45" stroke-linejoin="round" />
      <path d="M7.2 9.5h5.6M7.2 12.2h5.6M7.2 14.8h3.6" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" />
    </svg>
    <svg v-else-if="category === 'archive'" viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <rect x="3" y="4" width="14" height="3.4" rx="1" stroke="currentColor" stroke-width="1.45" />
      <path d="M4.3 7.5v8.2a1 1 0 001 1h9.4a1 1 0 001-1V7.5M8.5 11.2h3" stroke="currentColor" stroke-width="1.45" stroke-linecap="round" />
    </svg>
    <svg v-else-if="category === 'executable'" viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <path d="M10 2.9l6 3.4v7.4l-6 3.4-6-3.4V6.3l6-3.4z" stroke="currentColor" stroke-width="1.45" stroke-linejoin="round" />
      <path d="M4 6.3l6 3.4 6-3.4M10 9.7v7.4" stroke="currentColor" stroke-width="1.35" />
    </svg>
    <svg v-else viewBox="0 0 20 20" fill="none" class="k-ftype-svg">
      <path d="M5.2 3h6.1l3.5 3.5v10a1 1 0 01-1 1H5.2a1 1 0 01-1-1V4a1 1 0 011-1z" stroke="currentColor" stroke-width="1.45" stroke-linejoin="round" />
      <circle cx="10" cy="12.5" r="1.4" fill="currentColor" />
    </svg>
  </span>
</template>

<style scoped>
.k-ftype-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: none;
  color: var(--k-text-muted);
}

.k-ftype-icon--sm { width: 17px; height: 17px; }
.k-ftype-icon--md { width: 22px; height: 22px; }
.k-ftype-icon--lg { width: 32px; height: 32px; }
.k-ftype-icon--xl { width: 58px; height: 58px; }

.k-ftype-svg { width: 100%; height: 100%; display: block; }

.k-ftype-icon--directory { color: var(--k-folder); }
.k-ftype-icon--image { color: var(--k-info); }
.k-ftype-icon--video { color: var(--k-lavender); }
.k-ftype-icon--audio { color: var(--k-ok); }
.k-ftype-icon--pdf { color: var(--k-error); }
.k-ftype-icon--code { color: var(--k-info-hover); }
.k-ftype-icon--text { color: var(--k-text); }
.k-ftype-icon--document { color: var(--k-info); }
.k-ftype-icon--archive { color: var(--k-warn); }
.k-ftype-icon--executable { color: var(--k-text-muted); }
.k-ftype-icon--binary { color: var(--k-text-faint); }
</style>
