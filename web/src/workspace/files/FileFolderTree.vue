<script setup>
import { computed, ref, watch } from 'vue'
import { t } from '../../i18n/index.js'
import { parentFolder } from './fileTree.js'

const props = defineProps({
  root: { type: Object, required: true },
  current: { type: String, default: '' },
})
const emit = defineEmits(['open-folder'])
const expanded = ref(new Set(['']))

watch(() => props.current, (path) => {
  while (path) {
    expanded.value.add(path)
    path = parentFolder(path)
  }
  expanded.value.add('')
}, { immediate: true })

const rows = computed(() => {
  const items = []
  function visit(folder, depth) {
    items.push({ folder, depth })
    if (expanded.value.has(folder.path)) {
      for (const child of folder.directories) visit(child, depth + 1)
    }
  }
  visit(props.root, 0)
  return items
})

function toggle(path) {
  if (expanded.value.has(path)) expanded.value.delete(path)
  else expanded.value.add(path)
}
</script>

<template>
  <nav class="k-folder-tree" :aria-label="t('files.folders')">
    <ul>
      <li v-for="{ folder, depth } in rows" :key="folder.path"
        :class="{ 'k-folder-tree-selected': folder.path === current }"
        :style="{ '--folder-depth': Math.min(depth, 8) }">
        <button v-if="folder.directories.length" type="button" class="k-folder-expand"
          :aria-expanded="expanded.has(folder.path)"
          :aria-label="t(expanded.has(folder.path) ? 'files.collapseFolder' : 'files.expandFolder', { name: folder.name || t('files.root') })"
          @click="toggle(folder.path)">
          <span aria-hidden="true">{{ expanded.has(folder.path) ? '▾' : '▸' }}</span>
        </button>
        <span v-else class="k-folder-expand"></span>
        <button type="button" class="k-folder-tree-name" :title="folder.path || t('files.root')"
          :aria-current="folder.path === current ? 'location' : undefined" @click="emit('open-folder', folder.path)">
          <span class="k-profile-folder" aria-hidden="true"></span>
          <span class="k-truncate">{{ folder.name || t('files.root') }}</span>
        </button>
      </li>
    </ul>
  </nav>
</template>

<style scoped>
.k-folder-tree ul { list-style: none; margin: 0; padding: 5px 6px; }
.k-folder-tree li {
  display: flex;
  align-items: center;
  min-width: 0;
  padding-inline-start: calc(var(--folder-depth) * 10px);
  border-radius: var(--k-radius-xs);
}
.k-folder-tree li:hover { background: var(--k-hover); }
.k-folder-tree .k-folder-tree-selected { background: var(--k-active); }
.k-folder-expand,
.k-folder-tree-name {
  background: transparent;
  border: 0;
  cursor: pointer;
}
.k-folder-expand { flex: 0 0 20px; padding: 2px; color: var(--k-text-muted); }
.k-folder-tree-name {
  min-width: 0;
  flex: 1;
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 4px 5px 4px 1px;
  text-align: start;
}
.k-folder-tree-name[aria-current] { color: var(--k-lavender); }
.k-folder-tree button:focus-visible { outline-offset: -2px; }
</style>
