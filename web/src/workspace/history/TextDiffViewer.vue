<script setup>
import { computed } from 'vue'
import { computeLineDiff } from '../../utils/diff.js'

const props = defineProps({
  leftText: { type: String, default: '' },
  rightText: { type: String, default: '' },
  leftLabel: { type: String, default: 'Before' },
  rightLabel: { type: String, default: 'After' },
})

const diff = computed(() => computeLineDiff(props.leftText ?? '', props.rightText ?? ''))
</script>

<template>
  <div class="k-diff-wrap">
    <div class="k-diff-head k-row k-row--between">
      <span class="k-mono k-text-sm">{{ leftLabel }} → {{ rightLabel }}</span>
      <span v-if="diff.truncated" class="k-faint k-text-xs">Truncated preview</span>
    </div>
    <div class="k-diff-body">
      <table class="k-diff-table">
        <tbody>
          <tr
            v-for="(row, idx) in diff.rows"
            :key="idx"
            :class="`k-diff-row--${row.type}`"
          >
            <td class="k-diff-ln">{{ row.leftLine ?? '' }}</td>
            <td class="k-diff-ln">{{ row.rightLine ?? '' }}</td>
            <td class="k-diff-sign">
              {{ row.type === 'add' ? '+' : row.type === 'del' ? '-' : ' ' }}
            </td>
            <td>{{ row.text }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.k-diff-wrap {
  border: 1px solid var(--k-border);
  border-radius: var(--k-radius-xs);
  overflow: hidden;
}

.k-diff-head {
  padding: 7px 12px;
  background: var(--k-surface-elevated);
  border-bottom: 1px solid var(--k-border-subtle);
  color: var(--k-text-muted);
}

.k-diff-body {
  max-height: 56vh;
  overflow: auto;
}

.k-diff-sign {
  width: 20px;
  user-select: none;
  color: var(--k-text-faint);
}
</style>
