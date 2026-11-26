<script setup>
import { ref } from 'vue'

defineProps({
  modelValue: { type: String, default: '' },
  label: { type: String, default: '' },
  placeholder: { type: String, default: '' },
  autocomplete: { type: String, default: 'current-password' },
  required: { type: Boolean, default: false },
  disabled: { type: Boolean, default: false },
  id: { type: String, default: '' },
})

const emit = defineEmits(['update:modelValue'])
const visible = ref(false)
</script>

<template>
  <div class="k-field">
    <label v-if="label" :for="id || undefined" class="k-field-label">{{ label }}</label>
    <div class="k-pw-wrap">
      <input
        :id="id || undefined"
        class="k-input k-pw-input"
        :type="visible ? 'text' : 'password'"
        :value="modelValue"
        :placeholder="placeholder"
        :autocomplete="autocomplete"
        :required="required"
        :disabled="disabled"
        @input="emit('update:modelValue', $event.target.value)"
      />
      <button
        type="button"
        class="k-pw-toggle"
        :disabled="disabled"
        :aria-label="visible ? 'Hide secret' : 'Show secret'"
        @click="visible = !visible"
      >
        {{ visible ? 'Hide' : 'Show' }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.k-pw-wrap {
  position: relative;
  display: flex;
  align-items: center;
}

.k-pw-input {
  padding-right: 54px;
}

.k-pw-toggle {
  position: absolute;
  right: 5px;
  padding: 2px 7px;
  border: none;
  border-radius: var(--k-radius-xs);
  background: transparent;
  color: var(--k-text-muted);
  font-size: 11.5px;
  cursor: pointer;
}

.k-pw-toggle:hover:not(:disabled) {
  background: var(--k-hover);
  color: var(--k-text);
}
</style>
