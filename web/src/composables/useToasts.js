import { ref } from 'vue'

let nextId = 1
const toasts = ref([])

export function pushToast(message, kind = 'info', durationMs = 4500) {
  const id = nextId++
  toasts.value.push({ id, message, kind })
  if (durationMs > 0) {
    window.setTimeout(() => dismissToast(id), durationMs)
  }
  return id
}

export function dismissToast(id) {
  toasts.value = toasts.value.filter((item) => item.id !== id)
}

export function useToasts() {
  return {
    toasts,
    pushToast,
    dismissToast,
  }
}
