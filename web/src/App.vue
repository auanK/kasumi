<script setup>
import { watch } from 'vue'
import { useRouter } from 'vue-router'
import ToastStack from './components/ToastStack.vue'
import { useAuth } from './composables/useAuth.js'
import { useDaemonStream } from './composables/useDaemonStream.js'
import { locale } from './i18n/index.js'

const router = useRouter()
const { auth } = useAuth()
const stream = useDaemonStream()

watch(locale, (language) => { document.documentElement.lang = language }, { immediate: true })

watch(
  () => auth.authenticated,
  (authenticated) => {
    if (authenticated) {
      stream.startDaemonStream()
    } else {
      stream.stopDaemonStream(true)
      if (auth.loaded && auth.configured && router.currentRoute.value.name !== 'login') {
        router.replace({ name: 'login' })
      }
    }
  },
  { immediate: true }
)
</script>

<template>
  <RouterView />
  <ToastStack />
</template>
