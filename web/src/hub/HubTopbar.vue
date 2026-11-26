<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import ChangePasswordModal from '../auth/ChangePasswordModal.vue'
import DropdownMenu from '../components/DropdownMenu.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { useAuth } from '../composables/useAuth.js'
import { useDaemonStream } from '../composables/useDaemonStream.js'
import { locale, setLocale, t } from '../i18n/index.js'

const emit = defineEmits(['open-system'])
const router = useRouter()
const { logout } = useAuth()
const stream = useDaemonStream()
const passwordOpen = ref(false)

async function handleSignOut() {
  stream.stopDaemonStream(true)
  await logout()
  router.replace({ name: 'login' })
}

function toggleLocale() {
  setLocale(locale.value === 'en' ? 'pt-BR' : 'en')
}
</script>

<template>
  <header class="k-topbar">
    <div class="k-topbar-left">
      <RouterLink :to="{ name: 'hub' }" class="k-wordmark">
        {{ t('app.name') }}
      </RouterLink>
    </div>

    <div class="k-topbar-right">
      <button type="button" class="k-btn k-btn--ghost k-btn--compact k-topbar-status" @click="emit('open-system')">
        <StatusBadge
          :state="stream.streamState"
          :label="
            stream.streamState === 'connected'
              ? t('system.pillOnline')
              : stream.streamState === 'reconnecting'
                ? t('system.pillReconnecting')
                : t('system.pillOffline')
          "
        />
      </button>

      <button type="button" class="k-btn k-btn--ghost k-btn--compact" @click="toggleLocale">
        <span :lang="locale === 'en' ? 'pt-BR' : 'en'">{{ locale === 'en' ? 'Português' : 'English' }}</span>
      </button>

      <DropdownMenu align="right">
        <template #trigger="{ toggle }">
          <button type="button" class="k-btn k-btn--compact" @click="toggle">
            {{ t('account.menu') }} ▾
          </button>
        </template>
        <button type="button" class="k-menu-item" @click="passwordOpen = true">
          <span>{{ t('account.changePassword') }}</span>
        </button>
        <div class="k-menu-divider" />
        <button type="button" class="k-menu-item k-menu-item--danger" @click="handleSignOut">
          <span>{{ t('account.signOut') }}</span>
        </button>
      </DropdownMenu>
    </div>

    <ChangePasswordModal
      :open="passwordOpen"
      @close="passwordOpen = false"
    />
  </header>
</template>
