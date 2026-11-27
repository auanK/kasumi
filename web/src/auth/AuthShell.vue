<script setup>
import { locale, setLocale, t } from '../i18n/index.js'

defineProps({
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
})

function toggleLocale() {
  setLocale(locale.value === 'en' ? 'pt-BR' : 'en')
}
</script>

<template>
  <div class="k-auth-shell">
    <header class="k-topbar">
      <div class="k-topbar-left">
        <span class="k-wordmark">{{ t('app.name') }}</span>
      </div>
      <div class="k-topbar-right">
        <button type="button" class="k-btn k-btn--ghost k-btn--compact" @click="toggleLocale">
          <span :lang="locale === 'en' ? 'pt-BR' : 'en'">{{ locale === 'en' ? 'Português' : 'English' }}</span>
        </button>
      </div>
    </header>
    <main class="k-auth-main">
      <section class="k-auth-card">
        <header class="k-auth-header">
          <h1 class="k-auth-title">{{ title }}</h1>
          <p v-if="subtitle" class="k-auth-sub">{{ subtitle }}</p>
        </header>
        <div class="k-auth-body">
          <slot />
        </div>
      </section>
    </main>
  </div>
</template>

<style scoped>
.k-auth-header {
  padding: 14px 18px;
  background: var(--k-surface-header);
  border-bottom: 1px solid var(--k-border-subtle);
}

.k-auth-body {
  padding: 18px;
}

.k-auth-title {
  margin: 0 0 4px;
  font-size: 17px;
  font-weight: 620;
}

.k-auth-sub {
  margin: 0;
  font-size: 13px;
  color: var(--k-text-muted);
  line-height: 1.5;
}
</style>
