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
  <main class="k-auth-shell">
    <section class="k-auth-card k-stack--lg">
      <div class="k-row k-row--between">
        <strong class="k-auth-wordmark">{{ t('app.name') }}</strong>
        <button type="button" class="k-btn k-btn--ghost k-btn--compact" @click="toggleLocale">
          {{ locale }}
        </button>
      </div>
      <div>
        <h1 class="k-auth-title">{{ title }}</h1>
        <p v-if="subtitle" class="k-auth-sub">{{ subtitle }}</p>
      </div>
      <slot />
    </section>
  </main>
</template>

<style scoped>
.k-auth-wordmark {
  font-size: 1.25rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--k-lavender);
}

.k-auth-title {
  margin: 0 0 4px;
  font-size: 17px;
  font-weight: 600;
}

.k-auth-sub {
  margin: 0;
  font-size: 13px;
  color: var(--k-text-muted);
  line-height: 1.5;
}
</style>
