import { createRouter, createWebHistory } from 'vue-router'
import { useAuth } from '../composables/useAuth.js'

const routes = [
  {
    path: '/setup',
    name: 'setup',
    component: () => import('../auth/SetupView.vue'),
    meta: { public: true },
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('../auth/LoginView.vue'),
    meta: { public: true },
  },
  {
    path: '/',
    name: 'hub',
    component: () => import('../hub/HubView.vue'),
  },
  {
    path: '/profiles/:name/:tab(overview|files|history|conflicts|maintenance|settings)?',
    name: 'workspace',
    component: () => import('../workspace/ProfileWorkspaceView.vue'),
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  const { auth, refreshAuthStatus } = useAuth()
  if (!auth.loaded) {
    try {
      await refreshAuthStatus()
    } catch {
      // If daemon is temporarily unreachable, fall through to login screen
    }
  }
  if (!auth.configured) {
    return to.name === 'setup' ? true : { name: 'setup' }
  }
  if (!auth.authenticated) {
    return to.name === 'login' ? true : { name: 'login' }
  }
  if (to.name === 'login' || to.name === 'setup') {
    return { name: 'hub' }
  }
  return true
})

export default router
