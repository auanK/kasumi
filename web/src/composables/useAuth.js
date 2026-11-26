import { reactive } from 'vue'
import {
  changePassword as apiChangePassword,
  fetchAuthStatus,
  login as apiLogin,
  logout as apiLogout,
  setupInitialPassword as apiSetupPassword,
} from '../api/auth.js'
import { onUnauthorized } from '../api/http.js'
import { invalidateInspections } from '../api/inspections.js'
import { clearProfiles } from './useProfiles.js'

const state = reactive({
  loaded: false,
  configured: true,
  authenticated: false,
  loading: false,
  username: '',
})

onUnauthorized(() => {
  state.authenticated = false
  clearProfiles()
  invalidateInspections(undefined, { discard: true })
})

export async function refreshAuthStatus() {
  state.loading = true
  try {
    const info = await fetchAuthStatus()
    state.configured = Boolean(info?.configured)
    state.authenticated = Boolean(info?.authenticated)
    if (info?.username) state.username = info.username
    state.loaded = true
    return info
  } finally {
    state.loading = false
  }
}

export async function login(password, username = 'admin') {
  const res = await apiLogin(password, username)
  state.configured = true
  state.authenticated = Boolean(res?.authenticated)
  if (state.authenticated) state.username = username
  state.loaded = true
  return res
}

export async function logout() {
  try {
    await apiLogout()
  } finally {
    state.authenticated = false
    clearProfiles()
    invalidateInspections(undefined, { discard: true })
  }
}

export async function setupInitialPassword(bootstrapToken, password, username) {
  const res = await apiSetupPassword(bootstrapToken, password, username)
  state.configured = Boolean(res?.configured ?? true)
  state.authenticated = false
  state.username = username || 'admin'
  state.loaded = true
  return res
}

export async function changePassword(currentPassword, password, username) {
  const res = await apiChangePassword(currentPassword, password, username)
  state.authenticated = false
  clearProfiles()
  invalidateInspections(undefined, { discard: true })
  if (username) state.username = username
  return res
}

export function useAuth() {
  return {
    auth: state,
    refreshAuthStatus,
    login,
    logout,
    setupInitialPassword,
    changePassword,
  }
}
