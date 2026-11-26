import { apiRequest, setCsrfToken } from './http.js'

export async function fetchAuthStatus() {
  const data = await apiRequest('/v1/auth/status')
  setCsrfToken(data?.csrf_token || '')
  return data
}

export async function login(password, username = 'admin') {
  const data = await apiRequest('/v1/auth/login', {
    method: 'POST',
    body: { username, password },
  })
  if (data?.csrf_token) setCsrfToken(data.csrf_token)
  return data
}

export async function logout() {
  try {
    return await apiRequest('/v1/auth/logout', { method: 'POST', body: {} })
  } finally {
    setCsrfToken('')
  }
}

export async function setupInitialPassword(bootstrapToken, password, username) {
  return apiRequest('/v1/auth/password', {
    method: 'POST',
    body: {
      bootstrap_token: bootstrapToken.trim(),
      password,
      username,
    },
  })
}

export async function changePassword(currentPassword, password, username) {
  const data = await apiRequest('/v1/auth/password', {
    method: 'POST',
    body: {
      current_password: currentPassword,
      password,
      username,
    },
  })
  setCsrfToken('')
  return data
}
