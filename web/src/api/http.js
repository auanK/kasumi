/**
 * Core HTTP transport for Kasumi Daemon Web API.
 * Attaches X-CSRF-Token and Content-Type: application/json on mutating requests.
 */

let csrfToken = ''
let unauthorizedHandler = null

export class ApiError extends Error {
  constructor(message, { status = 0, code = '', data = null, retryAfter = null } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.data = data
    this.retryAfter = retryAfter
  }
}

export function setCsrfToken(token) {
  csrfToken = typeof token === 'string' ? token : ''
}

export function onUnauthorized(handler) {
  unauthorizedHandler = handler
}

export function notifyUnauthorized() {
  if (unauthorizedHandler) unauthorizedHandler()
}

export function buildQuery(params = {}) {
  const sp = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    sp.set(key, String(value))
  }
  const str = sp.toString()
  return str ? `?${str}` : ''
}

export function encodeSegment(value) {
  return encodeURIComponent(String(value))
}

export async function apiRequest(path, { method = 'GET', body, headers = {}, signal } = {}) {
  const upper = method.toUpperCase()
  const isWrite = upper !== 'GET' && upper !== 'HEAD'
  const reqHeaders = { ...headers }

  if (isWrite && csrfToken) {
    reqHeaders['X-CSRF-Token'] = csrfToken
  }

  let payload
  if (isWrite) {
    reqHeaders['Content-Type'] = 'application/json'
    payload = JSON.stringify(body === undefined ? {} : body)
  }

  const response = await fetch(path, {
    method: upper,
    credentials: 'same-origin',
    headers: reqHeaders,
    body: payload,
    signal,
  })

  const contentType = response.headers.get('content-type') || ''
  let data = null
  if (contentType.includes('application/json')) {
    try {
      data = await response.json()
    } catch {
      data = null
    }
  } else {
    const text = await response.text()
    data = text ? { error: text } : null
  }

  if (!response.ok) {
    const message =
      (data && (data.error || data.detail || data.message)) ||
      `HTTP ${response.status}`
    const code = (data && data.code) || ''
    const retryAfter = response.headers.get('retry-after')

    if (
      (response.status === 401 || (response.status === 403 && code === 'invalid_credential')) &&
      !path.startsWith('/v1/auth/') &&
      unauthorizedHandler
    ) {
      unauthorizedHandler()
    }

    throw new ApiError(message, {
      status: response.status,
      code,
      data,
      retryAfter,
    })
  }

  return data
}
