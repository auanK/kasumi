import { afterEach, describe, expect, it, vi } from 'vitest'
import { apiRequest, buildQuery, onUnauthorized, setCsrfToken } from '../api/http.js'

afterEach(() => {
  setCsrfToken('')
  onUnauthorized(null)
  vi.restoreAllMocks()
})

describe('http client', () => {
  it('builds URL query strings omitting empty values', () => {
    expect(buildQuery({ profile: 'work', lines: 50, empty: '', nil: null })).toBe(
      '?profile=work&lines=50'
    )
    expect(buildQuery({})).toBe('')
  })

  it('attaches X-CSRF-Token and application/json on mutations', async () => {
    setCsrfToken('abcdef123456')
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    )

    const res = await apiRequest('/v1/reload', { method: 'POST', body: {} })
    expect(res).toEqual({ ok: true })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [, init] = fetchMock.mock.calls[0]
    expect(init.credentials).toBe('same-origin')
    expect(init.headers['X-CSRF-Token']).toBe('abcdef123456')
    expect(init.headers['Content-Type']).toBe('application/json')
  })

  it('triggers unauthorized handler on 403 invalid_credential', async () => {
    const unauth = vi.fn()
    onUnauthorized(unauth)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ code: 'invalid_credential', error: 'forbidden' }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      })
    )

    await expect(apiRequest('/v1/status')).rejects.toThrow('forbidden')
    expect(unauth).toHaveBeenCalledTimes(1)
  })
})
