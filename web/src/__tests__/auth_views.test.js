import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import LoginView from '../auth/LoginView.vue'
import SetupView from '../auth/SetupView.vue'

vi.mock('vue-router', () => ({
  useRouter: () => ({ replace: vi.fn() }),
}))

afterEach(() => {
  vi.restoreAllMocks()
})

describe('SetupView', () => {
  it('rejects passwords shorter than 8 characters before calling API', async () => {
    const wrapper = mount(SetupView)
    await wrapper.find('#setup-token').setValue('a'.repeat(64))
    await wrapper.find('#setup-pw').setValue('short')
    await wrapper.find('#setup-pw-confirm').setValue('short')
    await wrapper.find('form').trigger('submit.prevent')

    expect(wrapper.find('[role="alert"]').text()).toContain('8')
  })

  it('sets up a custom username and an eight-digit password', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({ configured: true })
    )
    const wrapper = mount(SetupView)
    await wrapper.get('input[autocomplete="username"]').setValue('Kauan ✓')
    await wrapper.get('#setup-token').setValue('a'.repeat(64))
    await wrapper.get('#setup-pw').setValue('12345678')
    await wrapper.get('#setup-pw-confirm').setValue('12345678')
    await wrapper.get('form').trigger('submit.prevent')
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toMatchObject({
      username: 'Kauan ✓', password: '12345678',
    })
    wrapper.unmount()
  })

  it('rejects mismatched password confirmation', async () => {
    const wrapper = mount(SetupView)
    await wrapper.find('#setup-token').setValue('a'.repeat(64))
    await wrapper.find('#setup-pw').setValue('very-secure-password-1')
    await wrapper.find('#setup-pw-confirm').setValue('very-secure-password-2')
    await wrapper.find('form').trigger('submit.prevent')

    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
  })
})

describe('LoginView', () => {
  it('renders clear error message on HTTP 429 rate limit', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'try again later' }), {
        status: 429,
        headers: { 'content-type': 'application/json' },
      })
    )

    const wrapper = mount(LoginView)
    await wrapper.find('#login-password').setValue('incorrect-password')
    await wrapper.find('form').trigger('submit.prevent')
    await new Promise((r) => setTimeout(r, 0))

    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
  })
})
