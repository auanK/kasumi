import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ChangePasswordModal from '../auth/ChangePasswordModal.vue'
import LoginView from '../auth/LoginView.vue'
import SetupView from '../auth/SetupView.vue'
import { useAuth } from '../composables/useAuth.js'

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

describe('ChangePasswordModal', () => {
  it('updates username with current password and second confirmation without password change fields', async () => {
    const { auth } = useAuth()
    auth.authenticated = true
    auth.username = 'admin'

    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({ username: 'kauan' })
    )

    const wrapper = mount(ChangePasswordModal, {
      props: { open: true },
      global: { stubs: { Teleport: true } },
    })

    expect(wrapper.find('#change-username-form').exists()).toBe(true)
    expect(wrapper.find('input[autocomplete="new-password"]').exists()).toBe(false)

    await wrapper.get('#change-username-form input[autocomplete="username"]').setValue('kauan')
    await wrapper.get('#change-username-form input[autocomplete="current-password"]').setValue('secret1234')
    await wrapper.get('#change-username-form').trigger('submit.prevent')

    expect(fetch).not.toHaveBeenCalled()
    const dialogs = wrapper.findAll('[role="dialog"]')
    expect(dialogs).toHaveLength(2)
    expect(dialogs[1].text()).toContain('kauan')

    await dialogs[1].get('button.k-btn--primary').trigger('click')
    await flushPromises()

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch.mock.calls[0][0]).toContain('/v1/auth/username')
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({
      current_password: 'secret1234',
      username: 'kauan',
    })
    expect(auth.authenticated).toBe(true)
    expect(auth.username).toBe('kauan')
    wrapper.unmount()
  })

  it('changes password in the password tab without resetting username field and revokes session', async () => {
    const { auth } = useAuth()
    auth.authenticated = true
    auth.username = 'kauan'

    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({ configured: true })
    )

    const wrapper = mount(ChangePasswordModal, {
      props: { open: true },
      global: { stubs: { Teleport: true } },
    })

    await wrapper.findAll('button[role="tab"]')[1].trigger('click')
    expect(wrapper.find('#change-pw-form').exists()).toBe(true)
    expect(wrapper.find('input[autocomplete="username"]').exists()).toBe(false)

    await wrapper.get('#pw-current').setValue('secret1234')
    await wrapper.get('#pw-next').setValue('new-secret-99')
    await wrapper.get('#pw-confirm').setValue('new-secret-99')
    await wrapper.get('#change-pw-form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('[role="alert"]').exists() ? wrapper.find('[role="alert"]').text() : '').toBe('')
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch.mock.calls[0][0]).toContain('/v1/auth/password')
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({
      current_password: 'secret1234',
      password: 'new-secret-99',
    })
    expect(auth.authenticated).toBe(false)
    wrapper.unmount()
  })
})
