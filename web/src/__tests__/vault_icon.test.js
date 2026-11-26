import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  updateProfile: vi.fn(),
  listRcloneRemotes: vi.fn(),
  uploadProfileIcon: vi.fn(),
  deleteProfileIcon: vi.fn(),
}))

vi.mock('../api/profiles.js', () => ({
  deleteProfile: vi.fn(),
  deleteProfileIcon: mocks.deleteProfileIcon,
  listRcloneRemotes: mocks.listRcloneRemotes,
  testProfileConnection: vi.fn(),
  updateProfile: mocks.updateProfile,
  uploadProfileIcon: mocks.uploadProfileIcon,
}))

vi.mock('../api/daemon.js', () => ({
  lockProfile: vi.fn(),
}))

vi.mock('../composables/useProfileActivity.js', async () => {
  const { ref } = await import('vue')
  return {
    useProfileActivity: () => ({ blockedReason: ref('') }),
  }
})

import VaultIcon from '../components/VaultIcon.vue'
import SettingsTab from '../workspace/settings/SettingsTab.vue'

describe('VaultIcon customization', () => {
  afterEach(() => vi.clearAllMocks())

  it('renders presets, auto-detects default empty icon, and falls back from image error to default SVG', async () => {
    const presetWrapper = mount(VaultIcon, {
      props: { profile: 'work', icon: 'preset:shield', size: 'md' },
    })
    expect(presetWrapper.find('svg').exists()).toBe(true)
    expect(presetWrapper.find('img').exists()).toBe(false)
    presetWrapper.unmount()

    const defaultPreset = mount(VaultIcon, {
      props: { profile: 'work', icon: 'preset:default', size: 'sm' },
    })
    expect(defaultPreset.find('svg').exists()).toBe(true)
    expect(defaultPreset.find('img').exists()).toBe(false)
    defaultPreset.unmount()

    const autoWrapper = mount(VaultIcon, {
      props: { profile: 'work studio', icon: '', size: 'sm' },
    })
    const img = autoWrapper.find('img')
    expect(img.exists()).toBe(true)
    expect(img.attributes('src')).toBe('/v1/profiles/work%20studio/icon?v=auto')
    await img.trigger('error')
    expect(autoWrapper.find('img').exists()).toBe(false)
    expect(autoWrapper.find('svg').exists()).toBe(true)
    autoWrapper.unmount()

    const customWrapper = mount(VaultIcon, {
      props: { profile: 'work', icon: 'custom:0123456789abcdef', size: 'sm' },
    })
    expect(customWrapper.find('img').attributes('src')).toBe(
      '/v1/profiles/work/icon?v=custom%3A0123456789abcdef',
    )
    customWrapper.unmount()
  })

  it('saves selected icon in SettingsTab', async () => {
    mocks.listRcloneRemotes.mockResolvedValue({ remotes: [] })
    mocks.updateProfile.mockResolvedValue({})

    const wrapper = mount(SettingsTab, {
      props: {
        profile: {
          name: 'demo',
          local_dir: 'D:/demo',
          remote_dir: 'D:/remote',
          min_history_depth: 5,
          min_history_age_hours: 6,
          sync_interval_seconds: 300,
          watch_enabled: true,
          paused: false,
          icon: '',
        },
        daemonState: { locked: false },
      },
      global: { stubs: { Teleport: true } },
    })
    await flushPromises()

    await wrapper.get('#settings-icon').setValue('preset:code')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(mocks.updateProfile).toHaveBeenCalledWith(
      'demo',
      expect.objectContaining({ icon: 'preset:code' }),
    )
    wrapper.unmount()
  })
})
