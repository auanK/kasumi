import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { reactive } from 'vue'

const mocks = vi.hoisted(() => ({
  fetchDiagnostics: vi.fn(),
  daemonState: null,
}))

vi.mock('../api/profiles.js', () => ({
  fetchDiagnostics: mocks.fetchDiagnostics,
}))

vi.mock('../composables/useDaemonStream.js', async () => {
  const { reactive: vueReactive } = await import('vue')
  mocks.daemonState = vueReactive({
    daemonStatus: {
      machine_name: 'Workstation-BR',
      kasumi_version: '0.30.0',
      uptime_seconds: 65,
      pid: 4321,
      web_port: 3137,
      secure_pages_locked: true,
      autostart: { supported: true, installed: false },
    },
    liveUptimeSeconds: 68,
    logs: [],
    streamState: 'connected',
    refreshStatus: vi.fn(),
  })
  return {
    useDaemonStream: () => mocks.daemonState,
  }
})

import ServicePanel from '../hub/ServicePanel.vue'
import SystemDiagnosticsTab from '../system/SystemDiagnosticsTab.vue'

describe('Diagnostics report mapping and ServicePanel device info', () => {
  afterEach(() => vi.clearAllMocks())

  it('renders backend DiagnosticsReport fields accurately', async () => {
    mocks.fetchDiagnostics.mockResolvedValue({
      overall_ok: true,
      os_name: 'Windows 11',
      app_data_dir: 'C:/Users/demo/AppData/Roaming/kasumi',
      app_data_free_bytes: 1024 * 1024 * 1024,
      rclone: {
        found: true,
        version: 'v1.69.1',
        minimum_version: 'v1.60.0',
        meets_minimum: true,
      },
      profiles: [
        {
          profile: { name: 'Documents', key_storage: 'vault' },
          ignore_file_present: true,
          ignore_file_valid: true,
          healthy: true,
          detail: '',
          daemon_error: '',
        },
        {
          profile: { name: 'Broken', key_storage: 'file' },
          ignore_file_present: false,
          ignore_file_valid: true,
          healthy: false,
          detail: 'missing local folder',
          daemon_error: '',
        },
      ],
    })

    const wrapper = mount(SystemDiagnosticsTab)
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('OK')
    expect(text).toContain('Windows 11')
    expect(text).toContain('v1.69.1')
    expect(text).toContain('Documents')
    expect(text).toContain('vault')
    expect(text).toContain('Broken')
    expect(text).toContain('missing local folder')
    wrapper.unmount()
  })

  it('shows device hostname, version, and live uptime in ServicePanel', () => {
    const wrapper = mount(ServicePanel)
    const text = wrapper.text()
    expect(text).toContain('Workstation-BR')
    expect(text).toContain('v0.30.0')
    expect(text).toContain('1m 08s')
    wrapper.unmount()
  })
})
