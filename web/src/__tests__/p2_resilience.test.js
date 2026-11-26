import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'

const mocks = vi.hoisted(() => ({
  fetchJob: vi.fn(),
  fetchRemoteSummary: vi.fn(),
  fetchRemoteHealth: vi.fn(),
  fetchProfileIgnore: vi.fn(),
  startMaintenanceJob: vi.fn(),
  restoreRemote: vi.fn(),
}))

vi.mock('../api/maintenance.js', () => ({
  startPreviewJob: vi.fn(),
  startMaintenanceJob: mocks.startMaintenanceJob,
  fetchJob: mocks.fetchJob,
}))

vi.mock('../api/remote.js', () => ({
  cachedRemoteReading: vi.fn(() => null),
  fetchRemoteSummary: mocks.fetchRemoteSummary,
  fetchRemoteHealth: mocks.fetchRemoteHealth,
  restoreRemote: mocks.restoreRemote,
}))

vi.mock('../api/ignore.js', () => ({
  fetchProfileIgnore: mocks.fetchProfileIgnore,
  initProfileIgnore: vi.fn(),
  checkProfileIgnore: vi.fn(),
}))

import { useDaemonStream } from '../composables/useDaemonStream.js'
import { useProfileActivity } from '../composables/useProfileActivity.js'
import StatusBadge from '../components/StatusBadge.vue'
import RestoreModal from '../workspace/files/RestoreModal.vue'
import MaintenanceTab from '../workspace/maintenance/MaintenanceTab.vue'

describe('P2 lock ownership, job reconciliation, and restore safety', () => {
  afterEach(() => {
    const stream = useDaemonStream()
    stream.daemonStatus = null
    stream.daemonInstance = ''
    stream.jobs = []
    stream.streamState = 'disconnected'
    vi.clearAllMocks()
  })

  it('reports busy external lock from daemon status instead of Ready', () => {
    const stream = useDaemonStream()
    stream.daemonStatus = {
      daemon_instance: '1234-1700000000',
      profiles: [{ name: 'demo', state: 'idle', busy: true, active_operation: 'external' }],
    }
    const { serverBusy, externalBusy, blockedReason } = useProfileActivity('demo')
    expect(serverBusy.value).toBe(true)
    expect(externalBusy.value).toBe(true)
    expect(blockedReason.value).toContain('Another Kasumi process')

    const badge = mount(StatusBadge, { props: { state: 'external' } })
    expect(badge.text()).toContain('In use by CLI')
    badge.unmount()
  })

  it('localizes VaultSpaceCard loading and reconciles disappeared jobs after daemon restart', async () => {
    const stream = useDaemonStream()
    stream.daemonInstance = 'inst-1'
    stream.streamState = 'connected'
    stream.daemonStatus = {
      daemon_instance: 'inst-1',
      profiles: [{ name: 'demo', state: 'idle', busy: false, active_operation: '' }],
    }
    mocks.fetchProfileIgnore.mockResolvedValue({ ignore_file_present: true, content: '' })
    let resolveSpace
    mocks.fetchRemoteSummary.mockImplementationOnce(() => new Promise((r) => { resolveSpace = r }))
    mocks.startMaintenanceJob.mockResolvedValueOnce({ id: 77, profile: 'demo', operation: 'gc', state: 'running' })
    mocks.fetchJob.mockRejectedValueOnce(Object.assign(new Error('job not found'), { status: 404 }))

    const wrapper = mount(MaintenanceTab, { props: { profile: 'demo' }, global: { stubs: { Teleport: true } } })
    await flushPromises()

    const measureBtn = wrapper.findAll('button').find((b) => b.text() === 'Measure space')
    const previewBtn = wrapper.findAll('button').find((b) => b.text() === 'Simulate')
    await measureBtn.trigger('click')
    expect(measureBtn.element.disabled).toBe(true)
    expect(previewBtn.element.disabled).toBe(false)

    resolveSpace({ space_usage: {} })
    await flushPromises()

    await previewBtn.trigger('click')
    await flushPromises()
    expect(previewBtn.element.disabled).toBe(true)

    // Simulate daemon restart: new instance and empty jobs list -> submitted running job reconciles to failed/interrupted.
    stream.daemonInstance = 'inst-2'
    stream.jobs = []
    await flushPromises()
    await nextTick()
    expect(previewBtn.element.disabled).toBe(false)
    expect(wrapper.text()).toContain('Failed')
    wrapper.unmount()
  })

  it('invalidates RestoreModal dry-run preview on input change and discards stale responses', async () => {
    let finishFirst
    let finishSecond
    mocks.restoreRemote
      .mockImplementationOnce(() => new Promise((r) => { finishFirst = r }))
      .mockImplementationOnce(() => new Promise((r) => { finishSecond = r }))

    const wrapper = mount(RestoreModal, {
      props: { open: true, profile: 'demo', commit: 'c1', initialPrefix: 'docs' },
      global: { stubs: { Teleport: true } },
    })
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('D:/restore-a')
    await flushPromises()

    const previewBtn = wrapper.findAll('button').find((b) => b.text() === 'Preview first')
    await previewBtn.trigger('click')
    // Changing destination while dry-run is in flight invalidates & bumps sequence.
    await inputs[0].setValue('D:/restore-b')
    finishFirst({ files_restored: 99, bytes_restored: 999 })
    await flushPromises()
    expect(wrapper.text()).not.toContain('99 file(s)')

    await previewBtn.trigger('click')
    finishSecond({ files_restored: 2, bytes_restored: 1024 })
    await flushPromises()
    expect(wrapper.text()).toContain('2 file(s)')

    await inputs[1].setValue('notes')
    await nextTick()
    expect(wrapper.text()).not.toContain('2 file(s)')
    wrapper.unmount()
  })
})
