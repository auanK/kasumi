import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, expect, it, vi } from 'vitest'
import { fetchDaemonLogs, fetchDaemonStatus } from '../api/daemon.js'
import { getProfile, listProfiles } from '../api/profiles.js'
import { useDaemonStream } from '../composables/useDaemonStream.js'
import { clearProfiles, useProfiles } from '../composables/useProfiles.js'
import HubView from '../hub/HubView.vue'
import ProfileCard from '../hub/ProfileCard.vue'
import ServicePanel from '../hub/ServicePanel.vue'
import SystemLogsTab from '../system/SystemLogsTab.vue'

const stream = vi.hoisted(() => ({ events: null }))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useRoute: () => ({ query: {}, params: {} }),
}))

vi.mock('../api/daemon.js', () => ({
  fetchDaemonLogs: vi.fn().mockResolvedValue({ latest_seq: 0, events: [] }),
  fetchDaemonStatus: vi.fn().mockResolvedValue({ running: true, profiles: [] }),
  triggerSync: vi.fn(),
}))

vi.mock('../api/profiles.js', () => ({
  listProfiles: vi.fn().mockResolvedValue({ profiles: [] }),
  getProfile: vi.fn(),
}))

vi.mock('../api/sse.js', () => ({
  connectEventStream(events) {
    stream.events = events
    return {
      close() {
        events.onStateChange?.('disconnected')
      },
    }
  },
}))

afterEach(() => {
  vi.useRealTimers()
  clearProfiles()
  useDaemonStream().stopDaemonStream(true)
  vi.clearAllMocks()
})

it('keeps live events after a log refresh and labels activity by outcome', async () => {
  let resolveSnapshot
  fetchDaemonLogs.mockReturnValueOnce(new Promise((resolve) => {
    resolveSnapshot = resolve
  }))
  const daemon = useDaemonStream()
  daemon.startDaemonStream()
  stream.events.onLog({ seq: 12, kind: 'sync_completed', detail: 'Synced report.txt', profile_name: 'docs' })
  stream.events.onLog({ seq: 13, kind: 'fast_noop', detail: 'Unchanged remote', profile_name: 'docs' })
  resolveSnapshot({ latest_seq: 11, events: [{ seq: 11, kind: 'started', detail: 'daemon engine started' }] })
  await flushPromises()

  expect(daemon.logs.map((event) => event.seq)).toEqual([11, 12, 13])
  const panel = mount(ServicePanel)
  expect(panel.text()).toContain('Service started')
  expect(panel.text()).toContain('Synchronization completed')
  expect(panel.get('[data-tone="unchanged"]').text()).toContain('No changes')
  expect(panel.get('[data-tone="success"]').text()).toContain('Synchronization completed')
  expect(panel.text()).not.toContain('Unchanged remote')

  const logs = mount(SystemLogsTab)
  expect(logs.text()).not.toContain('Unchanged remote')
  await logs.get('input[type=checkbox]').setValue(true)
  expect(logs.text()).toContain('Unchanged remote')
  expect(logs.text()).toContain('Synced report.txt')
  panel.unmount()
  logs.unmount()
})

it('keeps the newer live profile state when a status request finishes late', async () => {
  let resolveStatus
  fetchDaemonStatus.mockReturnValueOnce(new Promise((resolve) => { resolveStatus = resolve }))
  const daemon = useDaemonStream()
  daemon.startDaemonStream()
  stream.events.onStatus({ profiles: [{ name: 'work', state: 'idle' }] })
  resolveStatus({ kasumi_version: '0.30.0', profiles: [{ name: 'work', state: 'running_sync' }] })
  await flushPromises()
  expect(daemon.daemonStatus.profiles[0].state).toBe('idle')
  expect(daemon.daemonStatus.kasumi_version).toBe('0.30.0')
})

it('uses one shared status load, renders profiles before status finishes, reuses Hub cache, and recovers status when SSE reconnects', async () => {
  vi.useFakeTimers()
  let resolveStatus
  fetchDaemonStatus.mockReturnValueOnce(new Promise((resolve) => { resolveStatus = resolve }))
  listProfiles.mockResolvedValueOnce({
    profiles: [{ name: 'docs', local_dir: '/docs', remote_dir: 'remote:docs', key_storage: 'file', state: 'ready' }],
  })

  const daemon = useDaemonStream()
  daemon.startDaemonStream()
  const { refreshProfiles, profiles, loaded } = useProfiles()
  await refreshProfiles()

  // Profiles arrived immediately while /v1/status is still pending, and only 1 /v1/status call fired.
  expect(loaded.value).toBe(true)
  expect(profiles.value).toHaveLength(1)
  expect(fetchDaemonStatus).toHaveBeenCalledTimes(1)

  resolveStatus({ running: true, profiles: [{ name: 'docs', state: 'idle' }] })
  await flushPromises()
  expect(fetchDaemonStatus).toHaveBeenCalledTimes(1)

  // Mounting and remounting HubView reuses loaded profiles without extra HTTP fetches.
  const hubStubs = { RouterLink: { template: '<a><slot /></a>' }, SystemModal: true, PreviewChangesModal: true, CreateProfileWizardModal: true, UnlockModal: true }
  const hub1 = mount(HubView, { global: { stubs: hubStubs } })
  await flushPromises()
  expect(hub1.text()).toContain('docs')
  expect(listProfiles).toHaveBeenCalledTimes(1)
  hub1.unmount()

  const hub2 = mount(HubView, { global: { stubs: hubStubs } })
  await flushPromises()
  expect(listProfiles).toHaveBeenCalledTimes(1)
  hub2.unmount()

  // When SSE disconnects/reconnects, fallback status polling kicks in and stops once connected.
  fetchDaemonStatus.mockResolvedValue({ running: true, profiles: [{ name: 'docs', state: 'idle' }] })
  stream.events.onStateChange('reconnecting')
  await flushPromises()
  const afterReconnectCount = fetchDaemonStatus.mock.calls.length
  expect(afterReconnectCount).toBeGreaterThanOrEqual(2)
  await vi.advanceTimersByTimeAsync(5100)
  expect(fetchDaemonStatus.mock.calls.length).toBeGreaterThan(afterReconnectCount)
  const beforeConnected = fetchDaemonStatus.mock.calls.length
  stream.events.onStateChange('connected')
  await vi.advanceTimersByTimeAsync(10000)
  expect(fetchDaemonStatus.mock.calls.length).toBe(beforeConnected)
})

it('refreshes profile activity when external CLI lock releases via SSE', async () => {
  listProfiles.mockResolvedValueOnce({
    profiles: [
      {
        name: 'Documents',
        local_dir: '/docs',
        remote_dir: 'remote:docs',
        key_storage: 'file',
        state: 'ready',
        activity: { last_complete_sync: { status: 'succeeded', finished_at: 1000, duration_ms: 500 } },
      },
    ],
  })
  getProfile.mockResolvedValueOnce({
    name: 'Documents',
    state: 'ready',
    problem: 'none',
    activity: { last_complete_sync: { status: 'succeeded', finished_at: 2000, duration_ms: 1900 } },
  })

  const daemon = useDaemonStream()
  daemon.startDaemonStream()
  const { refreshProfiles, profiles } = useProfiles()
  await refreshProfiles()

  stream.events.onStatus({
    profiles: [{ name: 'Documents', state: 'idle', busy: true, active_operation: 'external' }],
  })
  await flushPromises()
  expect(getProfile).not.toHaveBeenCalled()

  stream.events.onStatus({
    profiles: [{ name: 'Documents', state: 'idle', busy: false, active_operation: '' }],
  })
  await flushPromises()
  expect(getProfile).toHaveBeenCalledWith('Documents')
  expect(profiles.value[0].activity.last_complete_sync.duration_ms).toBe(1900)
})

it('does not start a fallback polling loop when stopDaemonStream disconnects', async () => {
  vi.useFakeTimers()
  const ds = useDaemonStream()
  ds.startDaemonStream()
  await flushPromises()
  fetchDaemonStatus.mockClear()

  ds.stopDaemonStream(true)
  await flushPromises()
  expect(ds.streamState).toBe('disconnected')
  expect(fetchDaemonStatus).not.toHaveBeenCalled()

  await vi.advanceTimersByTimeAsync(15000)
  expect(fetchDaemonStatus).not.toHaveBeenCalled()
})

it('starts HubView with all profiles collapsed by default and toggles on user click', async () => {
  listProfiles.mockResolvedValueOnce({
    profiles: [
      { name: 'alpha', local_dir: '/alpha', remote_dir: 'remote:alpha', key_storage: 'file', state: 'ready' },
      { name: 'beta', local_dir: '/beta', remote_dir: 'remote:beta', key_storage: 'file', state: 'ready' },
    ],
  })
  fetchDaemonStatus.mockResolvedValueOnce({
    running: true,
    profiles: [
      { name: 'alpha', state: 'idle' },
      { name: 'beta', state: 'idle' },
    ],
  })

  const { refreshProfiles } = useProfiles()
  await refreshProfiles()

  const hubStubs = { RouterLink: { template: '<a><slot /></a>' }, SystemModal: true, PreviewChangesModal: true, CreateProfileWizardModal: true, UnlockModal: true }
  const hub = mount(HubView, { global: { stubs: hubStubs } })
  await flushPromises()

  const cards = hub.findAllComponents(ProfileCard)
  expect(cards).toHaveLength(2)
  expect(cards[0].props('expanded')).toBe(false)
  expect(cards[1].props('expanded')).toBe(false)

  await cards[0].vm.$emit('toggle', 'alpha')
  expect(cards[0].props('expanded')).toBe(true)
  expect(cards[1].props('expanded')).toBe(false)

  await cards[0].vm.$emit('toggle', 'alpha')
  expect(cards[0].props('expanded')).toBe(false)
  expect(cards[1].props('expanded')).toBe(false)

  hub.unmount()
})
