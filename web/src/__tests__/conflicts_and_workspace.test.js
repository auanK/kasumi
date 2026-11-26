import { flushPromises, mount } from '@vue/test-utils'
import { reactive } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ProfileWorkspaceView from '../workspace/ProfileWorkspaceView.vue'
import ConflictsTab from '../workspace/conflicts/ConflictsTab.vue'
import { fetchConflictDiff, listConflicts } from '../api/conflicts.js'
import { clearProfiles } from '../composables/useProfiles.js'
import { listProfiles } from '../api/profiles.js'

const route = reactive({ params: { name: 'alpha', tab: 'overview' }, query: {} })

vi.mock('vue-router', () => ({
  useRoute: () => route,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../api/profiles.js', () => ({
  listProfiles: vi.fn().mockResolvedValue({
    profiles: [
      { name: 'alpha', local_dir: '/alpha', remote_dir: 'r:alpha', key_storage: 'file', state: 'ready' },
      { name: 'beta', local_dir: '/beta', remote_dir: 'r:beta', key_storage: 'file', state: 'ready' },
    ],
  }),
  getProfile: vi.fn(),
}))

vi.mock('../api/daemon.js', () => ({
  fetchDaemonLogs: vi.fn().mockResolvedValue({ latest_seq: 0, events: [] }),
  fetchDaemonStatus: vi.fn().mockResolvedValue({ running: true, profiles: [] }),
}))

vi.mock('../api/sse.js', () => ({
  connectEventStream: () => ({ close() {} }),
}))

vi.mock('../api/conflicts.js', () => ({
  listConflicts: vi.fn(),
  fetchConflictDiff: vi.fn(),
  resolveConflict: vi.fn(),
}))

describe('Workspace lazy conflicts and error/stale-response isolation', () => {
  afterEach(() => {
    clearProfiles()
    vi.clearAllMocks()
    route.params = { name: 'alpha', tab: 'overview' }
  })

  it('never scans conflicts when opening overview or files, even across profile switches', async () => {
    const wrapper = mount(ProfileWorkspaceView, {
      global: {
        stubs: {
          FilesTab: true,
          HistoryTab: true,
          MaintenanceTab: true,
          SettingsTab: true,
          SystemModal: true,
          PreviewChangesModal: true,
          UnlockModal: true,
          RouterLink: { template: '<a><slot /></a>' },
        },
      },
    })
    await flushPromises()
    expect(listProfiles).toHaveBeenCalledTimes(1)
    expect(listConflicts).not.toHaveBeenCalled()

    route.params.tab = 'files'
    await flushPromises()
    route.params.name = 'beta'
    await flushPromises()
    expect(listConflicts).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('distinguishes loading, error, and empty states and discards stale profile/artifact results', async () => {
    let resolveAlpha
    listConflicts.mockReturnValueOnce(new Promise((resolve) => { resolveAlpha = resolve }))

    const wrapper = mount(ConflictsTab, { props: { profile: 'alpha' } })
    expect(wrapper.text()).toContain('Loading...')
    expect(wrapper.text()).not.toContain('No file conflicts')

    // Switch profile before alpha resolves; fail beta to ensure error state is shown cleanly.
    listConflicts.mockRejectedValueOnce(new Error('permission denied'))
    await wrapper.setProps({ profile: 'beta' })
    resolveAlpha({
      groups: [{ canonical_path: 'stale.txt', artifacts: [{ path: 'stale.txt.kasumiconflict_local', size: 4 }] }],
    })
    await flushPromises()
    expect(wrapper.text()).toContain('permission denied')
    expect(wrapper.text()).not.toContain('stale.txt')
    expect(wrapper.text()).not.toContain('No file conflicts')

    // Retry on beta and receive empty list -> renders empty state.
    listConflicts.mockResolvedValueOnce({ groups: [] })
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('No file conflicts')

    // Stale artifact diff response must not overwrite newly selected artifact diff.
    let resolveArt1
    listConflicts.mockResolvedValueOnce({
      groups: [{
        canonical_path: 'doc.txt',
        artifacts: [
          { path: 'doc.txt.kasumiconflict_local', size: 4 },
          { path: 'doc.txt.kasumiconflict_remote', size: 4 },
        ],
      }],
    })
    fetchConflictDiff
      .mockReturnValueOnce(new Promise((resolve) => { resolveArt1 = resolve }))
      .mockResolvedValueOnce({
        canonical: { hex: '6e6577' },
        artifact: { hex: '72656d6f7465' },
      })
    await wrapper.setProps({ profile: 'alpha' })
    await flushPromises()

    await wrapper.get('select').setValue('doc.txt.kasumiconflict_remote')
    await flushPromises()
    resolveArt1({
      canonical: { hex: '6f6c64' },
      artifact: { hex: '7374616c65' },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('remote')
    expect(wrapper.text()).not.toContain('stale')
    wrapper.unmount()
  })
})
