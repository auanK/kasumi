import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import ProfileCard from '../hub/ProfileCard.vue'
import ServicePanel from '../hub/ServicePanel.vue'
import CreateProfileWizardModal from '../hub/CreateProfileWizardModal.vue'
import ProfileOverview from '../workspace/ProfileOverview.vue'
import WorkspaceTopbar from '../workspace/WorkspaceTopbar.vue'
import PreviewChangesModal from '../workspace/PreviewChangesModal.vue'
import TextDiffViewer from '../workspace/history/TextDiffViewer.vue'
import QuickActionsCard from '../workspace/maintenance/QuickActionsCard.vue'
import MaintenanceTab from '../workspace/maintenance/MaintenanceTab.vue'
import FilesTab from '../workspace/files/FilesTab.vue'
import { fetchJob, startMaintenanceJob, startPreviewJob } from '../api/maintenance.js'
import { fetchLocalTree, fetchRemoteCommits, fetchRemoteHealth, fetchRemoteSummary, fetchRemoteTree } from '../api/remote.js'
import { useDaemonStream } from '../composables/useDaemonStream.js'
import { formatTimestamp } from '../utils/format.js'

vi.mock('../api/maintenance.js', () => ({
  fetchJob: vi.fn(),
  startMaintenanceJob: vi.fn(),
  startPreviewJob: vi.fn(),
}))

vi.mock('../api/remote.js', () => ({
  buildLocalThumbnailUrl: vi.fn((profile, path, size = 160) => `/v1/local/${profile}/thumbnail?path=${path}&size=${size}`),
  buildRemoteThumbnailUrl: vi.fn((profile, { path, hash, commit, size = 160 } = {}) =>
    hash ? `/v1/remote/${profile}/thumbnail?path=${path}&hash=${hash}${commit ? `&commit=${commit}` : ''}&size=${size}` : ''),
  cachedLocalTree: vi.fn(),
  cachedRemoteReading: vi.fn(),
  cachedRemoteTree: vi.fn(),
  clearSavedRemoteThumbnails: vi.fn(),
  fetchRemoteHealth: vi.fn(),
  fetchRemoteSummary: vi.fn(),
  fetchRemoteTree: vi.fn(),
  fetchLocalTree: vi.fn().mockResolvedValue({ entries: [] }),
  fetchRemoteCommits: vi.fn(),
  fetchRemoteWriters: vi.fn().mockResolvedValue({
    writers: [{ identifier: 'writer-a' }],
    barriers: [{ identifier: 'barrier-a' }],
  }),
  getSavedRemoteThumbnail: vi.fn(() => ''),
  saveRemoteThumbnail: vi.fn(),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))

vi.mock('../api/profiles.js', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    listRcloneRemotes: vi.fn().mockResolvedValue({ remotes: ['gdrive'] }),
  }
})

describe('Hub & Workspace components', () => {
  afterEach(() => vi.useRealTimers())

  it('keeps live progress visible and expands the local paths and daily actions in place', async () => {
    const profile = {
      name: 'docs',
      local_dir: '/home/user/docs',
      remote_dir: 'gdrive:kasumi/docs',
      key_storage: 'vault',
      paused: false,
    }
    const wrapper = mount(ProfileCard, {
      props: {
        profile,
        daemonState: {
          state: 'running_sync',
          sync_phase: 'applying',
          active_stage: 'uploading',
          active_bytes: 512,
          active_total_bytes: 1024,
          active_bytes_per_second: 256,
        },
      },
    })

    expect(wrapper.text()).toContain('docs')
    expect(wrapper.find('progress').exists()).toBe(true)
    expect(wrapper.findAll('.k-sync-steps li')).toHaveLength(5)
    expect(wrapper.find('[aria-current="step"]').text()).toContain('Apply')
    expect(wrapper.text()).toContain('50%')
    expect(wrapper.text()).toContain('256 B/s')
    expect(wrapper.text()).not.toContain(profile.local_dir)
    const summary = wrapper.find('button[aria-expanded]')
    await summary.trigger('click')
    expect(wrapper.emitted('toggle')).toEqual([['docs']])
    await wrapper.setProps({ expanded: true })
    expect(summary.attributes('aria-expanded')).toBe('true')
    expect(wrapper.text()).toContain(profile.local_dir)
    expect(wrapper.text()).toContain(profile.remote_dir)
    expect(wrapper.find('details').element.open).toBe(false)
    const buttons = wrapper.findAll('footer button')
    expect(buttons.find((button) => button.text() === 'Preview changes').element.disabled).toBe(true)
    await wrapper.setProps({ daemonState: { state: 'idle' } })
    await buttons.find((button) => button.text() === 'Preview changes').trigger('click')
    expect(wrapper.emitted('preview')[0][0].name).toBe('docs')
    await buttons.find((button) => button.text() === 'Edit profile').trigger('click')
    expect(wrapper.emitted('edit')[0][0].name).toBe('docs')
  })

  it('presents the async preview as planned file operations', async () => {
    vi.useFakeTimers()
    startPreviewJob.mockResolvedValue({ id: 7, state: 'running' })
    fetchJob.mockResolvedValue({ id: 7, state: 'completed', result: {
      upload_bytes: 1024,
      download_bytes: 0,
      items: [{ path: 'report.txt', action: 'upload', alternative_path: '', size: 1024 }],
    } })
    const wrapper = mount(PreviewChangesModal, { props: { profile: 'docs' }, global: { stubs: { Teleport: true } } })
    await flushPromises()
    await vi.advanceTimersByTimeAsync(500)
    expect(startPreviewJob).toHaveBeenCalledWith('docs', expect.any(AbortSignal))
    expect(fetchJob).toHaveBeenCalledWith(7, expect.any(AbortSignal))
    expect(wrapper.find('tbody').text()).toContain('report.txt')
    expect(wrapper.find('tbody').text()).toContain('Upload')
    wrapper.unmount()
  })

  it('sends the selected barrier identifier only after explicit confirmation', async () => {
    startMaintenanceJob.mockResolvedValue({ id: 8, state: 'running' })
    const wrapper = mount(QuickActionsCard, { props: { profile: 'docs' }, global: { stubs: { Teleport: true } } })
    await wrapper.findAll('button').find((button) => button.text() === 'Inspect remote markers').trigger('click')
    await flushPromises()
    await wrapper.findAll('select').at(-1).setValue('barrier-a')
    await wrapper.findAll('button').find((button) => button.text() === 'Remove barrier').trigger('click')
    expect(startMaintenanceJob).not.toHaveBeenCalled()
    await wrapper.findAll('[role="dialog"] button').find((button) => button.text() === 'Confirm').trigger('click')
    expect(startMaintenanceJob).toHaveBeenCalledWith('docs', 'remove-barrier', {
      barrier_id: 'barrier-a', confirm_abandoned: true,
    })
  })

  it('shows maintenance immediately and only queries storage when requested', async () => {
    startMaintenanceJob.mockClear().mockResolvedValue({ id: 9, state: 'running' })
    let finishSummary
    fetchRemoteSummary.mockReturnValueOnce(new Promise((resolve) => {
      finishSummary = resolve
    }))
    fetchRemoteHealth.mockResolvedValueOnce({ state: 'healthy' })

    const wrapper = mount(MaintenanceTab, {
      props: { profile: 'docs' },
      global: { stubs: { Teleport: true } },
    })
    await nextTick()
    const simulateCleanup = wrapper.findAll('button').find((button) => button.text() === 'Simulate')
    expect(simulateCleanup.element.disabled).toBe(false)
    expect(fetchRemoteSummary).not.toHaveBeenCalled()
    expect(fetchRemoteHealth).not.toHaveBeenCalled()
    await wrapper.findAll('button').find((button) => button.text() === 'Measure space').trigger('click')
    expect(simulateCleanup.element.disabled).toBe(false)
    finishSummary({ space_usage: {} })
    await flushPromises()
    expect(fetchRemoteHealth).not.toHaveBeenCalled()
    expect(simulateCleanup.element.disabled).toBe(false)
    await wrapper.findAll('button').find((button) => button.text() === 'Check health').trigger('click')
    await flushPromises()
    expect(fetchRemoteHealth).toHaveBeenCalledWith('docs', expect.any(AbortSignal), { refresh: true })
    expect(simulateCleanup.element.disabled).toBe(false)
    await simulateCleanup.trigger('click')
    await flushPromises()
    expect(startMaintenanceJob).toHaveBeenCalledWith('docs', 'gc', { dry_run: true })
    expect(simulateCleanup.element.disabled).toBe(true)
    wrapper.unmount()
  })

  it('shows the local reference and opens older snapshots in the same folder', async () => {
    const commitTime = 1760000000
    fetchLocalTree.mockResolvedValueOnce({ commit_id: 'synced-ref', created_at: commitTime, height: 3, entries: [{ path: 'work/local.txt', type: 'file', size: 5 }] })
    fetchRemoteTree.mockClear()
      .mockResolvedValueOnce({ commit_id: 'earlier', created_at: commitTime, height: 2, entries: [{ path: 'work/old.txt', type: 'file', size: 5 }] })
      .mockResolvedValueOnce({ commit_id: 'latest', created_at: commitTime + 100, height: 3, entries: [{ path: 'work/new.txt', type: 'file', size: 5 }] })
    fetchRemoteCommits.mockResolvedValueOnce({ commits: [{ commit_id: 'earlier', created_at: commitTime, height: 2 }] })
    const wrapper = mount(FilesTab, { props: { profile: 'docs' }, global: {
      stubs: { FilePreviewPane: true, RestoreModal: true, Teleport: true },
    } })
    await flushPromises()
    expect(wrapper.get('.k-snapshot-context').text()).toContain('Local map')
    expect(wrapper.get('.k-snapshot-context').text()).toContain('synced-ref')
    expect(wrapper.get('.k-snapshot-context').text()).toContain(formatTimestamp(commitTime))
    expect(fetchRemoteCommits).not.toHaveBeenCalled()
    expect(fetchRemoteTree).not.toHaveBeenCalled()
    await wrapper.get('.k-folder-tree button[title="work"]').trigger('click')
    const snapshotButton = wrapper.get('button[aria-haspopup="dialog"]')
    await snapshotButton.trigger('click')
    await flushPromises()
    expect(fetchRemoteCommits).toHaveBeenCalledWith('docs', expect.any(AbortSignal))
    await wrapper.get('[role="dialog"] code[title="earlier"]').trigger('click')
    await flushPromises()
    expect(fetchRemoteTree).toHaveBeenCalledWith('docs', { commit: 'earlier', refresh: false, signal: expect.any(AbortSignal) })
    expect(wrapper.get('.k-explorer-path [aria-current="location"]').text()).toBe('work')
    expect(wrapper.text()).toContain('old.txt')
    expect(wrapper.get('.k-snapshot-context').text()).toContain('Snapshot in use')
    expect(wrapper.get('.k-snapshot-context').text()).toContain('earlier')
    expect(wrapper.get('.k-snapshot-context').text()).toContain(formatTimestamp(commitTime))
    fetchRemoteCommits.mockResolvedValueOnce({ commits: [{ commit_id: 'earlier', created_at: commitTime, height: 2 }] })
    await snapshotButton.trigger('click')
    await wrapper.get('[role="dialog"] button.k-list-row').trigger('click')
    await flushPromises()
    expect(fetchRemoteTree).toHaveBeenLastCalledWith('docs', { commit: undefined, refresh: false, signal: expect.any(AbortSignal) })
    expect(wrapper.text()).toContain('new.txt')
    wrapper.unmount()
  })

  it('keeps the file listing available and disables maintenance until the sync finishes', async () => {
    const stream = useDaemonStream()
    stream.daemonStatus = { profiles: [{ name: 'docs', state: 'running_sync' }] }
    fetchLocalTree.mockClear().mockResolvedValue({ entries: [{ path: 'folder/file.txt', type: 'file', size: 5 }] })
    fetchRemoteTree.mockClear()
    const files = mount(FilesTab, { props: { profile: 'docs', locked: true }, global: {
      stubs: { FilePreviewPane: true, RestoreModal: true },
    } })
    const maintenance = mount(MaintenanceTab, { props: { profile: 'docs' } })
    const run = maintenance.findAll('button').find((button) => button.text() === 'Simulate')
    try {
      await flushPromises()
      expect(files.findAll('button').find((button) => button.text() === 'Vault').element.disabled).toBe(true)
      expect(files.get('button[aria-haspopup="dialog"]').element.disabled).toBe(true)
      expect(files.get('.k-folder-contents button[title="folder"]').exists()).toBe(true)
      expect(maintenance.text()).toContain('Syncing now')
      expect(run.element.disabled).toBe(true)
      expect(fetchRemoteTree).not.toHaveBeenCalled()
      stream.daemonStatus = { profiles: [{ name: 'docs', state: 'idle' }] }
      await flushPromises()
      expect(run.element.disabled).toBe(false)
      await files.get('.k-folder-tree button[title="folder"]').trigger('click')
      expect(files.get('.k-explorer-path [aria-current="location"]').text()).toBe('folder')
      const icons = files.findAll('button').find((button) => button.text() === 'Medium icons')
      await icons.trigger('click')
      expect(files.find('.k-explorer-icons button[title="folder/file.txt"]').exists()).toBe(true)
      stream.daemonStatus = { profiles: [{ name: 'docs', state: 'running_sync' }] }
      await nextTick()
      expect(files.find('.k-explorer-icons button[title="folder/file.txt"]').exists()).toBe(true)
      expect(fetchLocalTree).toHaveBeenCalledTimes(2)
      expect(fetchRemoteTree).not.toHaveBeenCalled()
    } finally {
      files.unmount()
      maintenance.unmount()
      stream.daemonStatus = null
      localStorage.removeItem('kasumi.files.view.v2')
    }
  })

  it('selects with a click, opens folders with a double click and keeps folder navigation local', async () => {
    fetchLocalTree.mockClear().mockResolvedValue({ entries: [
      { path: 'work/2026/report.txt', type: 'file' },
      { path: 'personal/report.txt', type: 'file' },
      { path: 'empty', type: 'directory' },
    ] })
    const wrapper = mount(FilesTab, { props: { profile: 'docs' }, global: {
      stubs: { FilePreviewPane: true, RestoreModal: true },
    } })
    try {
      await flushPromises()
      const folder = () => wrapper.get('.k-folder-contents button[title="work"]')
      const location = () => wrapper.get('.k-explorer-path [aria-current="location"]').text()
      await folder().trigger('click', { detail: 1 })
      expect(location()).toBe('Root')
      expect(folder().attributes('aria-pressed')).toBe('true')
      await folder().trigger('dblclick')
      expect(location()).toBe('work')
      await wrapper.get('input[type="search"]').setValue('report')
      expect(wrapper.find('.k-folder-contents button[title="work/2026/report.txt"]').exists()).toBe(true)
      expect(wrapper.find('.k-folder-contents button[title="personal/report.txt"]').exists()).toBe(false)
      await wrapper.get('button[aria-label="Back"]').trigger('click')
      expect(location()).toBe('Root')
      expect(wrapper.get('input[type="search"]').element.value).toBe('')
      await wrapper.get('button[aria-label="Forward"]').trigger('click')
      expect(location()).toBe('work')
      await wrapper.get('.k-folder-tree button[title="work/2026"]').trigger('click')
      expect(location()).toBe('2026')
      await wrapper.get('button[aria-label="Up one folder"]').trigger('click')
      expect(location()).toBe('work')
      expect(fetchLocalTree).toHaveBeenCalledTimes(1)
      expect(wrapper.emitted('update:folder').at(-1)).toEqual(['work'])
    } finally {
      wrapper.unmount()
    }
  })

  it('guides user through 2-step profile wizard before submitting', async () => {
    const wrapper = mount(CreateProfileWizardModal, {
      props: { open: true },
      global: { stubs: { Teleport: true } },
    })

    const nextBtn = wrapper.find('[data-testid="wizard-next"]')
    expect(nextBtn.element.disabled).toBe(true)

    await wrapper.find('[data-testid="wizard-name"]').setValue('photos')
    await wrapper.find('[data-testid="wizard-local"]').setValue('/home/user/Photos')
    await wrapper.find('[data-testid="wizard-remote"]').setValue('gdrive:kasumi/photos')
    await nextTick()

    expect(wrapper.find('[data-testid="wizard-next"]').element.disabled).toBe(false)
    await wrapper.find('[data-testid="wizard-next"]').trigger('click')
    await nextTick()

    expect(wrapper.find('#wizard-create-form').exists()).toBe(true)
  })

  it('renders WorkspaceTopbar tabs cleanly and emits tab selection', async () => {
    const wrapper = mount(WorkspaceTopbar, {
      props: {
        profileName: 'work',
        profiles: [{ name: 'work' }, { name: 'personal' }],
        activeTab: 'files',
        conflictCount: 2,
      },
      global: {
        stubs: {
          RouterLink: { template: '<a><slot /></a>' },
        },
      },
    })

    const navTabs = wrapper.findAll('nav .k-tab')
    expect(navTabs).toHaveLength(5)
    expect(wrapper.find('.k-tab-count').text()).toBe('2')

    expect(navTabs[0].text()).toBe('Overview')
    await navTabs[2].trigger('click')
    expect(wrapper.emitted('select-tab')[0]).toEqual(['history'])
  })

  it('renders TextDiffViewer rows for additions and deletions', () => {
    const wrapper = mount(TextDiffViewer, {
      props: { leftText: 'hello\nold', rightText: 'hello\nnew' },
    })
    expect(wrapper.findAll('.k-diff-row--del')).toHaveLength(1)
    expect(wrapper.findAll('.k-diff-row--add')).toHaveLength(1)
  })

  it('displays local operation durations in ProfileOverview, ProfileCard, and ServicePanel', () => {
    const overview = mount(ProfileOverview, {
      props: {
        profile: {
          name: 'docs',
          local_dir: '/home/user/docs',
          remote_dir: 'gdrive:kasumi/docs',
          state: 'ready',
          activity: {
            last_complete_sync: { status: 'succeeded', finished_at: 1700000100, duration_ms: 4120 },
            last_attempt: { operation: 'sync', status: 'succeeded', duration_ms: 4120 },
            recent_executions: [
              { execution_id: 'e1', operation: 'sync', started_at: 1700000000, finished_at: 1700000002, duration_ms: 850, status: 'succeeded_no_changes', detail: 'ok', commit_id: 'aaaa1111' },
              { execution_id: 'e2', operation: 'sync', started_at: 1700000090, finished_at: 1700000100, duration_ms: 4120, status: 'succeeded', detail: 'newer', commit_id: 'bbbb2222' },
            ],
          },
        },
        daemonState: { state: 'idle' },
      },
    })
    expect(overview.text()).toContain('4.1s')
    expect(overview.text()).toContain('Duration')
    const rows = overview.findAll('tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0].text()).toContain('4.1s')
    expect(rows[1].text()).toContain('850 ms')
    overview.unmount()

    const stream = useDaemonStream()
    stream.logs = [
      { seq: 1, timestamp_unix: 1700000100, profile_name: 'docs', kind: 'sync_completed', detail: 'up=1, down=0, rm=0, mv=0 (2.4 s)' },
    ]
    const panel = mount(ServicePanel)
    expect(panel.text()).toContain('2.4s')
    panel.unmount()
    stream.logs = []
  })
})
