import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

const profileMocks = vi.hoisted(() => ({
  checkIgnorePaths: vi.fn(),
  initIgnoreFile: vi.fn(),
}))

const maintMocks = vi.hoisted(() => ({
  fetchJob: vi.fn(),
}))

vi.mock('../api/profiles.js', () => ({
  checkIgnorePaths: profileMocks.checkIgnorePaths,
  initIgnoreFile: profileMocks.initIgnoreFile,
}))

vi.mock('../api/maintenance.js', () => ({
  fetchJob: maintMocks.fetchJob,
  startMaintenanceJob: vi.fn(),
}))

import JobProgressPanel from '../components/JobProgressPanel.vue'
import IgnoreRulesCard from '../workspace/maintenance/IgnoreRulesCard.vue'
import JobsActivityCard from '../workspace/maintenance/JobsActivityCard.vue'
import QuickActionsCard from '../workspace/maintenance/QuickActionsCard.vue'
import MaintenanceTab from '../workspace/maintenance/MaintenanceTab.vue'

describe('IgnoreRulesCard ignore tester & presets', () => {
  afterEach(() => vi.clearAllMocks())

  it('normalizes pasted paths, maps backend items/rule_line, and prompts confirmation before overwriting .kasumiignore', async () => {
    profileMocks.checkIgnorePaths.mockResolvedValue({
      ignore_file: 'D:\\Pictures\\.kasumiignore',
      ignore_file_present: true,
      items: [
        {
          input_path: 'desktop.ini',
          logical_path: 'desktop.ini',
          is_directory: false,
          disposition: 'ignored_protected',
          reserved_internal: false,
          matched_rule: true,
          rule_line: 4,
          rule_text: 'desktop.ini',
        },
        {
          input_path: 'kasumi.db',
          logical_path: 'kasumi.db',
          is_directory: false,
          disposition: 'ignored_protected',
          reserved_internal: true,
          matched_rule: true,
          rule_line: 0,
          rule_text: '',
        },
      ],
    })
    profileMocks.initIgnoreFile.mockResolvedValue({
      dry_run: true,
      content: 'desktop.ini\n',
    })

    const wrapper = mount(IgnoreRulesCard, {
      props: { profile: 'Pictures', disabled: false },
      global: { stubs: { Teleport: true } },
    })

    await wrapper.find('textarea').setValue('"/desktop.ini"\nkasumi.db')
    await wrapper.findAll('button').find((b) => b.text() === 'Test paths').trigger('click')
    await flushPromises()

    expect(profileMocks.checkIgnorePaths).toHaveBeenCalledWith(
      'Pictures',
      ['desktop.ini', 'kasumi.db'],
      { signal: expect.any(AbortSignal) }
    )
    expect(wrapper.text()).toContain('D:\\Pictures\\.kasumiignore')
    expect(wrapper.text()).toContain('Ignored protected')
    expect(wrapper.text()).toContain('L4: desktop.ini')
    expect(wrapper.text()).toContain('Reserved internal Kasumi file')

    await wrapper.findAll('button').find((b) => b.text() === 'Preview preset').trigger('click')
    await flushPromises()
    expect(profileMocks.initIgnoreFile).toHaveBeenCalledWith(
      'Pictures',
      { preset: 'default', dryRun: true, force: false, signal: expect.any(AbortSignal) }
    )
    expect(wrapper.find('pre').text()).toContain('desktop.ini')

    // Write prompts confirmation because ignoreFilePresent === true
    await wrapper.findAll('button').find((b) => b.text() === 'Write .kasumiignore').trigger('click')
    expect(wrapper.find('[role="dialog"]').exists()).toBe(true)
    await wrapper.findAll('[role="dialog"] button').find((b) => b.text() === 'Confirm').trigger('click')
    await flushPromises()
    expect(profileMocks.initIgnoreFile).toHaveBeenLastCalledWith(
      'Pictures',
      { preset: 'default', dryRun: false, force: true, signal: expect.any(AbortSignal) }
    )
    wrapper.unmount()
  })
})

import { extractJobProgressMeter } from '../utils/jobFormat.js'
import { useDaemonStream } from '../composables/useDaemonStream.js'

describe('JobProgressPanel & JobsActivityCard feedback', () => {
  afterEach(() => {
    const stream = useDaemonStream()
    stream.jobs = []
    stream.daemonStatus = null
    vi.clearAllMocks()
  })

  it('shows Simulation vs Real execution pill and step bar on JobProgressPanel', () => {
    const sim = mount(JobProgressPanel, {
      props: {
        job: {
          id: 10,
          profile: 'Pictures',
          operation: 'gc',
          state: 'running',
          dry_run: true,
          progress: { stage: 'analyzing', sub_stage: 'analyzing_reachability' },
        },
      },
    })
    expect(sim.text()).toContain('Clean up vault')
    expect(sim.text()).toContain('Simulation')
    expect(sim.text()).toContain('Analyzing retained versions')
    expect(sim.findAll('.k-sync-steps li')).toHaveLength(4)
    sim.unmount()

    const real = mount(JobProgressPanel, {
      props: {
        job: {
          id: 11,
          profile: 'Pictures',
          operation: 'gc',
          state: 'running',
          dry_run: false,
          progress: { stage: 'applying', candidate_objects: 20, removed_objects: 5 },
        },
      },
    })
    expect(real.text()).toContain('Real execution')
    expect(real.text()).toContain('25%')
    real.unmount()

    const tMock = (key, params) => `${key}:${JSON.stringify(params || {})}`
    expect(
      extractJobProgressMeter(
        {
          operation: 'gc',
          progress: {
            stage: 'analyzing',
            sub_stage: 'authenticating_history',
            commits_processed: 45,
            commits_total: 100,
          },
        },
        tMock
      )
    ).toMatchObject({ current: 45, total: 100, percent: 45 })

    const analyzing = mount(JobProgressPanel, {
      props: {
        job: {
          id: 13,
          profile: 'Pictures',
          operation: 'gc',
          state: 'running',
          dry_run: false,
          progress: {
            stage: 'analyzing',
            sub_stage: 'authenticating_history',
            commits_processed: 45,
            commits_total: 100,
          },
        },
      },
    })
    expect(analyzing.text()).toContain('45%')
    analyzing.unmount()
  })

  it('renders inline simulation vs real summary cards and full modal metrics in JobsActivityCard', async () => {
    maintMocks.fetchJob.mockResolvedValue({
      id: 12,
      profile: 'Pictures',
      operation: 'gc',
      state: 'completed',
      dry_run: true,
      started_at: 1700000000,
      finished_at: 1700000004,
      duration_ms: 4120,
      result: {
        dry_run: true,
        candidate_objects: 12,
        candidate_bytes: 4096,
        candidate_content_objects: 10,
        candidate_expired_commits: 2,
        deferred_recent_objects: 1,
      },
    })

    const wrapper = mount(JobsActivityCard, {
      props: {
        jobs: [
          {
            id: 12,
            profile: 'Pictures',
            operation: 'gc',
            state: 'completed',
            dry_run: true,
            started_at: 1700000000,
            finished_at: 1700000004,
            duration_ms: 4120,
            summary: {
              dry_run: true,
              candidate_objects: 12,
              candidate_bytes: 4096,
            },
          },
          {
            id: 13,
            profile: 'Pictures',
            operation: 'repack',
            state: 'completed',
            dry_run: false,
            duration_ms: 850,
            summary: {
              dry_run: false,
              repacked_blobs: 30,
              new_packs: 2,
            },
          },
        ],
      },
      global: { stubs: { Teleport: true } },
    })

    expect(wrapper.text()).toContain('Simulation')
    expect(wrapper.text()).toContain('4.1s')
    expect(wrapper.text()).toContain('850 ms')
    expect(wrapper.text()).toContain('12 objects eligible for removal (4.0 KiB)')
    expect(wrapper.text()).toContain('Real execution')
    expect(wrapper.text()).toContain('30 objects consolidated into 2 pack(s).')

    await wrapper.find('.k-job-btn').trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="dialog"]').text()).toContain('Simulation mode — no changes were written to the remote vault.')
    expect(wrapper.find('[role="dialog"]').text()).toContain('Protected recent objects')
    expect(wrapper.find('[role="dialog"]').text()).toContain('Duration')
    wrapper.unmount()
  })

  it('sends dry_run: false on confirmed real execution for gc, repack, and resolve-missing, and sorts jobs newest-first', async () => {
    maintMocks.startMaintenanceJob = vi.fn().mockResolvedValue({ id: 20, profile: 'Pictures', operation: 'gc', state: 'running', dry_run: false, started_at: 1700000100 })
    const mod = await import('../api/maintenance.js')
    mod.startMaintenanceJob.mockResolvedValue({ id: 20, profile: 'Pictures', operation: 'gc', state: 'running', dry_run: false, started_at: 1700000100 })

    const quick = mount(QuickActionsCard, {
      props: { profile: 'Pictures' },
      global: { stubs: { Teleport: true } },
    })

    // Run + Confirm for gc, repack, and resolve-missing
    const runButtons = quick.findAll('button').filter((b) => b.text() === 'Run')
    expect(runButtons.length).toBeGreaterThanOrEqual(4)
    // Order: fsck, gc, repack, resolve-missing (inside recovery details)
    await runButtons[1].trigger('click')
    await quick.findAll('[role="dialog"] button').find((b) => b.text() === 'Confirm').trigger('click')
    await flushPromises()
    expect(mod.startMaintenanceJob).toHaveBeenLastCalledWith('Pictures', 'gc', { dry_run: false, confirm: true })

    await runButtons[2].trigger('click')
    await quick.findAll('[role="dialog"] button').find((b) => b.text() === 'Confirm').trigger('click')
    await flushPromises()
    expect(mod.startMaintenanceJob).toHaveBeenLastCalledWith('Pictures', 'repack', { dry_run: false, confirm: true })

    await runButtons[3].trigger('click')
    await quick.findAll('[role="dialog"] button').find((b) => b.text() === 'Confirm').trigger('click')
    await flushPromises()
    expect(mod.startMaintenanceJob).toHaveBeenLastCalledWith('Pictures', 'resolve-missing', { dry_run: false, confirm: true })
    quick.unmount()

    const stream = useDaemonStream()
    stream.jobs = [
      { id: 2, profile: 'Pictures', operation: 'fsck', state: 'completed', started_at: 1700000010 },
      { id: 5, profile: 'Pictures', operation: 'gc', state: 'completed', dry_run: true, started_at: 1700000050 },
    ]
    const tab = mount(MaintenanceTab, {
      props: { profile: 'Pictures' },
      global: { stubs: { QuickActionsCard: true, IgnoreRulesCard: true, VaultSpaceCard: true, Teleport: true } },
    })
    await flushPromises()
    const items = tab.findAll('.k-job-btn')
    expect(items).toHaveLength(2)
    expect(items[0].text()).toContain('Clean up vault')
    expect(items[1].text()).toContain('Integrity check')
    tab.unmount()
  })
})
