import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

const remoteMocks = vi.hoisted(() => ({
  fetchRemoteCommits: vi.fn(),
  fetchRemoteDiff: vi.fn(),
  cachedRemoteReading: vi.fn(() => null),
  cachedRemoteDiff: vi.fn(() => null),
  buildRemoteDownloadUrl: (profile, { path, commit }) =>
    `/v1/remote/${encodeURIComponent(profile)}/download?path=${encodeURIComponent(path)}&commit=${encodeURIComponent(commit || '')}`,
}))

vi.mock('../api/remote.js', () => ({
  fetchRemoteCommits: remoteMocks.fetchRemoteCommits,
  fetchRemoteDiff: remoteMocks.fetchRemoteDiff,
  cachedRemoteReading: remoteMocks.cachedRemoteReading,
  cachedRemoteDiff: remoteMocks.cachedRemoteDiff,
  buildRemoteDownloadUrl: remoteMocks.buildRemoteDownloadUrl,
}))

vi.mock('../composables/useProfileActivity.js', async () => {
  const { ref } = await import('vue')
  return {
    useProfileActivity: () => ({
      serverBusy: ref(false),
      blockedReason: ref(''),
    }),
  }
})

import HistoryTab from '../workspace/history/HistoryTab.vue'

describe('HistoryTab rich details & caching', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  const commitsPayload = {
    commits: [
      {
        commit_id: 'c2',
        height: 2,
        created_at_unix: 1700000200,
        parent_ids: ['c1'],
        logical_head: true,
        total_bytes: 3072,
        entry_count: 5,
        authorship: { operation: 'sync', machine_name: 'Karyl' },
      },
      {
        commit_id: 'c1',
        height: 1,
        created_at_unix: 1700000100,
        parent_ids: [],
        total_bytes: 1024,
        entry_count: 3,
        authorship: { operation: 'sync', machine_name: 'Karyl' },
      },
    ],
  }

  it('loads commits without auto-fetching diff, shows snapshot metrics and deltas, and emits browse-commit', async () => {
    remoteMocks.fetchRemoteCommits.mockResolvedValue(commitsPayload)
    remoteMocks.fetchRemoteDiff.mockResolvedValue({
      changes: [{ path: 'notes.txt', kind: 'modified' }],
    })

    const wrapper = mount(HistoryTab, {
      props: { profile: 'demo' },
    })
    await flushPromises()

    expect(remoteMocks.fetchRemoteCommits).toHaveBeenCalledTimes(1)
    expect(remoteMocks.fetchRemoteDiff).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Karyl')
    expect(wrapper.text()).toContain('3.0 KiB')
    expect(wrapper.text()).toContain('+2.0 KiB')
    expect(wrapper.text()).toContain('+2')

    const browseBtn = wrapper.findAll('button').find((b) => b.text().includes('Browse snapshot files'))
    await browseBtn.trigger('click')
    expect(wrapper.emitted('browse-commit')?.[0]).toEqual(['c2'])

    const inspectBtn = wrapper.findAll('button').find((b) => b.text().includes('View changed files'))
    await inspectBtn.trigger('click')
    await flushPromises()

    expect(remoteMocks.fetchRemoteDiff).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('notes.txt')
    wrapper.unmount()
  })

  it('renders cached commits immediately without triggering a remote fetch when cache is fresh', async () => {
    remoteMocks.cachedRemoteReading.mockReturnValue({
      fresh: true,
      value: commitsPayload,
    })

    const wrapper = mount(HistoryTab, {
      props: { profile: 'demo' },
    })
    await flushPromises()

    expect(remoteMocks.fetchRemoteCommits).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('3.0 KiB')
    wrapper.unmount()
  })
})
