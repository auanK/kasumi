import { afterEach, expect, it, vi } from 'vitest'
import { cachedInspection, inspectionPending, invalidateInspections, readInspection } from '../api/inspections.js'

afterEach(() => invalidateInspections(undefined, { discard: true }))

it('shares identical reads and runs distinct reads in order within each profile', async () => {
  let finish
  const controller = new AbortController()
  const tree = vi.fn(() => new Promise((resolve) => { finish = resolve }))
  const commits = vi.fn().mockResolvedValue(['second'])
  const first = readInspection('work', 'work/tree', tree, { signal: controller.signal, cacheable: true })
  const duplicate = readInspection('work', 'work/tree', tree, { cacheable: true })
  const next = readInspection('work', 'work/commits', commits)
  const other = readInspection('other', 'other/tree', () => 'independent')

  expect(await other).toBe('independent')
  expect(inspectionPending('work')).toBe(true)
  expect(tree).toHaveBeenCalledTimes(1)
  expect(commits).not.toHaveBeenCalled()
  const firstCancelled = expect(first).rejects.toHaveProperty('name', 'AbortError')
  controller.abort()
  await firstCancelled
  finish(['first'])
  expect(await duplicate).toEqual(['first'])
  expect(await next).toEqual(['second'])
  expect(inspectionPending('work')).toBe(false)
  expect(await readInspection('work', 'work/tree', tree, { cacheable: true })).toEqual(['first'])
  expect(tree).toHaveBeenCalledTimes(1)
})

it('keeps a stale copy after sync and discards cached and pending data on profile changes', async () => {
  const request = vi.fn().mockResolvedValueOnce(['old']).mockResolvedValueOnce(['new'])
  const readTree = () => readInspection('work', 'work/tree', request, { cacheable: true })
  expect(await readTree()).toEqual(['old'])
  invalidateInspections('work')
  expect(cachedInspection('work/tree')).toMatchObject({ value: ['old'], fresh: false })
  expect(await readTree()).toEqual(['new'])
  expect(cachedInspection('work/tree')).toMatchObject({ value: ['new'], fresh: true })

  const delayed = vi.fn()
  const read = readInspection('work', 'work/log', delayed, { cacheable: true })
  invalidateInspections('work', { discard: true })
  await expect(read).rejects.toHaveProperty('name', 'AbortError')
  expect(delayed).not.toHaveBeenCalled()
  expect(cachedInspection('work/tree')).toBeNull()
})

it('cancelling an already-started read immediately unblocks high-priority preview reads', async () => {
  const startedSignals = []
  let resolveSlow
  const slowController = new AbortController()
  const slow = readInspection('work', 'work/commits', (signal) => {
    startedSignals.push(signal)
    return new Promise((_, reject) => {
      resolveSlow = reject
      signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })
    })
  }, { signal: slowController.signal, cacheable: true })

  // Flush microtask so `slow` is genuinely in-flight before aborting and queueing preview.
  await Promise.resolve()
  expect(startedSignals).toHaveLength(1)

  const normalQueued = vi.fn().mockResolvedValue('normal')
  const previewQueued = vi.fn().mockResolvedValue('preview-bytes')
  const normalPromise = readInspection('work', 'work/summary', normalQueued, { priority: 'normal' })
  const previewPromise = readInspection('work', 'work/preview#0', previewQueued, { priority: 'high' })

  expect(previewQueued).not.toHaveBeenCalled()

  slowController.abort()
  await expect(slow).rejects.toHaveProperty('name', 'AbortError')
  expect(startedSignals[0].aborted).toBe(true)

  // High-priority preview runs immediately without waiting for slow promise settlement or normalQueued.
  expect(await previewPromise).toBe('preview-bytes')
  expect(previewQueued).toHaveBeenCalledTimes(1)
  expect(await normalPromise).toBe('normal')
  expect(typeof resolveSlow).toBe('function')
})

it('preserves immutable commit caches across sync invalidation until history-rewriting invalidation', async () => {
  const headReq = vi.fn().mockResolvedValueOnce('head-1').mockResolvedValueOnce('head-2')
  const immutableReq = vi.fn().mockResolvedValueOnce('commit-tree-1').mockResolvedValueOnce('commit-tree-2')

  expect(await readInspection('work', 'work/tree', headReq, { cacheable: true, tier: 'head' })).toBe('head-1')
  expect(await readInspection('work', 'work/tree?commit=abc', immutableReq, { cacheable: true, tier: 'immutable' })).toBe('commit-tree-1')

  invalidateInspections('work')
  expect(cachedInspection('work/tree')).toMatchObject({ fresh: false })
  expect(cachedInspection('work/tree?commit=abc')).toMatchObject({ fresh: true })

  expect(await readInspection('work', 'work/tree', headReq, { cacheable: true, tier: 'head' })).toBe('head-2')
  expect(await readInspection('work', 'work/tree?commit=abc', immutableReq, { cacheable: true, tier: 'immutable' })).toBe('commit-tree-1')
  expect(immutableReq).toHaveBeenCalledTimes(1)

  invalidateInspections('work', { includeImmutable: true })
  expect(cachedInspection('work/tree?commit=abc')).toMatchObject({ fresh: false })
  expect(await readInspection('work', 'work/tree?commit=abc', immutableReq, { cacheable: true, tier: 'immutable' })).toBe('commit-tree-2')
  expect(immutableReq).toHaveBeenCalledTimes(2)
})
