import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api/remote.js', () => ({
  buildLocalDownloadUrl: (profile, path) => `/v1/local/${encodeURIComponent(profile)}/download?path=${encodeURIComponent(path)}`,
  buildLocalThumbnailUrl: (profile, path, size = 160) =>
    `/v1/local/${encodeURIComponent(profile)}/thumbnail?path=${encodeURIComponent(path)}&size=${size}`,
  buildRemoteDownloadUrl: (profile, { path, commit }) =>
    `/v1/remote/${encodeURIComponent(profile)}/download?path=${encodeURIComponent(path)}&commit=${encodeURIComponent(commit || '')}`,
  buildRemoteThumbnailUrl: (profile, { path, hash, commit, size = 160, rev } = {}) =>
    hash
      ? `/v1/remote/${encodeURIComponent(profile)}/thumbnail?path=${encodeURIComponent(path)}&hash=${encodeURIComponent(hash)}${commit ? `&commit=${encodeURIComponent(commit)}` : ''}&size=${size}${rev ? `&rev=${encodeURIComponent(rev)}` : ''}`
      : '',
  fetchRemoteFileLog: vi.fn().mockResolvedValue({ entries: [] }),
  readFileChunk: vi.fn().mockResolvedValue({ bytes: new TextEncoder().encode('hello'), done: true }),
}))

import FileExplorerList from '../workspace/files/FileExplorerList.vue'
import FilePreviewPane from '../workspace/files/FilePreviewPane.vue'

describe('FileExplorerList semantic icons & thumbnails', () => {
  afterEach(() => vi.clearAllMocks())

  const hash = 'a'.repeat(64)
  const items = [
    { path: 'docs', name: 'docs', kind: 'directory' },
    { path: 'pic.png', name: 'pic.png', kind: 'file', size: 1200, logical_hash: hash },
    { path: 'clip.mp4', name: 'clip.mp4', kind: 'file', size: 4200, logical_hash: hash },
    { path: 'song.mp3', name: 'song.mp3', kind: 'file', size: 3200 },
    { path: 'spec.pdf', name: 'spec.pdf', kind: 'file', size: 2200 },
    { path: 'app.ts', name: 'app.ts', kind: 'file', size: 300 },
    { path: 'bundle.zip', name: 'bundle.zip', kind: 'file', size: 900 },
    { path: 'notes.txt', name: 'notes.txt', kind: 'file', size: 100 },
  ]

  it('renders distinct file-type categories and extensions in details view', () => {
    const wrapper = mount(FileExplorerList, {
      props: { items, view: 'details', profile: 'demo', local: true },
    })
    const categories = wrapper.findAll('[data-category]').map((el) => el.attributes('data-category'))
    expect(categories).toEqual(['directory', 'image', 'video', 'audio', 'pdf', 'code', 'archive', 'text'])
    expect(wrapper.text()).toContain('PNG')
    expect(wrapper.text()).toContain('MP4')
    expect(wrapper.text()).toContain('PDF')
    wrapper.unmount()
  })

  it('renders lazy local and hash-matched remote thumbnails including mp4 with fallback on error', async () => {
    const localIcons = mount(FileExplorerList, {
      props: { items, view: 'icons', profile: 'demo', local: true },
    })
    const thumbs = localIcons.findAll('img.k-explorer-thumb')
    expect(thumbs.map((el) => el.attributes('src'))).toEqual([
      '/v1/local/demo/thumbnail?path=pic.png&size=160',
      '/v1/local/demo/thumbnail?path=clip.mp4&size=160',
    ])
    expect(localIcons.find('.k-explorer-video-badge').exists()).toBe(true)

    await thumbs[0].trigger('error')
    expect(localIcons.findAll('img.k-explorer-thumb').length).toBe(1)
    expect(localIcons.find('[data-category="image"]').exists()).toBe(true)
    const iconSlots = localIcons.findAll('.k-explorer-icon-slot')
    expect(iconSlots.length).toBeGreaterThan(0)
    expect(localIcons.find('.k-explorer-icon-slot [data-category="directory"]').classes()).toContain('k-ftype-icon--xl')
    expect(localIcons.find('.k-explorer-thumb-frame [data-category="directory"]').exists()).toBe(false)
    localIcons.unmount()

    const vaultIcons = mount(FileExplorerList, {
      props: { items, view: 'icons', profile: 'demo', local: false },
    })
    const remoteThumbs = vaultIcons.findAll('img.k-explorer-thumb')
    expect(remoteThumbs.map((el) => el.attributes('src'))).toEqual([
      `/v1/remote/demo/thumbnail?path=pic.png&hash=${hash}&size=160`,
      `/v1/remote/demo/thumbnail?path=clip.mp4&hash=${hash}&size=160`,
    ])
    vaultIcons.unmount()
  })

  it('throttles unseen remote thumbnails to two concurrent requests and updates on preview save', async () => {
    const h1 = '1'.repeat(64)
    const h2 = '2'.repeat(64)
    const h3 = '3'.repeat(64)
    const h4 = '4'.repeat(64)
    const many = [
      { path: 'a.png', name: 'a.png', kind: 'file', size: 100, logical_hash: h1 },
      { path: 'b.png', name: 'b.png', kind: 'file', size: 100, logical_hash: h2 },
      { path: 'c.png', name: 'c.png', kind: 'file', size: 100, logical_hash: h3 },
      { path: 'clip.mp4', name: 'clip.mp4', kind: 'file', size: 4200, logical_hash: h4 },
    ]
    const wrapper = mount(FileExplorerList, {
      props: { items: many, view: 'icons', profile: 'demo', local: false, commit: 'deadbeef01' },
    })

    // Only 2 unseen remote thumbnails mount concurrently.
    let imgs = wrapper.findAll('img.k-explorer-thumb')
    expect(imgs.length).toBe(2)
    expect(imgs[0].attributes('src')).toBe(
      `/v1/remote/demo/thumbnail?path=a.png&hash=${h1}&commit=deadbeef01&size=160`,
    )

    // Settling the first opens the queue slot for the 3rd item.
    await imgs[0].trigger('load')
    imgs = wrapper.findAll('img.k-explorer-thumb')
    expect(imgs.length).toBe(3)
    expect(imgs[2].attributes('src')).toBe(
      `/v1/remote/demo/thumbnail?path=c.png&hash=${h3}&commit=deadbeef01&size=160`,
    )

    // Failing the 3rd advances the queue to the 4th item.
    await imgs[2].trigger('error')
    imgs = wrapper.findAll('img.k-explorer-thumb')
    expect(imgs.map((el) => el.attributes('src'))).toEqual([
      `/v1/remote/demo/thumbnail?path=a.png&hash=${h1}&commit=deadbeef01&size=160`,
      `/v1/remote/demo/thumbnail?path=b.png&hash=${h2}&commit=deadbeef01&size=160`,
      `/v1/remote/demo/thumbnail?path=clip.mp4&hash=${h4}&commit=deadbeef01&size=160`,
    ])

    // Bumping thumbRevisions for h3 retries its thumbnail with rev=1.
    await wrapper.setProps({ thumbRevisions: { [h3]: 1 } })
    imgs = wrapper.findAll('img.k-explorer-thumb')
    expect(imgs.some((el) => el.attributes('src') === `/v1/remote/demo/thumbnail?path=c.png&hash=${h3}&commit=deadbeef01&size=160&rev=1`)).toBe(true)

    // Saved dataUrl (e.g. captured video frame) renders directly with video badge.
    await wrapper.setProps({ savedThumbs: { [h4]: 'data:image/jpeg;base64,ZmFrZQ==' } })
    imgs = wrapper.findAll('img.k-explorer-thumb')
    expect(imgs.some((el) => el.attributes('src') === 'data:image/jpeg;base64,ZmFrZQ==')).toBe(true)
    wrapper.unmount()
  })
})

describe('FilePreviewPane fallback, video poster & RAM optimization', () => {
  beforeEach(() => {
    vi.spyOn(HTMLMediaElement.prototype, 'pause').mockImplementation(() => {})
    vi.spyOn(HTMLMediaElement.prototype, 'load').mockImplementation(() => {})
  })
  afterEach(() => {
    vi.restoreAllMocks()
    vi.clearAllMocks()
  })

  it('falls back from failed scaled preview to original download URL before showing error', async () => {
    const wrapper = mount(FilePreviewPane, {
      props: {
        profile: 'demo',
        local: true,
        path: 'big.png',
        entry: { path: 'big.png', size: 2 * 1024 * 1024 },
      },
    })
    await flushPromises()

    const thumbImg = wrapper.find('img.k-preview-media')
    expect(thumbImg.attributes('src')).toBe('/v1/local/demo/thumbnail?path=big.png&size=1280')
    expect(wrapper.find('a[download]').attributes('href')).toBe('/v1/local/demo/download?path=big.png')

    // First error on thumbnail falls back to original downloadUrl
    await thumbImg.trigger('error')
    await flushPromises()
    const origImg = wrapper.find('img.k-preview-media')
    expect(origImg.exists()).toBe(true)
    expect(origImg.attributes('src')).toBe('/v1/local/demo/download?path=big.png')
    expect(wrapper.find('.k-alert--error').exists()).toBe(false)

    // Second error (on downloadUrl itself) surfaces preview error with retry button
    await origImg.trigger('error')
    expect(wrapper.find('img.k-preview-media').exists()).toBe(false)
    expect(wrapper.find('.k-alert--error').exists()).toBe(true)
    const retryBtn = wrapper.findAll('.k-alert--error button').find((b) => b.text() === 'Try again')
    expect(retryBtn).toBeTruthy()
    await retryBtn.trigger('click')
    expect(wrapper.find('img.k-preview-media').attributes('src')).toBe('/v1/local/demo/thumbnail?path=big.png&size=1280')
    wrapper.unmount()
  })

  it('uses hash-matched remote thumbnail for vaulted images >512 KiB and falls back to historical download', async () => {
    const hash = 'a'.repeat(64)
    const wrapper = mount(FilePreviewPane, {
      props: {
        profile: 'demo',
        local: false,
        path: 'old.png',
        commit: 'deadbeef01',
        entry: { path: 'old.png', size: 2 * 1024 * 1024, logical_hash: hash },
      },
    })
    await flushPromises()

    const thumbImg = wrapper.find('img.k-preview-media')
    expect(thumbImg.attributes('src')).toBe(`/v1/remote/demo/thumbnail?path=old.png&hash=${hash}&commit=deadbeef01&size=1280`)
    await thumbImg.trigger('load')
    expect(wrapper.emitted('preview-ready')?.[0]?.[0]).toEqual({ path: 'old.png', hash })
    await thumbImg.trigger('error')
    await flushPromises()
    expect(wrapper.find('img.k-preview-media').attributes('src')).toBe('/v1/remote/demo/download?path=old.png&commit=deadbeef01')
    wrapper.unmount()
  })

  it('attaches poster thumbnail on video preview', async () => {
    const wrapper = mount(FilePreviewPane, {
      props: {
        profile: 'demo',
        local: true,
        path: 'clip.mp4',
        entry: { path: 'clip.mp4', size: 8_000_000 },
      },
    })
    await flushPromises()
    const video = wrapper.find('video.k-preview-media')
    expect(video.exists()).toBe(true)
    expect(video.attributes('poster')).toBe('/v1/local/demo/thumbnail?path=clip.mp4&size=640')
    wrapper.unmount()
  })

  it('captures remote video poster preview frame on loadeddata', async () => {
    const hash = 'b'.repeat(64)
    const drawImage = vi.fn()
    const origCreate = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tag, ...rest) => {
      if (tag === 'canvas') {
        return {
          width: 0,
          height: 0,
          getContext: () => ({ drawImage }),
          toDataURL: () => 'data:image/jpeg;base64,Y2FwdHVyZWQ=',
        }
      }
      return origCreate(tag, ...rest)
    })

    const wrapper = mount(FilePreviewPane, {
      props: {
        profile: 'demo',
        local: false,
        path: 'clip.mp4',
        commit: 'deadbeef01',
        entry: { path: 'clip.mp4', size: 8_000_000, logical_hash: hash },
      },
    })
    await flushPromises()
    const video = wrapper.find('video.k-preview-media')
    expect(video.attributes('poster')).toBe(`/v1/remote/demo/thumbnail?path=clip.mp4&hash=${hash}&commit=deadbeef01&size=640`)
    Object.defineProperty(video.element, 'videoWidth', { value: 320, configurable: true })
    Object.defineProperty(video.element, 'videoHeight', { value: 180, configurable: true })
    await video.trigger('loadeddata')
    expect(drawImage).toHaveBeenCalledTimes(1)
    expect(wrapper.emitted('preview-ready')?.[0]?.[0]).toEqual({
      path: 'clip.mp4',
      hash,
      dataUrl: 'data:image/jpeg;base64,Y2FwdHVyZWQ=',
    })
    wrapper.unmount()
  })
})
