import { describe, expect, it } from 'vitest'
import { computeLineDiff } from '../utils/diff.js'
import {
  decodeHexToText,
  extractDetailDuration,
  formatBytes,
  formatDuration,
  formatDurationMs,
  formatTimestamp,
} from '../utils/format.js'

describe('format utilities', () => {
  it('formats timestamps with explicit UTC offset', () => {
    const formatted = formatTimestamp(1700000000)
    expect(formatted).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} [+-]\d{2}:\d{2}$/)
    expect(formatTimestamp(null)).toBe('—')
  })

  it('formats bytes and durations cleanly', () => {
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(2048)).toBe('2.0 KiB')
    expect(formatDuration(125)).toBe('2m 05s')
    expect(formatDurationMs(420)).toBe('420 ms')
    expect(formatDurationMs(4120)).toBe('4.1s')
    expect(formatDurationMs(134000)).toBe('2m 14s')
    expect(formatDurationMs(null)).toBe('—')
    expect(extractDetailDuration('up=0, down=0, rm=0, mv=0 (4.1 s)')).toBe('4.1s')
  })

  it('decodes hex UTF-8 strings', () => {
    expect(decodeHexToText('6b6173756d69')).toBe('kasumi')
  })
})

describe('line diff', () => {
  it('detects additions, deletions, and unchanged lines', () => {
    const res = computeLineDiff('a\nb\nc', 'a\nx\nc\nd')
    expect(res.truncated).toBe(false)
    expect(res.rows.map((r) => `${r.type}:${r.text}`)).toEqual([
      'same:a',
      'del:b',
      'add:x',
      'same:c',
      'add:d',
    ])
  })
})
