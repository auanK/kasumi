/**
 * Lightweight line-based diff (LCS with safe cap for large files).
 */

const MAX_DIFF_LINES = 2500

export function computeLineDiff(leftText, rightText) {
  const left = leftText === null || leftText === undefined ? [] : String(leftText).split(/\r?\n/)
  const right = rightText === null || rightText === undefined ? [] : String(rightText).split(/\r?\n/)

  if (left.length > MAX_DIFF_LINES || right.length > MAX_DIFF_LINES) {
    return {
      truncated: true,
      rows: [
        ...left.slice(0, 500).map((text, idx) => ({ type: 'del', leftLine: idx + 1, rightLine: null, text })),
        ...right.slice(0, 500).map((text, idx) => ({ type: 'add', leftLine: null, rightLine: idx + 1, text })),
      ],
    }
  }

  const m = left.length
  const n = right.length
  const dp = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1))

  for (let i = m - 1; i >= 0; i -= 1) {
    for (let j = n - 1; j >= 0; j -= 1) {
      dp[i][j] =
        left[i] === right[j]
          ? dp[i + 1][j + 1] + 1
          : dp[i + 1][j] >= dp[i][j + 1]
            ? dp[i + 1][j]
            : dp[i][j + 1]
    }
  }

  const rows = []
  let i = 0
  let j = 0
  while (i < m && j < n) {
    if (left[i] === right[j]) {
      rows.push({ type: 'same', leftLine: i + 1, rightLine: j + 1, text: left[i] })
      i += 1
      j += 1
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rows.push({ type: 'del', leftLine: i + 1, rightLine: null, text: left[i] })
      i += 1
    } else {
      rows.push({ type: 'add', leftLine: null, rightLine: j + 1, text: right[j] })
      j += 1
    }
  }
  while (i < m) {
    rows.push({ type: 'del', leftLine: i + 1, rightLine: null, text: left[i] })
    i += 1
  }
  while (j < n) {
    rows.push({ type: 'add', leftLine: null, rightLine: j + 1, text: right[j] })
    j += 1
  }

  return { truncated: false, rows }
}
