const IMAGE_EXTS = new Set([
  'png', 'jpg', 'jpeg', 'jfif', 'gif', 'webp', 'bmp', 'avif', 'ico', 'cur', 'svg', 'tif', 'tiff',
])
const RASTER_THUMB_EXTS = new Set([
  'png', 'jpg', 'jpeg', 'jfif', 'webp', 'bmp', 'gif', 'ico', 'cur', 'tif', 'tiff', 'avif',
])
const VIDEO_EXTS = new Set([
  'mp4', 'webm', 'ogv', 'mov', 'm4v', 'mkv', 'avi',
])
const AUDIO_EXTS = new Set([
  'mp3', 'wav', 'flac', 'm4a', 'ogg', 'opus', 'aac',
])
const CODE_EXTS = new Set([
  'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'vue', 'svelte', 'css', 'scss', 'html', 'htm',
  'c', 'h', 'cpp', 'hpp', 'cc', 'cxx', 'rs', 'go', 'py', 'sh', 'bash', 'ps1', 'bat', 'cmd',
  'sql', 'cmake', 'java', 'kt', 'cs', 'rb', 'php', 'lua', 'swift', 'zig', 'json', 'jsonl',
  'yaml', 'yml', 'toml', 'xml', 'diff', 'patch',
])
const TEXT_EXTS = new Set([
  'txt', 'md', 'markdown', 'csv', 'tsv', 'ini', 'conf', 'cfg', 'log', 'env', 'lock',
])
const ARCHIVE_EXTS = new Set([
  'zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'zst', '7z', 'rar',
])
const DOCUMENT_EXTS = new Set([
  'doc', 'docx', 'odt', 'rtf', 'xls', 'xlsx', 'ods', 'ppt', 'pptx', 'odp',
])
const EXECUTABLE_EXTS = new Set([
  'exe', 'msi', 'dll', 'so', 'dylib', 'appimage', 'deb', 'rpm', 'bin',
])
const SPECIAL_TEXT_NAMES = new Set([
  '.kasumiignore', '.gitignore', '.gitattributes', '.dockerignore', '.editorconfig',
  'makefile', 'dockerfile', 'containerfile', 'readme', 'license',
])

function extractFileExtension(pathOrName) {
  if (!pathOrName) return ''
  const name = String(pathOrName).split('/').at(-1).toLowerCase()
  const dot = name.lastIndexOf('.')
  if (dot <= 0 || dot === name.length - 1) return ''
  return name.slice(dot + 1)
}

export function classifyFile(itemOrPath, fallbackKind = 'file') {
  const kind = typeof itemOrPath === 'object' && itemOrPath?.kind
    ? itemOrPath.kind
    : fallbackKind
  const rawPath = typeof itemOrPath === 'object' ? (itemOrPath?.path || itemOrPath?.name || '') : (itemOrPath || '')

  if (!rawPath) {
    return { category: 'binary', ext: '', previewKind: 'none', isThumbnailable: false, isVideo: false }
  }
  if (kind === 'directory') {
    return { category: 'directory', ext: '', previewKind: 'none', isThumbnailable: false, isVideo: false }
  }

  const name = String(rawPath).split('/').at(-1).toLowerCase()
  const ext = extractFileExtension(name)
  const isThumbnailable = RASTER_THUMB_EXTS.has(ext) || VIDEO_EXTS.has(ext)

  if (IMAGE_EXTS.has(ext)) {
    const webImage = ['png', 'jpg', 'jpeg', 'jfif', 'gif', 'webp', 'bmp', 'avif', 'ico', 'svg'].includes(ext)
    return { category: 'image', ext, previewKind: webImage ? 'image' : 'binary', isThumbnailable, isVideo: false }
  }
  if (VIDEO_EXTS.has(ext)) {
    const webVideo = ['mp4', 'webm', 'ogv', 'mov', 'm4v'].includes(ext)
    return { category: 'video', ext, previewKind: webVideo ? 'video' : 'binary', isThumbnailable, isVideo: true }
  }
  if (AUDIO_EXTS.has(ext)) {
    const webAudio = ['mp3', 'wav', 'flac', 'm4a', 'ogg', 'opus'].includes(ext)
    return { category: 'audio', ext, previewKind: webAudio ? 'audio' : 'binary', isThumbnailable: false, isVideo: false }
  }
  if (ext === 'pdf') {
    return { category: 'pdf', ext, previewKind: 'pdf', isThumbnailable: false, isVideo: false }
  }
  if (CODE_EXTS.has(ext)) {
    return { category: 'code', ext, previewKind: 'text', isThumbnailable: false, isVideo: false }
  }
  if (TEXT_EXTS.has(ext) || SPECIAL_TEXT_NAMES.has(name)) {
    return { category: 'text', ext, previewKind: 'text', isThumbnailable: false, isVideo: false }
  }
  if (ARCHIVE_EXTS.has(ext)) {
    return { category: 'archive', ext, previewKind: 'binary', isThumbnailable: false, isVideo: false }
  }
  if (DOCUMENT_EXTS.has(ext)) {
    return { category: 'document', ext, previewKind: 'binary', isThumbnailable: false, isVideo: false }
  }
  if (EXECUTABLE_EXTS.has(ext)) {
    return { category: 'executable', ext, previewKind: 'binary', isThumbnailable: false, isVideo: false }
  }
  return { category: 'binary', ext, previewKind: 'binary', isThumbnailable: false, isVideo: false }
}

export function formatFileTypeLabel(item, t) {
  if (item?.kind === 'directory') return t('files.kind.directory')
  const ext = extractFileExtension(item?.name || item?.path || '')
  return ext ? ext.toUpperCase() : t('files.kind.file')
}
