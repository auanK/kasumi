export function parentFolder(path) {
  const slash = path.lastIndexOf('/')
  return slash > 0 ? path.slice(0, slash) : ''
}

export function indexFileTree(entries) {
  const folders = new Map([['', { path: '', pathLower: '', name: '', nameLower: '', items: [], directories: [] }]])
  const files = new Map()

  function addFolder(path) {
    if (folders.has(path)) return folders.get(path)
    const parent = addFolder(parentFolder(path))
    const name = path.slice(path.lastIndexOf('/') + 1)
    const folder = {
      path,
      pathLower: path.toLowerCase(),
      name,
      nameLower: name.toLowerCase(),
      kind: 'directory',
      items: [],
      directories: [],
    }
    folders.set(path, folder)
    parent.items.push(folder)
    parent.directories.push(folder)
    return folder
  }

  for (const entry of entries) {
    if (!entry.path) continue
    if (entry.type === 'directory') {
      addFolder(entry.path)
    } else {
      const folder = addFolder(parentFolder(entry.path))
      const name = entry.path.slice(entry.path.lastIndexOf('/') + 1)
      const file = {
        ...entry,
        name,
        nameLower: name.toLowerCase(),
        pathLower: entry.path.toLowerCase(),
        kind: 'file',
      }
      folder.items.push(file)
      files.set(file.path, file)
    }
  }
  const byName = (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true })
  for (const { items, directories } of folders.values()) {
    directories.sort(byName)
    items.sort((a, b) => a.kind.localeCompare(b.kind) || byName(a, b))
  }
  return { folders, files }
}
