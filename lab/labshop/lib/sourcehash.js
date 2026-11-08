// Hash of the code this process was started from, reported on /health so SmartVuln can
// tell whether the running container matches the source on disk.
// Must stay identical to smartvuln/sourcehash.py.
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const EXTENSIONS = ['.js', '.mjs', '.html', '.css', '.json']
const EXCLUDED_DIRS = new Set(['node_modules', '.git'])

function walk (root, dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (!EXCLUDED_DIRS.has(entry.name)) walk(root, full, out)
    } else if (EXTENSIONS.some((ext) => entry.name.endsWith(ext))) {
      out.push(path.relative(root, full).split(path.sep).join('/'))
    }
  }
  return out
}

export function sourceHash (root = process.cwd()) {
  const h = crypto.createHash('sha256')
  for (const rel of walk(root, root, []).sort()) {
    h.update(rel + '\n')
    h.update(fs.readFileSync(path.join(root, rel)))
  }
  return h.digest('hex').slice(0, 12)
}
