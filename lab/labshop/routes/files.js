import path from 'node:path'

const FILES_DIR = path.join(process.cwd(), 'files')

export function download (req, res) {
  // Keep only the file name (drops any "../" or folder part) and let sendFile enforce the root folder.
  const name = path.basename(String(req.query.file || 'catalog.txt'))
  res.sendFile(name, { root: FILES_DIR }, (err) => {
    if (err) res.status(404).send('File not found')
  })
}
