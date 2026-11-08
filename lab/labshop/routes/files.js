import path from 'node:path'

export function download (req, res) {
  const file = req.query.file || 'catalog.txt'
  res.sendFile(path.join(process.cwd(), 'files', file))
}
