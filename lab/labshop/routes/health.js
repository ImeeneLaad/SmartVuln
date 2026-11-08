import { sourceHash } from '../lib/sourcehash.js'

const startedAt = new Date().toISOString()
const hash = sourceHash()

export function health (req, res) {
  res.json({ status: 'ok', app: 'labshop', started_at: startedAt, source_hash: hash })
}
