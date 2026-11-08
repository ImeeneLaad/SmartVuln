import { exec } from 'node:child_process'

// Store-staff helper: resolve a supplier host name.
export function lookup (req, res) {
  const host = req.query.host || 'localhost'
  exec(`getent hosts ${host}`, (err, stdout, stderr) => {
    res.type('text/plain').send(stdout || stderr || `No address found for ${host}`)
  })
}
