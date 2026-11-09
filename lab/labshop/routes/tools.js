import { lookup as dnsLookup } from 'node:dns/promises'

// Only letters, digits, dots and dashes are valid in a host name.
const HOSTNAME = /^[a-zA-Z0-9.-]{1,253}$/

// Store-staff helper: resolve a supplier host name (no shell, no child process).
export async function lookup (req, res) {
  const host = String(req.query.host || 'localhost')
  if (!HOSTNAME.test(host)) return res.status(400).type('text/plain').send('Invalid host name')
  try {
    const addresses = await dnsLookup(host, { all: true })
    res.type('text/plain').send(addresses.map((a) => `${a.address}  ${host}`).join('\n'))
  } catch {
    res.type('text/plain').send(`No address found for ${host}`)
  }
}
