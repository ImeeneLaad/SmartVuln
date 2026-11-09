// Only known partner sites can be reached; the visitor chooses a key, never a URL.
const PARTNERS = new Map([
  ['example', 'https://example.org']
])

export function go (req, res) {
  const target = PARTNERS.get(String(req.query.to || ''))
  res.redirect(target || '/')
}
