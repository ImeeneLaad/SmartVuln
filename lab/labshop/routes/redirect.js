export function go (req, res) {
  res.redirect(req.query.url || '/')
}
