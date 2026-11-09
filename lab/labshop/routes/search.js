import { db } from '../lib/db.js'

// Turns characters that have a meaning in HTML into harmless text codes.
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])

export function searchPage (req, res) {
  const q = String(req.query.q || '')
  const rows = db.prepare('SELECT name, price FROM products WHERE name LIKE ? ORDER BY name').all(`%${q}%`)
  const items = rows.map((p) => `<li>${escapeHtml(p.name)} <span>${p.price.toFixed(2)} €</span></li>`).join('')
  res.send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Search · LabShop</title>
<link rel="stylesheet" href="/style.css"></head>
<body><header><a href="/">LabShop</a></header>
<main><h1>Results for "${escapeHtml(q)}"</h1>
<ul class="results">${items || '<li>No products found.</li>'}</ul>
<p><a href="/">Back to the shop</a></p></main></body></html>`)
}
