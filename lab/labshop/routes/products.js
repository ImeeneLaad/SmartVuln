import _ from 'lodash'
import { db } from '../lib/db.js'

export function listProducts (req, res) {
  const rows = db.prepare('SELECT id, name, description, price FROM products ORDER BY name').all()
  res.json(_.map(rows, (p) => ({ ...p, price: _.round(p.price, 2) })))
}

export function searchProducts (req, res, next) {
  const q = String(req.query.q || '')
  try {
    // The search text is passed as a bound parameter (?) - the database treats it as data, never as SQL.
    const rows = db.prepare('SELECT id, name, description, price FROM products WHERE name LIKE ? ORDER BY name').all(`%${q}%`)
    res.json(rows)
  } catch (err) {
    next(err)
  }
}
