import _ from 'lodash'
import { db } from '../lib/db.js'

export function listProducts (req, res) {
  const rows = db.prepare('SELECT id, name, description, price FROM products ORDER BY name').all()
  res.json(_.map(rows, (p) => ({ ...p, price: _.round(p.price, 2) })))
}

export function searchProducts (req, res, next) {
  const q = req.query.q || ''
  try {
    const rows = db.prepare(`SELECT id, name, description, price FROM products WHERE name LIKE '%${q}%' ORDER BY name`).all()
    res.json(rows)
  } catch (err) {
    next(err)
  }
}
