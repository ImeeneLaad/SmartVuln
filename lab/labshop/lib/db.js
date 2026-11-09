import crypto from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'

// In-memory database, recreated with the same seed data on every start.
export const db = new DatabaseSync(':memory:')

// Passwords are stored as "salt:hash" using scrypt: slow on purpose and salted per user.
export function hashPassword (password) {
  const salt = crypto.randomBytes(16)
  const hash = crypto.scryptSync(password, salt, 32)
  return `${salt.toString('hex')}:${hash.toString('hex')}`
}

export function verifyPassword (password, stored) {
  const [salt, hash] = String(stored).split(':')
  if (!salt || !hash) return false
  const candidate = crypto.scryptSync(password, Buffer.from(salt, 'hex'), 32)
  return crypto.timingSafeEqual(candidate, Buffer.from(hash, 'hex'))  // constant-time comparison
}

db.exec(`
  CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT, price REAL);
  CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, role TEXT, name TEXT);
`)

const products = [
  ['Desk lamp', 'Adjustable LED desk lamp', 24.9],
  ['Notebook', 'A5 dotted notebook, 160 pages', 6.5],
  ['Mechanical keyboard', 'Tenkeyless, brown switches', 79.0],
  ['USB-C cable', '2 m braided cable', 9.9],
  ['Monitor stand', 'Bamboo monitor riser', 34.0],
  ['Coffee mug', 'Ceramic mug, 350 ml', 8.0]
]
const insertProduct = db.prepare('INSERT INTO products (name, description, price) VALUES (?, ?, ?)')
for (const p of products) insertProduct.run(...p)

const insertUser = db.prepare('INSERT INTO users (email, password, role, name) VALUES (?, ?, ?, ?)')
insertUser.run('alice@labshop.test', hashPassword('alice123'), 'customer', 'Alice')
insertUser.run('admin@labshop.test', hashPassword('admin2024'), 'admin', 'Shop admin')
