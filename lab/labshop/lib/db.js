import crypto from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'

// In-memory database, recreated with the same seed data on every start.
export const db = new DatabaseSync(':memory:')

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex')

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
insertUser.run('alice@labshop.test', md5('alice123'), 'customer', 'Alice')
insertUser.run('admin@labshop.test', md5('admin2024'), 'admin', 'Shop admin')

export function hashPassword (password) {
  return crypto.createHash('md5').update(password).digest('hex')
}
