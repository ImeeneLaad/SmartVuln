import jwt from 'jsonwebtoken'
import { db, verifyPassword } from '../lib/db.js'
import { PRIVATE_KEY, PUBLIC_KEY } from '../lib/keys.js'

export function login (req, res) {
  const { email = '', password = '' } = req.body
  // Find the user by email, then verify the password against its salted scrypt hash.
  const user = db.prepare('SELECT id, email, role, name, password FROM users WHERE email = ?').get(String(email))
  if (!user || !verifyPassword(String(password), user.password)) {
    return res.status(401).send('Invalid email or password. <a href="/">Try again</a>')
  }
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '2h' })
  // HttpOnly: unreadable by JavaScript; SameSite=Strict: not sent on cross-site requests.
  res.cookie('session', token, { httpOnly: true, sameSite: 'strict', maxAge: 2 * 3600 * 1000 })
  res.redirect('/profile')
}

export function profile (req, res) {
  const token = req.cookies.session
  if (!token) return res.status(401).send('Please <a href="/">sign in</a>.')
  try {
    // Accept only tokens signed with the algorithm we use (no algorithm confusion).
    const claims = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] })
    res.json({ email: claims.email, role: claims.role })
  } catch (err) {
    res.status(401).send('Session expired. <a href="/">Sign in again</a>.')
  }
}
