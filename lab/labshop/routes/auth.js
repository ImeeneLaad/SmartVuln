import jwt from 'jsonwebtoken'
import { db, hashPassword } from '../lib/db.js'
import { PRIVATE_KEY, PUBLIC_KEY } from '../lib/keys.js'

export function login (req, res) {
  const { email = '', password = '' } = req.body
  const user = db.prepare('SELECT id, email, role, name FROM users WHERE email = ? AND password = ?')
    .get(email, hashPassword(password))
  if (!user) {
    return res.status(401).send('Invalid email or password. <a href="/">Try again</a>')
  }
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '2h' })
  res.cookie('session', token)
  res.redirect('/profile')
}

export function profile (req, res) {
  const token = req.cookies.session
  if (!token) return res.status(401).send('Please <a href="/">sign in</a>.')
  try {
    const claims = jwt.verify(token, PUBLIC_KEY)
    res.json({ email: claims.email, role: claims.role })
  } catch (err) {
    res.status(401).send('Session expired. <a href="/">Sign in again</a>.')
  }
}
