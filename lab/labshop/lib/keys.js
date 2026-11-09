import { generateKeyPairSync } from 'node:crypto'

// Signing keys for session tokens: taken from the environment (secret store), or generated at
// start-up when none is configured (sessions then end when the server restarts).
// No key material is ever stored in the source code.
function loadKeys () {
  if (process.env.JWT_PRIVATE_KEY && process.env.JWT_PUBLIC_KEY) {
    return { privateKey: process.env.JWT_PRIVATE_KEY, publicKey: process.env.JWT_PUBLIC_KEY }
  }
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  })
}

const keys = loadKeys()
export const PRIVATE_KEY = keys.privateKey
export const PUBLIC_KEY = keys.publicKey
