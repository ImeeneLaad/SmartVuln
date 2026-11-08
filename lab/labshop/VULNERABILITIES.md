# LabShop — vulnerabilities and fixes

LabShop contains eleven deliberate weaknesses. This guide explains each one: where it
is, what an attacker can do, which scanner found it, and how to fix it. Try each fix
yourself first; a reference solution is folded under each section.

**"Detected by"** records what really happened in *Scan #1 — Before fixes* (Semgrep 1.183,
ZAP 2.17, Trivy, November 2026). Scanner versions and vulnerability databases change, so
your numbers may differ slightly.

| # | Vulnerability | File | Detected by |
|---|---|---|---|
| 1 | SQL injection | `routes/products.js` | Semgrep (custom rule) + ZAP — correlated |
| 2 | Reflected XSS | `routes/search.js` | Semgrep · *missed by ZAP* |
| 3 | Path traversal | `routes/files.js` | Semgrep + ZAP — correlated |
| 4 | Open redirect | `routes/redirect.js` | ZAP · *missed by Semgrep* |
| 5 | OS command injection | `routes/tools.js` | ZAP · *missed by Semgrep* |
| 6 | Hard-coded private key | `lib/keys.js` | Semgrep (custom rule) + Trivy — correlated |
| 7 | Unsalted MD5 password hashes | `lib/db.js` | Semgrep (custom rule) |
| 8 | Session cookie without flags | `routes/auth.js` | ZAP |
| 9 | Missing security headers, `X-Powered-By`, stack traces | `server.js` | ZAP (headers) · *stack traces not reported* |
| 10 | Vulnerable dependencies | `package.json` / `package-lock.json` | Trivy |
| 11 | Container image (base OS, npm, no health check) | `Dockerfile` | Trivy |

The misses are part of the lesson. Each scanner sees only part of the picture, which is
why SmartVuln combines them.

> **Before you start**, keep a copy of the vulnerable version so you can repeat the lab:
> `Copy-Item -Recurse lab\labshop lab\labshop-original` (PowerShell) or `cp -r lab/labshop lab/labshop-original`.

---

## 1. SQL injection — `routes/products.js`

The search term is pasted into the SQL text:

```js
db.prepare(`SELECT ... FROM products WHERE name LIKE '%${q}%' ORDER BY name`).all()
```

`q=zz' UNION SELECT id, email, password, role FROM users--` returns every user's email and
password hash. A single quote triggers a database error that is shown to the visitor.

**Fix:** never build SQL from strings. Pass the value as a bound parameter (`?`).

<details><summary>Reference solution</summary>

```js
const q = String(req.query.q || '')
const rows = db.prepare('SELECT id, name, description, price FROM products WHERE name LIKE ? ORDER BY name')
  .all(`%${q}%`)
```
</details>

## 2. Reflected cross-site scripting — `routes/search.js`

`/search?q=` writes the search term into the HTML page unescaped, so
`<script>…</script>` runs in the visitor's browser.

**Fix:** HTML-escape every value inserted into HTML (`& < > " '`). Escape the product
name too.

<details><summary>Reference solution</summary>

```js
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])
// ...
`<h1>Results for "${escapeHtml(q)}"</h1>`
`<li>${escapeHtml(p.name)} ...`
```
</details>

> ZAP 2.17's reflected-XSS rule did not report this page, even when run on its own
> against `/search`, although the payload is reflected verbatim (verified with curl).
> This is a real DAST false negative.
>
> After your fix Semgrep **keeps** reporting `search.js`, because it cannot know that
> `escapeHtml` makes the output safe. Verify the fix in the browser, then mark these
> findings as **False positive** in SmartVuln, with your justification (see step 6 of
> the README).

## 3. Path traversal — `routes/files.js`

`/download?file=../../etc/passwd` reads any file the server can read. The function
`path.join` happily walks up out of `files/`.

**Fix:** keep only the file name (`path.basename`), and let `sendFile` enforce a root folder.

<details><summary>Reference solution</summary>

```js
const FILES_DIR = path.join(process.cwd(), 'files')
export function download (req, res) {
  const name = path.basename(String(req.query.file || 'catalog.txt'))
  res.sendFile(name, { root: FILES_DIR }, (err) => { if (err) res.status(404).send('File not found') })
}
```
</details>

> Semgrep's generic `res.sendFile` rule still flags the fixed line. Triage it as a false
> positive once you've checked that `../` no longer works.

## 4. Open redirect — `routes/redirect.js`

`/go?url=https://evil.example` sends visitors anywhere. This makes phishing links that
look like they point to LabShop.

**Fix:** don't accept URLs from the request. Map a short key to an allow-list of
destinations, and update the "Partners" link in `public/index.html` to match.

<details><summary>Reference solution</summary>

```js
const PARTNERS = new Map([['example', 'https://example.org']])
export function go (req, res) {
  res.redirect(PARTNERS.get(String(req.query.to || '')) || '/')
}
```
and in `public/index.html`: `href="/go?to=example"`.
</details>

## 5. OS command injection — `routes/tools.js`

The host name goes into a shell command: `exec(\`getent hosts ${host}\`)`. The input
`localhost; id` runs `id` on the server.

**Fix:** don't start a shell at all. Node can resolve names itself (`dns.lookup`). Also
validate the input.

<details><summary>Reference solution</summary>

```js
import { lookup as dnsLookup } from 'node:dns/promises'
const HOSTNAME = /^[a-zA-Z0-9.-]{1,253}$/
export async function lookup (req, res) {
  const host = String(req.query.host || 'localhost')
  if (!HOSTNAME.test(host)) return res.status(400).type('text/plain').send('Invalid host name')
  try {
    const addresses = await dnsLookup(host, { all: true })
    res.type('text/plain').send(addresses.map((a) => `${a.address}  ${host}`).join('\n'))
  } catch {
    res.type('text/plain').send(`No address found for ${host}`)
  }
}
```
</details>

## 6. Hard-coded private key — `lib/keys.js`

The RSA key that signs session tokens is in the source code. Anyone who can read the
repository can forge an admin session.

**Fix:** load the key from the environment (or a secret store). If no key is
configured, generate a fresh pair when the server starts. Treat the committed key as
compromised.

<details><summary>Reference solution</summary>

```js
import { generateKeyPairSync } from 'node:crypto'
function loadKeys () {
  if (process.env.JWT_PRIVATE_KEY && process.env.JWT_PUBLIC_KEY) {
    return { privateKey: process.env.JWT_PRIVATE_KEY, publicKey: process.env.JWT_PUBLIC_KEY }
  }
  return generateKeyPairSync('rsa', { modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } })
}
const keys = loadKeys()
export const PRIVATE_KEY = keys.privateKey
export const PUBLIC_KEY = keys.publicKey
```
</details>

## 7. Unsalted MD5 password hashes — `lib/db.js`

MD5 is fast and unsalted. The hashes leaked by vulnerability 1 crack in seconds.

**Fix:** use a slow, salted algorithm (Node's built-in `scrypt`). Store `salt:hash`,
and compare in constant time. Login must then look the user up by email and verify
the password.

<details><summary>Reference solution</summary>

```js
export function hashPassword (password) {
  const salt = crypto.randomBytes(16)
  return `${salt.toString('hex')}:${crypto.scryptSync(password, salt, 32).toString('hex')}`
}
export function verifyPassword (password, stored) {
  const [salt, hash] = String(stored).split(':')
  if (!salt || !hash) return false
  return crypto.timingSafeEqual(crypto.scryptSync(password, Buffer.from(salt, 'hex'), 32), Buffer.from(hash, 'hex'))
}
```
In `routes/auth.js`:
```js
const user = db.prepare('SELECT id, email, role, name, password FROM users WHERE email = ?').get(String(email))
if (!user || !verifyPassword(String(password), user.password)) { /* 401 */ }
```
Remove the `md5` helper from `lib/db.js`, and seed the users with `hashPassword(...)`.
</details>

## 8. Session cookie without flags — `routes/auth.js`

`res.cookie('session', token)` lets JavaScript read the session (no `HttpOnly`) and sends
it on cross-site requests (no `SameSite`). While you're in this file, also pin the
accepted JWT algorithm when verifying.

<details><summary>Reference solution</summary>

```js
res.cookie('session', token, { httpOnly: true, sameSite: 'strict', maxAge: 2 * 3600 * 1000 })
// ...
const claims = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] })
```
`Secure` would also be required in production; it needs HTTPS, which this lab doesn't use.
</details>

## 9. Security headers, `X-Powered-By`, stack traces — `server.js`

The app sends no Content-Security-Policy, no clickjacking or MIME-sniffing protection, and
announces `X-Powered-By: Express`. The error handler returns stack traces to the visitor.

**Fix:** add `helmet` with a strict policy, disable `x-powered-by`, return a generic error
page, and add your own 404 handler. Express's built-in 404 page would otherwise replace
helmet's policy.

<details><summary>Reference solution</summary>

```js
import helmet from 'helmet'
app.disable('x-powered-by')
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'"],
      fontSrc: ["'self'"], connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"],
      formAction: ["'self'"], frameAncestors: ["'none'"]
    }
  }
}))
// ... routes ...
app.use((req, res) => res.status(404).type('text/plain').send('Not found'))
app.use((err, req, res, next) => { console.error(err); res.status(500).type('text/plain').send('Something went wrong.') })
```
</details>

> **Trap observed while verifying:** plain `app.use(helmet())` makes ZAP report **new**
> findings ("CSP: Wildcard Directive", "style-src unsafe-inline"), because helmet's
> default policy allows `https:` sources and inline styles. Its default
> `upgrade-insecure-requests` would also break the page's CSS on plain-HTTP localhost.
> That's why the policy above is written out explicitly.

## 10. Vulnerable dependencies — `package.json`

Trivy reports known CVEs in `lodash 4.17.15`, `jsonwebtoken 8.5.1`, `express 4.17.1` and the
packages they pull in (`qs`, `path-to-regexp`, `body-parser`, `send`, `cookie`, …).

**Fix:** upgrade to versions Trivy reports as fixed, and add `helmet` (fix 9). npm runs
inside the same Node image, so nothing has to be installed on your machine:

```bash
docker run --rm -v "${PWD}/lab/labshop:/app" -w /app node:22-slim npm install --package-lock-only --no-audit --no-fund express@4 lodash@4.18.1 jsonwebtoken@9 cookie-parser@1.4.7 helmet@8
```

> **Check the fixed version, not just "the latest".** During verification, `lodash 4.17.21`
> (the classic "safe" version) still had two CVEs fixed only in 4.18.0. Each Trivy finding
> in SmartVuln shows *fixed in …*.

## 11. Container image — `Dockerfile`

Most of Trivy's findings (about 215) are not in LabShop's code at all. They're in the
Debian packages of the `node:22-slim` base image, plus npm's own bundled modules, which
the app never uses at runtime. The Dockerfile also has no `HEALTHCHECK` (Trivy misconfig
DS-0026).

**Fix (optional, but it shows the biggest drop):**
- a smaller base image;
- remove npm after installing dependencies;
- add a health check.

This requires fix 5, because the hardened image has no `getent`.

<details><summary>Reference solution</summary>

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /root/.npm
COPY . .
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD ["node", "-e", "fetch('http://localhost:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
```
</details>

---

## What to expect after all fixes

All eleven reference fixes were applied to an isolated copy of LabShop and scanned with
the same SmartVuln configuration, on a separate network and database, so your lab was
not touched.

| | Before | After |
|---|---|---|
| Findings | 330 | 7 |
| Semgrep | 8 | 4 (the false positives of fixes 2 and 3) |
| Trivy | 290 | 0 |
| OWASP ZAP | 32 | 3 |
| Compare | — | **323 resolved · 7 remaining · 0 new** |

The 7 remaining findings:
- the 4 Semgrep false positives: triage them;
- ZAP **Absence of Anti-CSRF Tokens**: real but optional. A CSRF token on the login form
  would remove it, which makes a good stretch exercise;
- two informational ZAP notices that just identify the login form and session cookie.

If you skip fix 11, expect about 240 Trivy findings to remain. They come from the base
image, not from your code.
