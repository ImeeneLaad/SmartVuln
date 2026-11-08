// Test cases for smartvuln-hardcoded-crypto-key (all key material below is fake test data)
// ruleid: smartvuln-hardcoded-crypto-key
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDtestonly\r\n-----END RSA PRIVATE KEY-----'
// ruleid: smartvuln-hardcoded-crypto-key
export const hmac = (data: string) => crypto.createHmac('sha256', 'hard-coded-test-secret').update(data).digest('hex')
// ruleid: smartvuln-hardcoded-crypto-key
app.use(cookieParser('kekse'))
// ruleid: smartvuln-hardcoded-crypto-key
const t = jwt.sign({ id: 1 }, 'secret')

// ok: smartvuln-hardcoded-crypto-key
const publicKey = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCtest\n-----END PUBLIC KEY-----'
// ok: smartvuln-hardcoded-crypto-key
const h = crypto.createHmac('sha256', process.env.HMAC_KEY)
// ok: smartvuln-hardcoded-crypto-key
const t2 = jwt.sign({ id: 1 }, privateKeyFromVault, { algorithm: 'RS256' })
