// Test cases for smartvuln-weak-password-hash
// ruleid: smartvuln-weak-password-hash
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
// ruleid: smartvuln-weak-password-hash
const h1 = crypto.createHash('sha1').update(pw).digest('hex')
// ok: smartvuln-weak-password-hash
const h2 = crypto.createHash('sha256').update(fileContent).digest('hex')
