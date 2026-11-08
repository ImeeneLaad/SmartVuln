// Test cases for smartvuln-substring-url-allowlist
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    // ruleid: smartvuln-substring-url-allowlist
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}

function legacy (targetUrl: string, trustedHost: string) {
  // ruleid: smartvuln-substring-url-allowlist
  return targetUrl.indexOf(trustedHost) !== -1
}

function exact (url: string) {
  // ok: smartvuln-substring-url-allowlist
  return allowlist.has(new URL(url).origin)
}

function unrelated (msg: string, nullByte: string) {
  // ok: smartvuln-substring-url-allowlist
  return msg.includes(nullByte)
}
