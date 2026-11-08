# SmartVuln custom detection

Five original Semgrep rules for the TypeScript/Express code of the target, and one
Python-based analysis (the Express route mapper) used for SAST↔DAST correlation.

Each rule `X.yaml` has a test file `X.ts` next to it, in Semgrep's test format
(`// ruleid:` = must match on the next line, `// ok:` = must not match). Run all tests with:

```bash
docker run --rm -v "$PWD/custom_rules/semgrep:/rules:ro" -w /rules semgrep/semgrep semgrep --test --metrics=off /rules
```

Result in this workspace: `5/5: ✓ All tests passed` (Semgrep 1.183.0).

Each rule sets `smartvuln_category` in its metadata. The normalizer uses that
vulnerability class directly instead of guessing it from the CWE, so a custom rule
always lands in the intended correlation bucket.

## 1. `smartvuln-raw-sql-interpolation` (CWE-89)

*(Previously `smartvuln-sequelize-raw-query-interpolation`, which covered Sequelize only.)*

**Purpose.** Flags SQL built by a template literal with `${...}` or by string
concatenation, when it is passed to a query method. The method must be `query`,
`prepare`, `exec`, `all`, `get`, `run`, `raw` or `execute`, on a receiver named like a
database handle (`*sequelize`, `*db`, `*database`, `*sql`, `*knex`, `*conn`, `*pool`).
That covers Sequelize (Juice Shop), `node:sqlite` / better-sqlite3 (LabShop) and the
usual pg/mysql pools.

**Why custom.** Registry rules (e.g. `express-sequelize-injection`) need a taint path
from `req`, and none covers `node:sqlite`. This rule is purely structural. It also
catches queries built from variables that a taint engine loses track of. It does not flag
the safe forms: bound parameters (`?`, `:name`), `replacements`, `bind`.

**Limitations.**
- A query string built in a variable first (`const q = \`...${x}\`; db.prepare(q)`) is missed.
- Interpolating a trusted constant is still flagged, so a human must review the match.
- It depends on how the receiver is named: a database handle called `repo` is not matched.

**Test case.** `smartvuln-raw-sql-interpolation.ts`: four vulnerable calls (Sequelize
template, Sequelize concatenation, `db.prepare` template, `pool.query` concatenation), plus
four safe ones (replacements, bound `?` parameter, constant SQL, a non-database `.query`).

**On Juice Shop v20.3.0.** Matches `routes/login.ts:34` and `routes/search.ts:23`
(ground-truth entries GT-01 and GT-02). **On LabShop**, it matches
`routes/products.js:12`, correlated with ZAP's SQL-injection alert on
`/api/products/search`.

## 2. `smartvuln-request-data-code-execution` (CWE-94, taint mode)

**Purpose.** Follows HTTP request data (`req.body/query/params/headers/cookies`, plus the
destructured `({ body }: Request) =>` handler style Juice Shop uses) into `eval`,
`new Function`, `vm.runIn*Context` or `vm.createContext`.

**Why custom.** It models the B2B order flaw, where the user value never reaches
`eval` directly: it is placed in a sandbox object that is passed to `vm.createContext`
and then evaluated by `notevil`. Registry `eval` rules don't follow that.

**Limitations.**
- Sources are syntactic. Data that comes back from the database (stored injection) is
  only caught if Semgrep's taint engine links it to `req`. On v20.3.0 it did flag
  `routes/userProfile.ts:65`, because the username lookup starts from request cookies.
- The `vm.createContext` sink can over-report when the sandbox holds request data that
  the evaluated code never touches.

**Test case.** `smartvuln-request-data-code-execution.ts`: the sandbox pattern, a direct
`eval(req.query.x)`, an `eval` of a server-generated constant (must not match, which
mirrors `routes/captcha.ts`), and `JSON.parse` of request data (must not match).

**On Juice Shop v20.3.0.** Matches `routes/b2bOrder.ts:22-23` (GT-06) and
`routes/userProfile.ts:65` (GT-07). It correctly ignores `routes/captcha.ts:22`.

## 3. `smartvuln-substring-url-allowlist` (CWE-601)

**Purpose.** Flags allow-list checks written as `url.includes(allowed)` or
`url.indexOf(allowed) !== -1`, when the variable names suggest a URL and an
allow-list. Any attacker URL that merely *contains* an allowed value passes the check.

**Why custom.** Registry open-redirect rules flag the `res.redirect(x)` sink. This rule
points at the faulty *validation*, which is where the fix belongs (`lib/insecurity.ts`).

**Limitations.**
- It relies on variable names (`url|uri|redirect|target|origin|href|host` and
  `allow|white|trusted|safe|permitted`), so it misses checks written with other names.
- `startsWith` checks are not flagged, even though they can also be bypassed in some
  URL forms.

**Test case.** `smartvuln-substring-url-allowlist.ts`: `includes` in an allow-list loop
and an `indexOf` variant, plus an exact `new URL(...).origin` lookup and an unrelated
`includes` (neither may match).

**On Juice Shop v20.3.0.** Matches `lib/insecurity.ts:136` (GT-11).

## 4. `smartvuln-hardcoded-crypto-key` (CWE-798 / CWE-321)

**Purpose.** Flags key material written into source:
- PEM private-key string literals;
- `createHmac(alg, "<literal>")`;
- `jwt.sign(payload, "<literal>")`;
- `cookieParser("<literal>")`;
- `expressJwt({ secret: "<literal>" })`.

Semgrep's constant propagation also resolves `const k = "..."` that is used later.

**Limitations.**
- It doesn't detect secrets from other APIs or other naming patterns; Trivy's secret
  scanner covers some of these.
- Secrets in test fixtures are flagged unless the path is excluded.
- A public key literal is deliberately *not* flagged.

**Test case.** `smartvuln-hardcoded-crypto-key.ts`: four positives (private key, HMAC,
cookie secret, JWT secret), and three negatives (public key, HMAC key from env,
JWT signed with a variable from a vault).

**On Juice Shop v20.3.0.** Matches:
- `lib/insecurity.ts:21`, `:54` and `:150`: the private key, plus its use in `jwt.sign`
  and `createHmac` (all GT-08);
- `lib/insecurity.ts:42` (GT-09);
- `server.ts:317` (GT-16).

The Trivy secret finding on `lib/insecurity.ts:21` is correlated with this rule by
rule R2 (same code location).

## 5. `smartvuln-weak-password-hash` (CWE-916)

**Purpose.** Flags `createHash('md5' | 'md4' | 'sha1')`.

**Limitations.**
- It can't tell whether the digest is applied to a password or to a non-security
  checksum. On v20.3.0 it also matches `scripts/package.mjs:121`, which is outside the
  ground-truth scope and is a build-script checksum, so it is a likely false positive.
  The risk engine lowers its score with the `non_production_code` factor (`scripts/`).

**Test case.** `smartvuln-weak-password-hash.ts`: MD5 and SHA-1 must match; SHA-256 must not.

**On Juice Shop v20.3.0.** Matches `lib/insecurity.ts:41` (GT-10).

## Python-based custom analysis: Express route mapper

`smartvuln/engine/routemap.py` statically parses `server.ts`:
1. It resolves the `import { x } from './routes/…'` and `import * as ns from …` bindings.
2. It maps every single-line `app.<verb>(path, …handlers)` registration to the handler's
   source file.

On v20.3.0 it extracts **108 routes**. For example, `GET /rest/products/search` maps to
`routes/search.ts`, and `/ftp(?!/quarantine)/:file` maps to `routes/fileServer.ts`.

The correlation engine (rule R3) uses this table to link a ZAP alert on an endpoint with
a Semgrep finding **of the same vulnerability class** in that endpoint's handler file.
The scoring engine uses the same table for the `reachable_http_handler` factor.

**Limitations.**
- Routers mounted from other files, multi-line registrations, dynamically built paths and
  the auto-generated finale-rest `/api/*` resources are not mapped.
- A missing route only means a correlation is missed; it never creates a wrong link.

**Tests.** `tests/test_correlation.py::test_route_map` and
`::test_sast_dast_correlation_via_route_map`, using the mini app in `tests/fixtures/mini_app`.
