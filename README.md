# SmartVuln – Intelligent Web Vulnerability Assessment Platform

SmartVuln runs three complementary scanners against OWASP Juice Shop, a deliberately
vulnerable application deployed locally:

| Approach | Tool | What is scanned |
|---|---|---|
| SAST | Semgrep (registry rules + 5 SmartVuln rules) | application source code |
| DAST | OWASP ZAP (Automation Framework) | the running application on an isolated Docker network |
| SCA | Trivy | dependencies of the deployed container image + secrets/misconfigurations in the source tree |

Its main contribution is the **Python analysis engine**:
1. It **normalizes** the three report formats into one schema.
2. It **deduplicates and correlates** findings with explicit, explainable rules. This
   includes an original Express *route mapper* that links a DAST URL to the source file
   that handles it.
3. It **prioritizes** issues with a transparent, configurable score.
4. It keeps a **triage** workflow in which only a human can confirm a finding or reject
   it as a false positive.
5. It **compares** successive scans.

Results are stored in SQLite and shown in a Flask + Chart.js dashboard. The tool exports
JSON and HTML reports, and a GitHub Actions workflow runs the whole pipeline.

> This is an academic mini-project, not a production platform. By default it only
> scans the local, isolated Juice Shop container.

---

## 1. Architecture

```
            ┌──────────────── docker network: smartvuln-net ───────────────┐
            │  juice-shop:3000  (bkimminich/juice-shop:v20.3.0, healthcheck) │
            │        ▲                                                       │
            │        │ HTTP (spider, passive, targeted active scan)          │
            │  zap container (ghcr.io/zaproxy/zaproxy:stable)                │
            └────────────────────────────────────────────────────────────────┘
 targets/juice-shop (source, git tag v20.3.0) ──► semgrep container ─┐
 bkimminich/juice-shop:v20.3.0 image ───────────► trivy image ───────┤ raw JSON reports
 targets/juice-shop ────────────────────────────► trivy fs ──────────┤ data/scans/NNNN/raw/
                                                                     ▼
 smartvuln/scanners/*   adapters: run container, timeout, capture stdout/stderr, status
 smartvuln/engine/normalize.py   → common Finding schema (smartvuln/models.py)
 smartvuln/engine/routemap.py    → endpoint ↔ handler-file table from server.ts
 smartvuln/engine/correlation.py → links R1–R4, union-find groups, primary election
 smartvuln/engine/scoring.py     → risk score + explained factors
 smartvuln/engine/triage.py      → needs_verification / likely_duplicate / manual verdicts
 smartvuln/engine/compare.py     → new / resolved / not re-tested / persistent / severity & coverage changes
 smartvuln/database/store.py     → SQLite: scans, scanner_runs, findings, triage, triage_log
 smartvuln/reports/render.py     → normalized JSON, HTML report, comparison HTML, CI summary (Markdown)
 smartvuln/app/                  → Flask dashboard (overview, explorer, details, history, compare, reports)
 smartvuln/evaluation.py         → precision/recall vs evaluation/ground_truth.json
```

### Directory layout

```
smartvuln/            Python package
  scanners/           base.py (execution & status), semgrep.py, zap.py, trivy.py
  engine/             taxonomy, normalize, routemap, correlation, scoring, triage, compare, pipeline
  database/           store.py (SQLite)
  reports/            render.py + templates/ (standalone HTML reports)
  app/                Flask dashboard: templates/, static/
  orchestrator.py     scan workflow;  cli.py  command line;  evaluation.py  ground-truth metrics
config/smartvuln.toml all settings (target, scanners, scoring weights)
custom_rules/         5 Semgrep rules + tests + README (purpose, limitations, test cases)
lab/labshop/          LabShop: deliberately vulnerable lab app + exercise guide (separate from SmartVuln)
evaluation/           ground_truth.json (17 manually verified entries + closed-world scope)
tests/                pytest suite + hand-written fixtures (labelled as such)
scripts/              fetch_target.sh, demo.sh
.github/workflows/    smartvuln.yml
docker-compose.yml    Juice Shop, LabShop (+ optional dashboard container)
```

---

## 2. Installation

Requirements: Docker (Desktop or Engine) with Compose v2, Python 3.11+ and git.
Semgrep, ZAP and Trivy are **not** installed locally: each one runs from its official
Docker image, so the same commands work on Windows, Linux and in CI.

```bash
git clone https://github.com/ImeeneLaad/SmartVuln.git smartvuln && cd smartvuln
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
bash scripts/fetch_target.sh    # clones Juice Shop v20.3.0 into targets/juice-shop
docker pull semgrep/semgrep:latest aquasec/trivy:latest ghcr.io/zaproxy/zaproxy:stable   # optional pre-pull
```

## 3. Configuration

Everything lives in `config/smartvuln.toml`. Any key can be overridden with an
environment variable named `SMARTVULN_<SECTION>_<KEY>`, for example:

| Key | Default | Meaning |
|---|---|---|
| `target.url` | `http://juice-shop:3000` | URL that ZAP scans (service name on the compose network) |
| `target.healthcheck_url` | `http://localhost:3000/rest/admin/application-version` | readiness probe used before DAST |
| `target.allowed_hosts` | `juice-shop, localhost, 127.0.0.1, …` | **safety allow-list** — any other host is refused unless `--allow-external` |
| `source.path` / `source.image` | `targets/juice-shop` / `bkimminich/juice-shop:v20.3.0` | SAST source and SCA image |
| `semgrep.configs` | `p/javascript p/typescript p/nodejs custom_rules/semgrep` | rulesets (local paths are mounted read-only) |
| `zap.profile` | `targeted` | `baseline` = spider + passive; `targeted` = + active scan limited to 9 injection/redirect/listing rules (all shipped in the stable image) |
| `zap.seed_paths`, `zap.seed_posts` | API endpoints | requests the spider can't discover in an Angular SPA |
| `*.timeout_s` | 1200–1800 | per-scanner timeout; the container is killed on timeout |
| `scoring.*` | see §6 | every weight of the risk formula |

**Several targets.** The sections above describe the default target (Juice Shop). Each
`[targets.<id>]` block adds another target by overriding only what differs: URL,
health-check URL, source folder, image, seeds and excludes. LabShop is configured this
way. Targets appear in the Scan Center and in `python -m smartvuln targets`, and
`--target <id>` selects one on the CLI. A target block can never widen
`target.allowed_hosts`.

## 4. Execution

### From the dashboard (Scan Center)

```bash
docker compose up -d juice-shop          # isolated target, bound to 127.0.0.1:3000
python -m smartvuln serve                # http://127.0.0.1:5000  →  "▶ Scan Center"
```

The Scan Center:
- shows the target, its live availability, the source checkout and the pre-flight
  checks (Docker, allow-list, scanner images);
- lets you tick Semgrep, OWASP ZAP and Trivy individually;
- starts a real scan with **Start Scan**.

Clicking Start Scan sends `POST /api/scans`. The server creates the scan record, with
one *pending* row per scanner, and runs the scanners in a background thread. The page
polls the scan's status and its incremental logs every 2 s, so you see each scanner move
from **Pending → Running → Completed / Failed**, along with the overall phase, progress
and live tool output.

Only one scan per target can run at a time; the API answers `409` otherwise. A scan
left running by a stopped server is marked *interrupted* at the next start-up. The Logs
page keeps the complete log of every scan, also saved under `data/scans/NNNN/logs/`.

API: `GET /api/targets` (pre-flight), `POST /api/scans` (`{"target", "scanners", "label"}` +
`X-CSRF-Token`), `GET /api/scans`, `GET /api/scans/<id>`, `GET /api/scans/<id>/logs?after=<id>`,
`DELETE /api/scans/<id>` (`{"confirm": <id>}` + `X-CSRF-Token`).

**Naming scans.** The *Scan name* field suggests the next number for the selected target
(for example "Scan #2 — Before fixes"). If you leave it empty, the scan is named "Scan #N".

**Deleting scans.** *History* → **Delete** opens a confirmation dialog showing the scan's
name, target, date and finding count. The button unlocks only after you type the scan
number. The deletion removes:
- the scan and, through SQLite's `ON DELETE CASCADE`, its findings, scanner runs and log lines;
- its own folder `data/scans/NNNN`, and nothing else on disk.

It keeps every other scan, and analyst verdicts, which are shared per fingerprint. If a
later scan of the same target had been compared against the deleted one, that scan's
comparison report is regenerated against its new predecessor. Running scans cannot be
deleted.

**Scanning any project (Upload / Folder).** At the top of the Scan Center, *What to scan* has three tabs:
- **Upload:** drop a `.zip` of a project, or a single source file (up to 200 MB). It is extracted
  safely into `data/projects/<id>/source/`: paths escaping the folder (zip-slip) are refused,
  symbolic links are skipped, and size and file counts are limited.
- **Folder on this PC:** paste a folder path. It is scanned in place, read-only.
- **Saved:** the built-in apps (Juice Shop, LabShop) and every project added before.

Optionally, give the **app URL** (where the app is running, local hosts only) so OWASP ZAP can
test it, and a **Docker image** for Trivy's image scan. Without a URL, Semgrep (code, generic
multi-language rulesets) and Trivy (lockfiles, secrets, misconfiguration) still run, and ZAP is
disabled with "Needs app URL". ZAP runs in a container, so `localhost` in the URL is translated
to `host.docker.internal` to reach an app running on this PC. Uploading again with the same
name replaces that project's code, so its scans can be compared before and after. API:
`POST /api/projects` (multipart: `mode`, `name`, `file` or `path`, `url`, `image`), `GET /api/projects`.

The Scan Center needs the dashboard to run **on the host** (`python -m smartvuln serve`),
because it starts the scanner containers through the local Docker CLI. The optional
dashboard container is read-only.

### From the command line

```bash
docker compose up -d juice-shop          # isolated target, bound to 127.0.0.1:3000
python -m smartvuln health               # docker / source / target readiness
python -m smartvuln scan                 # all scanners -> analysis -> SQLite -> reports
python -m smartvuln scan --scanners semgrep,trivy   # subset (e.g. without a running target)
python -m smartvuln targets              # configured targets
python -m smartvuln scan --target labshop --label "Before fixes"
python -m smartvuln list                 # scan history
python -m smartvuln compare 2            # scan #2 vs previous scan (or --baseline N)
python -m smartvuln evaluate             # precision/recall vs the ground truth
python -m smartvuln triage <fingerprint> confirmed --analyst alice --note "reproduced with ' OR 1=1--"
python -m smartvuln serve                # dashboard on http://127.0.0.1:5000
python -m smartvuln import <dir> [--demo]   # analyze existing raw reports (CI artifacts, fixtures)
python -m smartvuln reanalyze 3 4        # re-run the current engine on stored raw reports (after upgrades)
python -m smartvuln delete 5 --yes       # delete a scan (without --yes it only shows what would go)
```

`scan` exits with code 0 even when vulnerabilities are found, so reports are always
collected. `--fail-on high` turns it into a CI gate.

Each scan writes to `data/scans/NNNN/`:
- `raw/`: the untouched scanner reports, plus ZAP's own HTML report and the generated
  automation plan;
- `normalized-findings.json`;
- `report.html`;
- `summary.md`;
- `comparison.json` and `comparison-report.html`, when a previous scan exists.

The dashboard can also run as a container: `docker compose --profile dashboard up -d dashboard`.

### Demonstration fixtures vs real data

`tests/fixtures/*_sample.json` are **hand-written** test fixtures. They are only loaded
when you ask for it (`python -m smartvuln import tests/fixtures --demo`). The scan is then
stored with `is_demo = 1`, and every dashboard page and report shows a yellow
"DEMONSTRATION FIXTURES" banner. Real scans never contain fixture data.

---

## 5. Analysis engine

### 5.1 Normalized schema (`smartvuln/models.py::Finding`)

`id, fingerprint, application, scanner, scan_type, rule_id, title, category, cwe[], cve[],
severity, confidence, file_path, line_start/end, url, http_method, parameter, package_name/version,
fixed_version, target, description, remediation, evidence, references, cvss_score,
exploitability_hint, detected_at, raw` + analysis fields (`group_id, correlation_status,
correlation_reasons, related_ids, is_group_primary, risk_score, priority, risk_factors,
triage_status, triage_reason`).

The normalizer follows these rules:
- A value the scanner doesn't provide stays `null`. For example, Trivy gives no
  confidence and Semgrep OSS returns `"requires login"` instead of the code snippet;
  neither is ever replaced with a guess.
- The original record is kept in `raw`.
- Secret values are masked before they reach the database, the logs or the UI.

The `fingerprint` (scanner + rule + location) is stable across scans. It is what scan
comparison and persistent triage verdicts are keyed on.

### 5.2 Deduplication & correlation (`engine/correlation.py`)

| Rule | Links | Condition |
|---|---|---|
| R1 same-advisory | SCA ↔ SCA | same CVE/GHSA **and** same package |
| R2 same-code-location | any file-based finding (Semgrep, Trivy secret/misconfig) | same file **and** lines within ±2 **and** same vulnerability class |
| R3 endpoint-handler | DAST ↔ SAST | same class **and** the SAST file is the Express handler of the DAST URL (route mapper) |
| R4 same-endpoint | DAST ↔ DAST | same class, method, path and parameter, but a different ZAP rule |

A shared severity or CWE alone **never** links two findings. Library CVEs get their own
class (`vulnerable-dependency`), so an XSS CVE in a dependency never merges with an XSS
in application code.

Linked findings are grouped with union-find. The highest-severity / highest-confidence
member becomes the group primary; the others are marked `likely_duplicate`, but each one
keeps its own provenance and evidence. Each group is then labelled:
- `multi_scanner`, with SAST∩DAST shown separately on the dashboard;
- `same_scanner_duplicate`;
- `uncorrelated` (nothing else matched).

### 5.3 Risk scoring (`engine/scoring.py`)

```
score = clamp(0..100, base × confidence_multiplier + Σ adjustments)
base       = severity points (critical 90 / high 70 / medium 45 / low 20 / info 5),
             or CVSS v3 × 10 for SCA findings when the advisory provides it
confidence = high 1.0 / medium 0.85 / low 0.6 / not provided 0.85 (neutral, explicitly labelled "NOT evidence")
adjustments (only applied when evidence exists):
  +10 ZAP recorded an attack payload that triggered the rule
  ±5  Semgrep rule metadata likelihood HIGH / LOW
  +10 corroborated by another scanner
  +5  SAST file is an Express route handler (route mapper)
  +5  DAST finding observed on the running deployment
  −15 file in test / fixture / tooling code
priority  = P1 ≥ 80, P2 ≥ 60, P3 ≥ 35, else P4      (all values in config/smartvuln.toml)
```

Every applied term is stored as a factor with a reason, so the finding page shows why a
finding got its priority. A manual `false_positive` verdict sets the score to 0.

### 5.4 Triage (`engine/triage.py`)

Automatic triage only ever produces `needs_verification` or `likely_duplicate`.
`confirmed` and `false_positive` require an analyst name and a written justification of
at least 10 characters. Verdicts are stored per fingerprint with an audit log, so they
carry over to later scans of the same code or endpoint.

### 5.5 Scan comparison (`engine/compare.py`)

Findings are matched by fingerprint. The comparison reports new, persistent, severity
changed (up/down) and scanner coverage changed (status or count per scanner).

A finding that is missing from the current scan gets one of three labels:

| Label | When |
|---|---|
| *not re-tested* | its scanner did not complete in the current scan |
| *not observed* | ZAP only: that URL was not reported again, but **the same ZAP rule still fires on other URLs** of the site |
| *resolved* | otherwise: a SAST/SCA finding is gone, or the ZAP rule no longer fires anywhere |

*Not observed* exists because a DAST tool samples URLs: the spider's path and ZAP's
per-alert instance list change from run to run. Two consecutive scans of the
**unchanged** Juice Shop showed this. Without the rule, 5 ZAP findings were reported as
"resolved" and 4 as "new", even though nothing had been fixed. In the other direction, a
new ZAP finding whose rule already fired in the baseline is tagged as a *new location of
a known rule*.

Two more rules came out of the LabShop before/after runs:

- **Code that only moved counts as remaining.** SAST fingerprints contain the line
  number, so fixing one line shifts every warning below it. A second matching pass pairs
  leftover findings with the same scanner, rule and file in line order, and reports them
  as *remaining (moved)* instead of "resolved + new".
- **Dependency fingerprints ignore the installed version.** They are keyed on advisory +
  package + location. A CVE that still applies after an upgrade is therefore *remaining*.
  For example, lodash 4.17.15 → 4.17.21 still carries CVE-2025-13465, which is fixed only
  in 4.17.23. Only a real fix shows as *resolved*.

After an engine change like these, `python -m smartvuln reanalyze <scan ids>` rebuilds
stored scans from their preserved raw reports, so old and new scans stay comparable.

---

## 6. Custom detection

See [custom_rules/README.md](custom_rules/README.md):
- five original Semgrep rules: Sequelize raw-query interpolation, request data reaching
  code execution (taint mode), substring URL allow-lists, hard-coded key material, and
  weak password hashing;
- the Python route mapper.

Each item is documented with its purpose, its limitations and a test case.

---

## 7. Testing

```bash
python -m pytest -q tests        # 60 tests, no Docker required
```

| Area | File |
|---|---|
| normalization (Semgrep/ZAP/Trivy), masking, fingerprints, taxonomy | `tests/test_normalize.py` |
| route map, R1–R4 correlation, no merge on shared CWE/severity, provenance | `tests/test_correlation.py` |
| scoring factors, no invented exploitability, CVSS, clamping, triage rules, comparison (incl. failed scanner) | `tests/test_scoring_triage_compare.py` |
| scanner error handling: non-zero exit with report, tool errors, missing/corrupt report, timeout, partial jobs, Docker unavailable, disabled, external target refused, unhealthy target | `tests/test_scanners.py` |
| SQLite store, import, persistent triage, every dashboard route, CSRF, raw-file path traversal, evaluation metrics | `tests/test_store_app_eval.py` |

---

## 8. Evaluation methodology

`evaluation/ground_truth.json` lists **17 vulnerabilities in Juice Shop v20.3.0**. I
**verified each one manually by reading the cited code**. Each entry is based on Juice
Shop's own `vuln-code-snippet` annotations or challenge documentation, and records:
- its class and CWE;
- its source location(s);
- its HTTP endpoint, when the vulnerability is reachable over HTTP;
- a sentence explaining why it is exploitable.

`python -m smartvuln evaluate` matches findings to entries by **class + location**:
file and line within ±3 lines, or an endpoint regex plus HTTP method.

- **Recall** is computed per detector, over the entries that detector could detect in
  principle: code locations for Semgrep, secrets for Trivy's secret scanner, endpoints
  for ZAP.
- **Precision** is computed **only inside a closed-world scope**: 15 (file, class) pairs
  where every occurrence was reviewed by hand. Inside that scope, a finding that matches
  no entry is a false positive. Seven documented "known negatives" explain the expected
  ones, for example the `res.sendFile` path-traversal alerts on handlers that reject `/`.
  Outside the scope no precision is claimed. DAST precision is not computed at all,
  because there is no closed-world DAST ground truth.
- **Correlation quality:** for ground-truth entries hit by two or more scanners, the
  evaluation checks whether the engine grouped them, and whether any group wrongly
  merges two different ground-truth vulnerabilities.

The evaluation does **not** claim that every scanner detects every vulnerability. Misses
are reported as misses; GT-17 (a client-side DOM XSS) is expected to be missed by a
non-browser DAST configuration.

### Measured results (this workspace, scan of 2026-11-06)

**Setup:** Semgrep 1.183.0, ZAP 2.17.0 (targeted profile), Trivy schema 2, Juice Shop v20.3.0.

**Scan:** 223 raw findings: Semgrep 27, Trivy 169, ZAP 27. After correlation they form
190 unique issues. 4 groups are multi-scanner, 3 of them SAST∩DAST.

| Detector | Recall | Closed-world precision |
|---|---|---|
| Semgrep, all rules | 13/17 = 76% | 21/26 = 81% |
| – SmartVuln custom rules | 9/17 = 53% | 12/12 = 100% * |
| – registry rules | 9/17 = 53% | 9/14 = 64% |
| Trivy secret scanner | 1/3 = 33% | 1/1 |
| ZAP | 3/13 = 23% (SQLi login, SQLi search, open redirect) | not computed |
| All scanners combined | 13/17 = 76% | – |

- **Missed by every scanner:** the three NoSQL injections (GT-03/04/05) and the DOM XSS
  (GT-17).
- **The five registry false positives:**
  - four `express-res-sendfile` path-traversal alerts on handlers that reject `/`;
  - one directory-listing alert on the intentionally public `/.well-known`.
- **Correlation check:** all 4 ground-truth vulnerabilities found by 2+ scanners were
  grouped together:
  - login SQLi: Semgrep + ZAP;
  - search SQLi: Semgrep + ZAP;
  - open redirect: Semgrep + ZAP via the route mapper;
  - private key: Semgrep + Trivy.

  There were **0 wrong merges**.

\* **Bias warning.** The custom rules were written after reading this code base, so
their precision and recall on the same code are optimistic. The figures show that the
rules work on the code they were designed for, not how well they generalize. The ground
truth has 17 entries and the closed-world scope has 26 in-scope findings. That is far
too small for statistically meaningful rates, so treat the numbers as a reproducible
case study rather than a benchmark.

Reproduce with `python -m smartvuln scan && python -m smartvuln evaluate --out data/evaluation.json`.
Results vary with scanner and rule versions (`semgrep/semgrep:latest`, ZAP `stable`,
and Trivy's database update daily). Pin image digests in `config/smartvuln.toml` for
exact reproduction.

---

## 9. CI/CD (`.github/workflows/smartvuln.yml`)

The workflow triggers on `push`, `pull_request` and manual dispatch, with read-only
permissions and no secrets.

1. **tests** job: runs the pytest suite and `semgrep --test` on the custom rules.
2. **assessment** job:
   1. fetches the pinned Juice Shop source;
   2. starts the target with `docker compose up -d juice-shop`;
   3. waits for `smartvuln health`;
   4. runs `smartvuln scan`, where Semgrep and Trivy run in parallel and ZAP runs after
      the health check;
   5. runs `smartvuln evaluate`;
   6. appends the Markdown summary (scanner statuses, severity table, top 10 issues,
      evaluation) to the job summary;
   7. uploads raw reports, normalized reports and the SQLite database as artifacts
      (`if: always()`);
   8. tears down.

Scanner findings never fail the job: the scan step uses `continue-on-error`, and the
summary and upload steps run with `if: always()`. Scanner output tails are masked for
token-like strings before they are logged or stored.

---

## 10. Demonstration scenario: LabShop before and after fixes (≈30 min)

The main demo uses **LabShop** (`lab/labshop/`), a small deliberately vulnerable shop with
eleven weaknesses spread over code, dependencies, configuration and the container image.
The step-by-step exercise is in [lab/labshop/README.md](lab/labshop/README.md), and the
vulnerabilities and fixes are in [lab/labshop/VULNERABILITIES.md](lab/labshop/VULNERABILITIES.md).

1. `docker compose up -d --build labshop` and `python -m smartvuln serve`.
2. **Scan Center** → LabShop → all three scanners → label *Before fixes* → **Start scan**.
   Follow the live progress and log.
3. **Overview / Findings**: the SQL injection is reported by both the Semgrep custom rule
   and ZAP, linked SAST↔DAST through the route map. The hard-coded key is reported by
   Semgrep and Trivy. Show what each scanner missed: ZAP the reflected XSS, Semgrep the
   command injection.
4. Fix the code and dependencies yourself, then `docker compose up -d --build labshop`.
   The pre-flight list confirms that the running build matches the source.
5. **Scan Center** → label *After fixes* → **Start scan**.
6. Triage the Semgrep warnings that survive a correct fix as *false positive*, with a
   justification.
7. **Compare** *Before fixes* → *After fixes*: totals, resolved / remaining / new, and
   before/after charts by severity and by scanner. **Export report** saves it as HTML.

Verified with the reference fixes in an isolated sandbox (separate network, image and
database): 330 findings → 7, **323 resolved, 7 remaining, 0 new**. Trivy went 290 → 0,
ZAP 32 → 3, and Semgrep 8 → 4; those four are the false positives to triage.

**Juice Shop** remains available as a larger, realistic target, and is used by the
evaluation in §8.

## 11. Troubleshooting

| Symptom | Fix |
|---|---|
| `docker daemon not reachable` | start Docker Desktop / `systemctl start docker` |
| ZAP `skipped: target health check failed` | `docker compose ps` — wait for `healthy`; check `target.healthcheck_url` is reachable **from the host** (port 3000 published on 127.0.0.1) |
| ZAP `skipped: Refusing to scan '<host>'` | intended safety guard; add the host to `target.allowed_hosts` or pass `--allow-external` for an authorized target |
| ZAP container cannot resolve `juice-shop` | the network must be named `smartvuln-net` (`docker network ls`); start the target with this compose file |
| Semgrep `skipped: source directory … not found` | `bash scripts/fetch_target.sh` |
| Semgrep slow / timeout | raise `semgrep.timeout_s`, add `exclude` patterns, or drop rulesets |
| First Trivy run is slow | it downloads its vulnerability DB into the `smartvuln-trivy-cache` volume; later runs reuse it |
| Trivy image job fails without Docker socket access | it falls back to pulling the image from the registry (`--image-src docker,remote`) |
| `permission denied` writing reports on Linux | the orchestrator `chmod 777`s each scan's `raw/` folder; check the `data/` folder is writable by you |
| Dashboard container can't save triage verdicts (Linux) | it runs as uid 10001; `sudo chown -R 10001 data/` or run the dashboard on the host with `python -m smartvuln serve` |
| Charts don't render | Chart.js loads from cdnjs; offline, the tables still work |
| Want to reset | delete `data/` (SQLite DB and reports) |

## 12. Known limitations

- **ZAP spider:** ZAP uses the classic spider plus seeded endpoints and no AJAX/browser
  spider. Client-side flaws (DOM XSS) and most authenticated functionality are not
  reached, and no authenticated scan is configured.
- **Active scan scope:** the active scan is time-boxed and limited to 9 rules, by
  design, to keep CI runs short. It is not a full penetration test.
- **Route mapper coverage:** it only understands single-line `app.<verb>(…)`
  registrations in `server.ts`.
- **SAST fingerprints are line-based:** the comparison pairs line-shifted warnings with the
  same rule and file (see §5.5), but triage verdicts are stored per fingerprint. A verdict
  must therefore be repeated if the flagged line moves.
- **ZAP false negatives:** ZAP 2.17 did not report LabShop's reflected XSS, even with its
  XSS rule running alone, although the flaw is exploitable. The active scan is not a
  complete test.
- **Comparison in CI:** each CI run starts with an empty database. Comparison across CI
  runs requires importing a previous run's artifact (`smartvuln import`).
