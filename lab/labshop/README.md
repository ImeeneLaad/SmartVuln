# LabShop — before/after lab for SmartVuln

LabShop is a small online shop: Express backend, SQLite database (Node's built-in
`node:sqlite`) and a plain HTML frontend. It is **deliberately vulnerable**, and it is kept
separate from SmartVuln's own code. Run it only in this lab: Compose binds it to
`127.0.0.1:3100` and attaches it to the private `smartvuln-net` network.

Lab accounts: `alice@labshop.test` / `alice123` and `admin@labshop.test` / `admin2024`.

## The exercise

All commands run from the SmartVuln folder (`D:\SmartVuln`).

### 1. Start LabShop and SmartVuln

```bash
docker compose up -d --build labshop
```
```bash
python -m smartvuln serve
```

Open http://127.0.0.1:5000. LabShop itself is at http://127.0.0.1:3100.

### 2. Scan #1 — Before fixes

In the **Scan Center**, choose **LabShop**, keep Semgrep, Trivy and OWASP ZAP ticked, enter
the label `Before fixes` and click **Start scan**. It takes about 2–3 minutes.

*Already done in this workspace: scan #4, labelled "Scan #1 — Before fixes".*

Browse the results in **Overview** and **Findings**. Each finding page shows its severity,
the scanner(s) that reported it, a description, the source line or HTTP evidence, and how to
fix it.

### 3. Fix the vulnerabilities yourself

Follow [VULNERABILITIES.md](VULNERABILITIES.md). It explains each of the eleven weaknesses
and how to fix it, and keeps the reference code folded away.

### 4. Rebuild the app

ZAP and Trivy test the **running container**, so code changes count only after a rebuild:

```bash
docker compose up -d --build labshop
```

Back in the Scan Center, the pre-flight list shows **"Running build matches source"**. If
it says *out of date*, you forgot to rebuild.

### 5. Scan #2 — After fixes

Same target, same scanners, label `After fixes`, **Start scan**.

### 6. Triage what remains

Open the Semgrep findings that remain in `routes/search.js` and `routes/files.js`. Check in
the browser that the attack no longer works, then record **False positive** with a short
justification. The verdict follows the finding into later scans.

### 7. Compare

**Compare** → *Before fixes* → *After fixes*. You'll see:
- before/after totals and how many were **resolved**, **remain** and are **new**;
- before/after charts by severity and by scanner;
- the lists of resolved, new and remaining findings.

**Export report** saves the comparison as HTML.

## Resetting the lab

Restore your copy of the original folder (see VULNERABILITIES.md), or check the files back
out from version control, then run `docker compose up -d --build labshop`.

## How SmartVuln is configured for LabShop

The `[targets.labshop]` block in `config/smartvuln.toml` sets:
- the source folder for Semgrep and Trivy (`lab/labshop`) and the image Trivy scans
  (`smartvuln-labshop:latest`);
- the URL ZAP scans (`http://labshop:3000`) and the health-check URL;
- seed URLs and a lab login, so ZAP reaches every endpoint and sees the session cookie.

`/health` reports a hash of the code the container was built from. SmartVuln compares it
with the source on disk to detect a stale build.
