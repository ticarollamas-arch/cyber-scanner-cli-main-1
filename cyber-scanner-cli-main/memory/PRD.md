# VulnScan AI · Product Requirements Document

## Original problem statement
User (Portuguese) provided a generic corporate blueprint for a vulnerability scanner SaaS (`VulnScan AI`) with a full directory tree, Go/Next.js/K8s/Terraform stack and DB schema. Their instruction: *"Esse meu projeto esta generico transforme ele real com poc reproziveis real com terminal real"* — "This project is generic, make it real with reproducible POCs and a real terminal."

## Product decision
Adapted the blueprint to the runnable stack in this environment while preserving the same functional shape:
- **Backend:** FastAPI (Python) + MongoDB
- **Frontend:** React (CRA) + Tailwind + custom terminal (xterm.js was tried but replaced with a resilient DOM terminal)
- **Scanners:** All REAL and installed in the container.
- **AI:** Claude Sonnet 4.5 via Emergent LLM Key (emergentintegrations).

## User personas
- **Security engineer** – uploads code archives, wants reproducible PoC to hand off to devs.
- **DevSecOps operator** – reviews severity, runs live commands in the sandbox to verify.
- **Executive / auditor** – downloads the PDF report with executive summary.

## Core (implemented)
- [x] JWT auth (register/login/me) with bcrypt hashing
- [x] Upload ZIP → jailed extraction with zip-slip blocking (max 100MB)
- [x] Real scanner pipeline: **Semgrep** (`--config auto`), **Bandit**, **Gitleaks**, **IaC heuristics** (K8s/Docker/Terraform), **SCA CVE detection** (npm + PyPI KB)
- [x] Progress + live log per scan (auto-polled)
- [x] AI enrichment (Claude Sonnet 4.5) generates: title, cwe, severity, impact, root_cause, attack_vector, reproducible poc_commands[], remediation, patch_diff
- [x] Sandboxed real bash terminal per scan (workspace-jailed, 30s timeout, dangerous commands blocked)
- [x] Vulnerability drawer with "Run in terminal" that injects the PoC and switches tabs
- [x] Landing page with cybersecurity/terminal aesthetic (matrix-green on obsidian, IBM Plex Sans + JetBrains Mono)
- [x] Dashboard with severity breakdown, auto-refresh
- [x] Report export: PDF (reportlab) + Markdown
- [x] Delete scan cleans workspace + findings

## Architecture
- Backend at `/app/backend/` – `server.py`, `scanners.py`, `llm_analyzer.py`, `terminal.py`, `reports.py`, `auth.py`, `db.py`
- Scanner binaries at `/root/.venv/bin/{semgrep,bandit}` and `/usr/local/bin/gitleaks`
- Workspace at `/app/workspace/{scan_id}/src/`
- Frontend at `/app/frontend/src/` – `pages/`, `components/`, `lib/`

## Testing (20/20 backend tests passed on 2026-01-30)
- Auth: register/login/me/401 protection
- Scan lifecycle: queued → scanning → completed under ~40s
- Real findings: K8s privileged (CRITICAL), docker.sock (CRITICAL), pyyaml CVE, subprocess call, path traversal
- Terminal: real commands run in workspace, dangerous commands blocked
- Reports: PDF + Markdown export
- Tenant isolation

## Backlog / next
- **P1**: Persist scan queue (arq/RQ) so a backend restart resumes in-flight scans instead of leaving them at `scanning` forever
- **P1**: Surface semgrep registry availability in scanner_log if `--config auto` returned zero results
- **P2**: WebSocket streaming terminal (currently REST per command)
- **P2**: Compare scans across commits (delta report)
- **P2**: Slack / GitHub webhook on completion
- **P3**: Multi-user organizations + team roles

## Endpoints
- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`
- `POST /api/scans` (multipart), `GET /api/scans`, `GET /api/scans/{id}`, `DELETE /api/scans/{id}`
- `GET /api/scans/{id}/vulnerabilities`
- `POST /api/scans/{id}/vulnerabilities/{vuln_id}/analyze`
- `POST /api/scans/{id}/terminal`, `GET /api/scans/{id}/tree`, `GET /api/scans/{id}/file?path=`
- `GET /api/scans/{id}/report.pdf`, `GET /api/scans/{id}/report.md`
- `GET /api/stats`

## Timeline
- 2026-01-30 — MVP built end to end. Landing + auth + scans + AI + terminal + reports. Backend suite green.
