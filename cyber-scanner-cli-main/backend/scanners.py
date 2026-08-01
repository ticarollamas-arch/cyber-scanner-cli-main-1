"""Real vulnerability scanners: Semgrep, Bandit, Gitleaks + heuristics."""
import asyncio
import json
import os
import re
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional


SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

PRIORITY_MAP = {
    "CRITICAL": "P0",
    "HIGH": "P1",
    "MEDIUM": "P2",
    "LOW": "P3",
    "INFO": "P4",
}


SEMGREP_BIN = shutil.which("semgrep") or "/root/.venv/bin/semgrep"
BANDIT_BIN = shutil.which("bandit") or "/root/.venv/bin/bandit"
GITLEAKS_BIN = shutil.which("gitleaks") or "/usr/local/bin/gitleaks"


async def _run(cmd: List[str], cwd: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
    """Run subprocess async and return {stdout, stderr, returncode}."""
    env = dict(os.environ)
    env["PATH"] = "/root/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return {"stdout": b"", "stderr": b"timeout", "returncode": -1}
    return {"stdout": stdout, "stderr": stderr, "returncode": proc.returncode}


def extract_zip(zip_bytes: bytes, target_dir: str) -> Dict[str, Any]:
    """Extract ZIP into target_dir, blocking zip-slip. Returns stats."""
    zip_path = Path(target_dir) / "_source.zip"
    zip_path.write_bytes(zip_bytes)
    stats = {"total_files": 0, "extracted": 0, "blocked": 0, "size_bytes": 0}
    target = Path(target_dir).resolve()

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
                stats["total_files"] += 1
                # Block zip slip
                extracted_path = (target / member.filename).resolve()
                if not str(extracted_path).startswith(str(target) + os.sep) and extracted_path != target:
                    stats["blocked"] += 1
                    continue
                # Block huge files (bomb) > 50MB
                if member.file_size > 50 * 1024 * 1024:
                    stats["blocked"] += 1
                    continue
                zf.extract(member, target_dir)
                stats["extracted"] += 1
                stats["size_bytes"] += member.file_size
    finally:
        zip_path.unlink(missing_ok=True)
    return stats


async def run_semgrep(target_dir: str) -> List[Dict[str, Any]]:
    """Run semgrep with auto config."""
    cmd = [SEMGREP_BIN, "scan", "--config", "auto", "--json", "--quiet", "--timeout", "60", "--no-git-ignore", target_dir]
    res = await _run(cmd, timeout=240)
    findings = []
    try:
        data = json.loads(res["stdout"].decode(errors="ignore") or "{}")
    except Exception:
        return findings

    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "MEDIUM").upper()
        severity = SEVERITY_MAP.get(sev, "MEDIUM")
        path = r.get("path", "").replace(target_dir + "/", "").replace(target_dir, "")
        line = r.get("start", {}).get("line", 0)
        end_line = r.get("end", {}).get("line", line)
        message = r.get("extra", {}).get("message", "")
        rule_id = r.get("check_id", "semgrep-rule")
        code_lines = r.get("extra", {}).get("lines", "") or ""
        metadata = r.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, list):
            cwe = ", ".join(cwe)
        owasp = metadata.get("owasp", "")
        if isinstance(owasp, list):
            owasp = ", ".join(owasp)
        findings.append({
            "scanner": "semgrep",
            "rule_id": rule_id,
            "title": message.split("\n")[0][:200] if message else rule_id,
            "description": message,
            "severity": severity,
            "priority": PRIORITY_MAP.get(severity, "P3"),
            "file_path": path,
            "line_start": line,
            "line_end": end_line,
            "code_snippet": code_lines,
            "cwe": cwe,
            "owasp": owasp,
            "references": metadata.get("references", []) or [],
        })
    return findings


async def run_bandit(target_dir: str) -> List[Dict[str, Any]]:
    """Run bandit against Python files."""
    # Only run if there are .py files
    has_py = False
    for root, _, files in os.walk(target_dir):
        for f in files:
            if f.endswith(".py"):
                has_py = True
                break
        if has_py:
            break
    if not has_py:
        return []
    cmd = [BANDIT_BIN, "-r", target_dir, "-f", "json", "-q"]
    res = await _run(cmd, timeout=120)
    findings = []
    try:
        data = json.loads(res["stdout"].decode(errors="ignore") or "{}")
    except Exception:
        return findings
    for r in data.get("results", []):
        sev = r.get("issue_severity", "MEDIUM").upper()
        severity = SEVERITY_MAP.get(sev, "MEDIUM")
        path = r.get("filename", "").replace(target_dir + "/", "").replace(target_dir, "")
        line = r.get("line_number", 0)
        cwe_data = r.get("issue_cwe", {}) or {}
        cwe = f"CWE-{cwe_data.get('id')}" if cwe_data.get("id") else ""
        findings.append({
            "scanner": "bandit",
            "rule_id": r.get("test_id", "bandit-rule"),
            "title": r.get("test_name", "Bandit finding"),
            "description": r.get("issue_text", ""),
            "severity": severity,
            "priority": PRIORITY_MAP.get(severity, "P3"),
            "file_path": path,
            "line_start": line,
            "line_end": line,
            "code_snippet": r.get("code", ""),
            "cwe": cwe,
            "owasp": "",
            "references": [r.get("more_info", "")] if r.get("more_info") else [],
        })
    return findings


async def run_gitleaks(target_dir: str) -> List[Dict[str, Any]]:
    """Scan for secrets."""
    report_path = os.path.join(target_dir, f".gitleaks-{uuid.uuid4().hex[:8]}.json")
    cmd = [GITLEAKS_BIN, "detect", "--source", target_dir, "--report-format", "json",
           "--report-path", report_path, "--no-git", "--exit-code", "0"]
    res = await _run(cmd, timeout=120)
    findings = []
    try:
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                data = json.load(f)
            os.remove(report_path)
        else:
            data = []
    except Exception:
        return findings
    for r in data or []:
        path = r.get("File", "").replace(target_dir + "/", "").replace(target_dir, "")
        line = r.get("StartLine", 0)
        rule = r.get("RuleID", "gitleaks-secret")
        findings.append({
            "scanner": "gitleaks",
            "rule_id": rule,
            "title": f"Secret detected: {rule}",
            "description": r.get("Description", "Hardcoded secret detected."),
            "severity": "HIGH",
            "priority": "P1",
            "file_path": path,
            "line_start": line,
            "line_end": r.get("EndLine", line),
            "code_snippet": (r.get("Match", "") or "")[:500],
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        })
    return findings


IAC_PATTERNS = [
    {
        "pattern": re.compile(r"hostPath\s*:", re.IGNORECASE),
        "ext": [".yaml", ".yml"],
        "title": "Kubernetes hostPath volume mount",
        "desc": "Using hostPath volumes exposes the host filesystem to containers, enabling container escapes.",
        "severity": "HIGH",
        "cwe": "CWE-250",
    },
    {
        "pattern": re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
        "ext": [".yaml", ".yml"],
        "title": "Kubernetes privileged container",
        "desc": "Privileged container has full root access to host, enabling privilege escalation.",
        "severity": "CRITICAL",
        "cwe": "CWE-250",
    },
    {
        "pattern": re.compile(r"runAsUser\s*:\s*0", re.IGNORECASE),
        "ext": [".yaml", ".yml"],
        "title": "Container running as root",
        "desc": "Containers running as root violate Pod Security Standards.",
        "severity": "MEDIUM",
        "cwe": "CWE-250",
    },
    {
        "pattern": re.compile(r"docker\.sock", re.IGNORECASE),
        "ext": [".yaml", ".yml", "Dockerfile"],
        "title": "Docker socket exposed",
        "desc": "Mounting docker.sock inside a container grants root on the host.",
        "severity": "CRITICAL",
        "cwe": "CWE-250",
    },
    {
        "pattern": re.compile(r"aws_secret_access_key\s*=", re.IGNORECASE),
        "ext": [".tf", ".hcl"],
        "title": "AWS credentials hardcoded in Terraform",
        "desc": "Hardcoded AWS credentials in Terraform files.",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
    },
]


async def run_iac_scan(target_dir: str) -> List[Dict[str, Any]]:
    """Simple heuristic IaC scanner for K8s / Docker / Terraform."""
    findings = []
    for root, _, files in os.walk(target_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = fpath.replace(target_dir + "/", "").replace(target_dir, "")
            for rule in IAC_PATTERNS:
                if not any(fname.endswith(e) or fname == e for e in rule["ext"]):
                    continue
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        for i, line in enumerate(f.readlines(), start=1):
                            if rule["pattern"].search(line):
                                findings.append({
                                    "scanner": "iac",
                                    "rule_id": f"iac-{rule['cwe']}",
                                    "title": rule["title"],
                                    "description": rule["desc"],
                                    "severity": rule["severity"],
                                    "priority": PRIORITY_MAP.get(rule["severity"], "P2"),
                                    "file_path": rel,
                                    "line_start": i,
                                    "line_end": i,
                                    "code_snippet": line.rstrip()[:300],
                                    "cwe": rule["cwe"],
                                    "owasp": "",
                                    "references": [],
                                })
                                break  # 1 hit per file per rule
                except Exception:
                    continue
    return findings


async def run_sca_scan(target_dir: str) -> List[Dict[str, Any]]:
    """Detect known vulnerable dependency versions in package.json / requirements.txt."""
    findings = []
    # Small KB of well-known CVEs
    kb_npm = {
        "lodash": [("<4.17.21", "CVE-2021-23337", "Command injection in _.template()", "HIGH")],
        "axios": [("<1.6.0", "CVE-2023-45857", "Cross-site request forgery vulnerability", "MEDIUM")],
        "minimist": [("<1.2.6", "CVE-2021-44906", "Prototype pollution", "CRITICAL")],
        "node-forge": [("<1.3.0", "CVE-2022-24771", "Signature verification bypass", "HIGH")],
    }
    kb_pypi = {
        "requests": [("<2.31.0", "CVE-2023-32681", "Unintended leak of Proxy-Authorization header", "MEDIUM")],
        "flask": [("<2.2.5", "CVE-2023-30861", "Cookie value leak via Flask's Set-Cookie header", "HIGH")],
        "django": [("<4.2.7", "CVE-2023-46695", "Denial of service via UsernameField", "HIGH")],
        "cryptography": [("<41.0.6", "CVE-2023-49083", "NULL dereference in PKCS12", "MEDIUM")],
        "pyyaml": [("<5.4", "CVE-2020-14343", "Arbitrary code execution via full_load", "CRITICAL")],
    }

    def _version_lt(v: str, spec: str) -> bool:
        # spec = "<X.Y.Z"
        try:
            spec_v = spec.lstrip("<").strip()
            v_clean = re.sub(r"[^\d.]", "", v.split("-")[0])
            sv = [int(x) for x in v_clean.split(".") if x][:3]
            sp = [int(x) for x in spec_v.split(".") if x][:3]
            while len(sv) < 3:
                sv.append(0)
            while len(sp) < 3:
                sp.append(0)
            return tuple(sv) < tuple(sp)
        except Exception:
            return False

    # package.json
    for root, _, files in os.walk(target_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = fpath.replace(target_dir + "/", "").replace(target_dir, "")
            if fname == "package.json":
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        pkg = json.load(f)
                    deps = {}
                    deps.update(pkg.get("dependencies", {}) or {})
                    deps.update(pkg.get("devDependencies", {}) or {})
                    for name, ver in deps.items():
                        if name in kb_npm:
                            for spec, cve, desc, sev in kb_npm[name]:
                                v_actual = re.sub(r"[\^~>=<]", "", str(ver))
                                if _version_lt(v_actual, spec):
                                    findings.append({
                                        "scanner": "sca",
                                        "rule_id": cve,
                                        "title": f"{name}@{ver} - {cve}",
                                        "description": f"{desc}. Affected: {spec}",
                                        "severity": sev,
                                        "priority": PRIORITY_MAP.get(sev, "P2"),
                                        "file_path": rel,
                                        "line_start": 0,
                                        "line_end": 0,
                                        "code_snippet": f'"{name}": "{ver}"',
                                        "cwe": "CWE-1104",
                                        "owasp": "A06:2021-Vulnerable and Outdated Components",
                                        "references": [f"https://nvd.nist.gov/vuln/detail/{cve}"],
                                    })
                except Exception:
                    continue
            elif fname == "requirements.txt":
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([0-9A-Za-z.\-]+)", line)
                            if not m:
                                continue
                            name = m.group(1).lower()
                            ver = m.group(2)
                            if name in kb_pypi:
                                for spec, cve, desc, sev in kb_pypi[name]:
                                    if _version_lt(ver, spec):
                                        findings.append({
                                            "scanner": "sca",
                                            "rule_id": cve,
                                            "title": f"{name}=={ver} - {cve}",
                                            "description": f"{desc}. Affected: {spec}",
                                            "severity": sev,
                                            "priority": PRIORITY_MAP.get(sev, "P2"),
                                            "file_path": rel,
                                            "line_start": 0,
                                            "line_end": 0,
                                            "code_snippet": line,
                                            "cwe": "CWE-1104",
                                            "owasp": "A06:2021-Vulnerable and Outdated Components",
                                            "references": [f"https://nvd.nist.gov/vuln/detail/{cve}"],
                                        })
                except Exception:
                    continue
    return findings


async def run_all_scanners(target_dir: str, progress_cb=None) -> Dict[str, Any]:
    """Run all scanners concurrently. progress_cb(step, message) optional."""
    findings: List[Dict[str, Any]] = []

    async def _stage(name: str, coro):
        if progress_cb:
            await progress_cb(name, f"Running {name}...")
        try:
            res = await coro
            findings.extend(res)
            if progress_cb:
                await progress_cb(name, f"{name} completed: {len(res)} findings")
        except Exception as e:
            if progress_cb:
                await progress_cb(name, f"{name} error: {e}")

    # Run sequentially so progress updates properly
    await _stage("semgrep", run_semgrep(target_dir))
    await _stage("bandit", run_bandit(target_dir))
    await _stage("gitleaks", run_gitleaks(target_dir))
    await _stage("iac", run_iac_scan(target_dir))
    await _stage("sca", run_sca_scan(target_dir))

    # Compute counts
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {"findings": findings, "counts": counts}
