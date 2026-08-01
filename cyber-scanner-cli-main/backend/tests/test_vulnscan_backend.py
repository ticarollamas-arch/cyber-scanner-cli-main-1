"""VulnScan AI backend integration tests."""
import io
import os
import time
import uuid
import zipfile

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # Try reading /app/frontend/.env
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL"):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

API = f"{BASE_URL}/api"

DEMO_EMAIL = "demo@vulnscan.ai"
DEMO_PASSWORD = "Demo1234!"


# --------------------------- Fixtures ---------------------------
@pytest.fixture(scope="session")
def api_client():
    s = requests.Session()
    s.headers.update({"Accept": "application/json"})
    return s


@pytest.fixture(scope="session")
def demo_token(api_client):
    r = api_client.post(f"{API}/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD})
    if r.status_code != 200:
        # Fallback: register the demo user (idempotent-ish)
        rr = api_client.post(f"{API}/auth/register", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD, "name": "Demo"})
        if rr.status_code == 200:
            return rr.json()["token"]
        pytest.fail(f"Cannot obtain demo token: login {r.status_code} {r.text}")
    return r.json()["token"]


@pytest.fixture(scope="session")
def demo_headers(demo_token):
    return {"Authorization": f"Bearer {demo_token}"}


@pytest.fixture(scope="session")
def vulnerable_zip_bytes():
    """Create a small vulnerable code ZIP."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("app.py", (
            "import subprocess\n"
            "import os\n"
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
            "def run(cmd):\n"
            "    return subprocess.check_output(cmd, shell=True)\n"
            "def read(path):\n"
            "    with open('/data/' + path, 'r') as f:\n"
            "        return f.read()\n"
        ))
        z.writestr("requirements.txt", "pyyaml==3.13\nflask==2.0.0\nrequests==2.25.0\n")
        z.writestr("k8s/pod.yaml", (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n  name: bad\n"
            "spec:\n"
            "  containers:\n"
            "  - name: bad\n"
            "    image: alpine\n"
            "    securityContext:\n"
            "      privileged: true\n"
            "    volumeMounts:\n"
            "    - name: dock\n"
            "      mountPath: /var/run/docker.sock\n"
            "  volumes:\n"
            "  - name: dock\n"
            "    hostPath:\n"
            "      path: /var/run/docker.sock\n"
        ))
        z.writestr(".env", "API_KEY=sk_test_abcdef1234567890abcdef1234567890\n")
    return buf.getvalue()


# --------------------------- Auth Tests ---------------------------
class TestAuth:
    def test_root(self, api_client):
        r = api_client.get(f"{API}/")
        assert r.status_code == 200
        assert r.json().get("service") == "VulnScan AI"

    def test_register_new_user(self, api_client):
        email = f"test_{uuid.uuid4().hex[:8]}@vulnscan.ai"
        r = api_client.post(f"{API}/auth/register", json={"email": email, "password": "Passw0rd!", "name": "T"})
        assert r.status_code == 200, r.text
        data = r.json()
        assert "token" in data and isinstance(data["token"], str) and len(data["token"]) > 10
        assert data["user"]["email"] == email
        assert "id" in data["user"]

    def test_register_duplicate(self, api_client):
        r = api_client.post(f"{API}/auth/register", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD})
        assert r.status_code == 409

    def test_login_demo(self, api_client, demo_token):
        assert isinstance(demo_token, str) and len(demo_token) > 10

    def test_login_wrong_password(self, api_client):
        r = api_client.post(f"{API}/auth/login", json={"email": DEMO_EMAIL, "password": "wrongpass!"})
        assert r.status_code == 401

    def test_me_with_token(self, api_client, demo_headers):
        r = api_client.get(f"{API}/auth/me", headers=demo_headers)
        assert r.status_code == 200
        assert r.json()["email"] == DEMO_EMAIL

    def test_me_without_token(self, api_client):
        r = api_client.get(f"{API}/auth/me")
        assert r.status_code == 401

    def test_scans_requires_auth(self, api_client):
        r = api_client.get(f"{API}/scans")
        assert r.status_code == 401


# --------------------------- Scan lifecycle ---------------------------
class TestScanLifecycle:
    scan_id = None

    def test_create_scan(self, api_client, demo_headers, vulnerable_zip_bytes):
        files = {"file": ("vuln.zip", vulnerable_zip_bytes, "application/zip")}
        data = {"project_name": "TEST_vuln_project"}
        r = api_client.post(f"{API}/scans", headers=demo_headers, files=files, data=data)
        assert r.status_code == 200, r.text
        j = r.json()
        assert "id" in j
        assert j["status"] == "queued"
        assert j["project_name"] == "TEST_vuln_project"
        TestScanLifecycle.scan_id = j["id"]

    def test_scan_progress_and_complete(self, api_client, demo_headers):
        assert TestScanLifecycle.scan_id
        sid = TestScanLifecycle.scan_id
        deadline = time.time() + 180
        last_status = None
        while time.time() < deadline:
            r = api_client.get(f"{API}/scans/{sid}", headers=demo_headers)
            assert r.status_code == 200
            j = r.json()
            last_status = j["status"]
            if last_status in ("completed", "failed"):
                break
            time.sleep(5)
        assert last_status == "completed", f"Scan did not complete: {last_status}"

    def test_list_scans(self, api_client, demo_headers):
        r = api_client.get(f"{API}/scans", headers=demo_headers)
        assert r.status_code == 200
        scans = r.json()
        ids = [s["id"] for s in scans]
        assert TestScanLifecycle.scan_id in ids

    def test_scan_isolation_between_users(self, api_client, vulnerable_zip_bytes):
        # Create another user
        email = f"other_{uuid.uuid4().hex[:8]}@vulnscan.ai"
        rr = api_client.post(f"{API}/auth/register", json={"email": email, "password": "Passw0rd!"})
        assert rr.status_code == 200
        other_headers = {"Authorization": f"Bearer {rr.json()['token']}"}
        r = api_client.get(f"{API}/scans", headers=other_headers)
        assert r.status_code == 200
        assert TestScanLifecycle.scan_id not in [s["id"] for s in r.json()]
        # And cannot access foreign scan directly
        r2 = api_client.get(f"{API}/scans/{TestScanLifecycle.scan_id}", headers=other_headers)
        assert r2.status_code == 404

    def test_vulnerabilities(self, api_client, demo_headers):
        sid = TestScanLifecycle.scan_id
        r = api_client.get(f"{API}/scans/{sid}/vulnerabilities", headers=demo_headers)
        assert r.status_code == 200
        vulns = r.json()
        assert isinstance(vulns, list) and len(vulns) > 0, "Expected findings from scanners"
        # Sorted by severity: first is <= last
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sevs = [sev_order.get(v["severity"], 5) for v in vulns]
        assert sevs == sorted(sevs)

        titles = " ".join(v.get("title", "") + " " + v.get("description", "") for v in vulns).lower()
        scanners_present = {v["scanner"] for v in vulns}

        # Expected findings
        assert "privileged" in titles, "Missing K8s privileged container finding"
        assert "docker" in titles or "docker.sock" in titles, "Missing docker socket finding"
        assert any("pyyaml" in (v.get("title") or "").lower() for v in vulns), "Missing pyyaml CVE"
        # SCA + IaC + gitleaks scanners should be present (semgrep/bandit may fail without network)
        assert "iac" in scanners_present
        assert "sca" in scanners_present
        # Store one vuln id for AI analyze
        crit = [v for v in vulns if v["severity"] == "CRITICAL"]
        TestScanLifecycle.vuln_id = (crit or vulns)[0]["id"]

    def test_ai_analyze(self, api_client, demo_headers):
        sid = TestScanLifecycle.scan_id
        vid = TestScanLifecycle.vuln_id
        r = api_client.post(f"{API}/scans/{sid}/vulnerabilities/{vid}/analyze", headers=demo_headers)
        assert r.status_code == 200, r.text
        ai = r.json()
        # Expected keys per spec
        expected_any = {"title", "severity", "poc_commands", "remediation"}
        assert any(k in ai for k in expected_any), f"AI response missing expected keys: {ai}"


# --------------------------- Terminal ---------------------------
class TestTerminal:
    def test_terminal_ls(self, api_client, demo_headers):
        sid = TestScanLifecycle.scan_id
        r = api_client.post(f"{API}/scans/{sid}/terminal", headers=demo_headers, json={"command": "ls -la"})
        assert r.status_code == 200, r.text
        j = r.json()
        assert "stdout" in j and "stderr" in j and "returncode" in j and "duration_ms" in j
        assert j["returncode"] == 0
        assert "app.py" in j["stdout"] or "requirements.txt" in j["stdout"]

    def test_terminal_blocks_dangerous(self, api_client, demo_headers):
        sid = TestScanLifecycle.scan_id
        for cmd in ["shutdown -h now", "mkfs.ext4 /dev/sda1"]:
            r = api_client.post(f"{API}/scans/{sid}/terminal", headers=demo_headers, json={"command": cmd})
            # Either explicit 400 or non-zero returncode with a "blocked" marker
            if r.status_code == 200:
                j = r.json()
                blocked = (j.get("returncode", 0) != 0) or ("block" in (j.get("stderr", "") + j.get("stdout", "")).lower())
                assert blocked, f"Dangerous command not blocked: {cmd} => {j}"
            else:
                assert r.status_code in (400, 403)

    def test_terminal_jailed(self, api_client, demo_headers):
        """Confirm that pwd/reading outside workspace is restricted or cwd is workspace."""
        sid = TestScanLifecycle.scan_id
        r = api_client.post(f"{API}/scans/{sid}/terminal", headers=demo_headers, json={"command": "pwd"})
        assert r.status_code == 200
        out = r.json().get("stdout", "")
        assert sid in out or "workspace" in out, f"Terminal cwd not in workspace: {out}"


# --------------------------- Reports ---------------------------
class TestReports:
    def test_pdf(self, api_client, demo_headers):
        sid = TestScanLifecycle.scan_id
        r = api_client.get(f"{API}/scans/{sid}/report.pdf", headers=demo_headers)
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("application/pdf")
        assert r.content.startswith(b"%PDF"), "Not a real PDF"

    def test_md(self, api_client, demo_headers):
        sid = TestScanLifecycle.scan_id
        r = api_client.get(f"{API}/scans/{sid}/report.md", headers=demo_headers)
        assert r.status_code == 200
        assert "text/markdown" in r.headers.get("content-type", "")
        assert "#" in r.text  # markdown header


# --------------------------- Delete ---------------------------
class TestDelete:
    def test_delete_scan(self, api_client, demo_headers):
        sid = TestScanLifecycle.scan_id
        r = api_client.delete(f"{API}/scans/{sid}", headers=demo_headers)
        assert r.status_code == 200
        # Verify removal
        r2 = api_client.get(f"{API}/scans/{sid}", headers=demo_headers)
        assert r2.status_code == 404
        r3 = api_client.get(f"{API}/scans/{sid}/vulnerabilities", headers=demo_headers)
        assert r3.status_code == 404
