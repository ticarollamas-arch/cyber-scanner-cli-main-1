"""VulnScan AI - Real vulnerability scanner SaaS backend."""
import asyncio
import io
import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, EmailStr, Field
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

from db import users_col, scans_col, vulns_col, reports_col
from auth import (
    hash_password, verify_password, create_token, get_current_user,
)
from scanners import extract_zip, run_all_scanners
from llm_analyzer import analyze_vulnerability
from terminal import execute_command, get_workspace_path
from reports import build_pdf, build_markdown

WORKSPACE_ROOT = os.environ.get("WORKSPACE_DIR", "/app/workspace")
os.makedirs(WORKSPACE_ROOT, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("vulnscan")

app = FastAPI(title="VulnScan AI")
api = APIRouter(prefix="/api")


# ----------------------------- Models -----------------------------
class RegisterReq(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=200)
    name: Optional[str] = None


class LoginReq(BaseModel):
    email: EmailStr
    password: str


class TerminalCmd(BaseModel):
    command: str


class VulnAnalyzeReq(BaseModel):
    finding_id: str


# ----------------------------- Helpers -----------------------------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _user_public(u: dict) -> dict:
    return {"id": u["id"], "email": u["email"], "name": u.get("name")}


def _scan_public(s: dict) -> dict:
    return {
        "id": s["id"],
        "project_name": s["project_name"],
        "filename": s.get("filename"),
        "status": s["status"],
        "progress": s.get("progress", 0),
        "current_step": s.get("current_step"),
        "counts": s.get("counts", {}),
        "created_at": s["created_at"],
        "completed_at": s.get("completed_at"),
        "total_findings": s.get("total_findings", 0),
        "scanner_log": s.get("scanner_log", []),
    }


def _vuln_public(v: dict) -> dict:
    return {k: v[k] for k in v if k != "_id"}


async def _update_scan(scan_id: str, updates: dict):
    updates["updated_at"] = _now()
    await scans_col.update_one({"id": scan_id}, {"$set": updates})


async def _append_log(scan_id: str, step: str, message: str):
    entry = {"step": step, "message": message, "ts": _now()}
    await scans_col.update_one({"id": scan_id}, {"$push": {"scanner_log": entry}})


# ----------------------------- Auth -----------------------------
@api.post("/auth/register")
async def register(req: RegisterReq):
    existing = await users_col.find_one({"email": req.email.lower()})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "email": req.email.lower(),
        "name": req.name or req.email.split("@")[0],
        "password_hash": hash_password(req.password),
        "created_at": _now(),
    }
    await users_col.insert_one(doc)
    token = create_token(user_id, doc["email"])
    return {"token": token, "user": _user_public(doc)}


@api.post("/auth/login")
async def login(req: LoginReq):
    u = await users_col.find_one({"email": req.email.lower()})
    if not u or not verify_password(req.password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(u["id"], u["email"])
    return {"token": token, "user": _user_public(u)}


@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    u = await users_col.find_one({"id": user["id"]})
    if not u:
        raise HTTPException(status_code=404, detail="Not found")
    return _user_public(u)


# ----------------------------- Scans -----------------------------
@api.post("/scans")
async def create_scan(
    file: UploadFile = File(...),
    project_name: str = Form(...),
    user=Depends(get_current_user),
):
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP archives are supported")
    content = await file.read()
    if len(content) > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 100MB)")

    scan_id = str(uuid.uuid4())
    workspace = get_workspace_path(scan_id)
    try:
        stats = extract_zip(content, workspace)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid ZIP: {e}")

    doc = {
        "id": scan_id,
        "user_id": user["id"],
        "project_name": project_name,
        "filename": file.filename,
        "status": "queued",
        "progress": 5,
        "current_step": "extracted",
        "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "extract_stats": stats,
        "created_at": _now(),
        "updated_at": _now(),
        "scanner_log": [{"step": "extract", "message": f"Extracted {stats['extracted']} files, blocked {stats['blocked']}", "ts": _now()}],
        "total_findings": 0,
    }
    await scans_col.insert_one(doc)
    # Kick off scan in background
    asyncio.create_task(_run_scan_job(scan_id, workspace))
    return _scan_public(doc)


async def _run_scan_job(scan_id: str, workspace: str):
    """Background scanner job."""
    try:
        await _update_scan(scan_id, {"status": "scanning", "progress": 15, "current_step": "semgrep"})

        step_progress = {"semgrep": 30, "bandit": 45, "gitleaks": 60, "iac": 70, "sca": 80}

        async def progress_cb(step, message):
            await _append_log(scan_id, step, message)
            await _update_scan(scan_id, {"progress": step_progress.get(step, 30), "current_step": step})

        result = await run_all_scanners(workspace, progress_cb=progress_cb)
        findings = result["findings"]
        counts = result["counts"]

        # Store findings
        docs = []
        for f in findings:
            f["id"] = str(uuid.uuid4())
            f["scan_id"] = scan_id
            f["ai_analysis"] = None
            f["created_at"] = _now()
            docs.append(f)
        if docs:
            await vulns_col.insert_many(docs)

        await _append_log(scan_id, "scan_complete", f"Total findings: {len(docs)}")

        # AI enrichment - top N by severity, in parallel
        await _update_scan(scan_id, {"progress": 85, "current_step": "ai_analysis"})
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        docs_sorted = sorted(docs, key=lambda x: sev_order.get(x["severity"], 5))
        top = docs_sorted[:8]  # Limit LLM calls

        async def enrich(f):
            file_content = ""
            try:
                fpath = os.path.join(workspace, f.get("file_path", ""))
                if os.path.exists(fpath) and os.path.getsize(fpath) < 200_000:
                    with open(fpath, "r", errors="ignore") as fh:
                        file_content = fh.read()
            except Exception:
                pass
            ai = await analyze_vulnerability(f, file_content=file_content)
            await vulns_col.update_one({"id": f["id"]}, {"$set": {"ai_analysis": ai}})

        await asyncio.gather(*(enrich(f) for f in top), return_exceptions=True)
        await _append_log(scan_id, "ai_analysis", f"AI-enriched {len(top)} top findings")

        await _update_scan(scan_id, {
            "status": "completed",
            "progress": 100,
            "current_step": "done",
            "counts": counts,
            "total_findings": len(docs),
            "completed_at": _now(),
        })
    except Exception as e:
        log.exception("Scan job failed")
        await _append_log(scan_id, "error", str(e))
        await _update_scan(scan_id, {"status": "failed", "current_step": "error"})


@api.get("/scans")
async def list_scans(user=Depends(get_current_user)):
    cursor = scans_col.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1)
    scans = await cursor.to_list(200)
    return [_scan_public(s) for s in scans]


@api.get("/scans/{scan_id}")
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    s = await scans_col.find_one({"id": scan_id, "user_id": user["id"]}, {"_id": 0})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_public(s)


@api.get("/scans/{scan_id}/vulnerabilities")
async def get_vulns(scan_id: str, user=Depends(get_current_user)):
    s = await scans_col.find_one({"id": scan_id, "user_id": user["id"]}, {"_id": 0})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    cursor = vulns_col.find({"scan_id": scan_id}, {"_id": 0})
    vulns = await cursor.to_list(1000)
    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns.sort(key=lambda x: sev_order.get(x.get("severity"), 5))
    return vulns


@api.post("/scans/{scan_id}/vulnerabilities/{vuln_id}/analyze")
async def analyze_single(scan_id: str, vuln_id: str, user=Depends(get_current_user)):
    s = await scans_col.find_one({"id": scan_id, "user_id": user["id"]}, {"_id": 0})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    v = await vulns_col.find_one({"id": vuln_id, "scan_id": scan_id}, {"_id": 0})
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    workspace = get_workspace_path(scan_id)
    file_content = ""
    try:
        fpath = os.path.join(workspace, v.get("file_path", ""))
        if os.path.exists(fpath) and os.path.getsize(fpath) < 200_000:
            with open(fpath, "r", errors="ignore") as fh:
                file_content = fh.read()
    except Exception:
        pass
    ai = await analyze_vulnerability(v, file_content=file_content)
    await vulns_col.update_one({"id": vuln_id}, {"$set": {"ai_analysis": ai}})
    return ai


@api.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, user=Depends(get_current_user)):
    s = await scans_col.find_one({"id": scan_id, "user_id": user["id"]})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    await scans_col.delete_one({"id": scan_id})
    await vulns_col.delete_many({"scan_id": scan_id})
    # Cleanup workspace
    workspace_dir = os.path.join(WORKSPACE_ROOT, scan_id)
    if os.path.exists(workspace_dir):
        shutil.rmtree(workspace_dir, ignore_errors=True)
    return {"ok": True}


# ----------------------------- Terminal -----------------------------
@api.post("/scans/{scan_id}/terminal")
async def run_terminal_cmd(scan_id: str, req: TerminalCmd, user=Depends(get_current_user)):
    s = await scans_col.find_one({"id": scan_id, "user_id": user["id"]}, {"_id": 0})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = await execute_command(scan_id, req.command, timeout=30)
    return result


@api.get("/scans/{scan_id}/tree")
async def get_tree(scan_id: str, user=Depends(get_current_user)):
    """Simple 'tree' listing of the scanned workspace."""
    s = await scans_col.find_one({"id": scan_id, "user_id": user["id"]}, {"_id": 0})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    workspace = get_workspace_path(scan_id)
    items = []
    max_items = 500
    for root, dirs, files in os.walk(workspace):
        # skip node_modules and heavy dirs
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__pycache__", "venv", ".venv")]
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, workspace)
            try:
                size = os.path.getsize(full)
            except Exception:
                size = 0
            items.append({"path": rel, "size": size})
            if len(items) >= max_items:
                return {"files": items, "truncated": True}
    return {"files": items, "truncated": False}


@api.get("/scans/{scan_id}/file")
async def read_file(scan_id: str, path: str, user=Depends(get_current_user)):
    s = await scans_col.find_one({"id": scan_id, "user_id": user["id"]}, {"_id": 0})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    workspace = get_workspace_path(scan_id)
    full = os.path.realpath(os.path.join(workspace, path))
    if not full.startswith(os.path.realpath(workspace)):
        raise HTTPException(status_code=403, detail="Path traversal blocked")
    if not os.path.exists(full) or not os.path.isfile(full):
        raise HTTPException(status_code=404, detail="File not found")
    if os.path.getsize(full) > 500_000:
        raise HTTPException(status_code=413, detail="File too large")
    try:
        with open(full, "r", errors="replace") as f:
            content = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"path": path, "content": content}


# ----------------------------- Reports -----------------------------
@api.get("/scans/{scan_id}/report.pdf")
async def report_pdf(scan_id: str, user=Depends(get_current_user)):
    s = await scans_col.find_one({"id": scan_id, "user_id": user["id"]}, {"_id": 0})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = await vulns_col.find({"scan_id": scan_id}, {"_id": 0}).to_list(1000)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_order.get(x.get("severity"), 5))
    pdf_bytes = build_pdf(s, findings)
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=vulnscan-{scan_id[:8]}.pdf"})


@api.get("/scans/{scan_id}/report.md")
async def report_md(scan_id: str, user=Depends(get_current_user)):
    s = await scans_col.find_one({"id": scan_id, "user_id": user["id"]}, {"_id": 0})
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = await vulns_col.find({"scan_id": scan_id}, {"_id": 0}).to_list(1000)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_order.get(x.get("severity"), 5))
    md = build_markdown(s, findings)
    return Response(content=md, media_type="text/markdown",
                    headers={"Content-Disposition": f"attachment; filename=vulnscan-{scan_id[:8]}.md"})


# ----------------------------- Meta -----------------------------
@api.get("/")
async def root():
    return {"service": "VulnScan AI", "status": "operational", "version": "1.0.0"}


@api.get("/stats")
async def stats(user=Depends(get_current_user)):
    total = await scans_col.count_documents({"user_id": user["id"]})
    completed = await scans_col.count_documents({"user_id": user["id"], "status": "completed"})
    # Scope vulns to caller's scans
    my_scan_ids = [s["id"] async for s in scans_col.find({"user_id": user["id"]}, {"id": 1, "_id": 0})]
    vulns = await vulns_col.count_documents({"scan_id": {"$in": my_scan_ids}}) if my_scan_ids else 0
    return {"scans": total, "completed": completed, "vulnerabilities_indexed": vulns}


app.include_router(api)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    log.info("VulnScan AI backend started")
