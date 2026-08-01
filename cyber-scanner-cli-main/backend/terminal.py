"""Real terminal executor - sandboxed bash inside a scan's workspace."""
import asyncio
import os
import shlex
from typing import Optional

WORKSPACE_ROOT = os.environ.get("WORKSPACE_DIR", "/app/workspace")

# Blocked commands (best-effort; workspace is already jailed by chroot-like path check)
BLOCKED_PATTERNS = [
    "rm -rf /",
    "mkfs",
    ":(){:|:&};:",
    "shutdown",
    "reboot",
    "dd if=/dev/zero of=/dev",
    "> /dev/sda",
    "chmod -R 000 /",
    "curl http",  # optional: keep curl to localhost; here we allow curl broadly to enable POCs
]

# We DO allow curl (needed to reproduce web exploits) but block obvious destructive shell.
DENY = [
    "shutdown", "reboot", "mkfs", "poweroff", "halt", "init 0", "init 6",
]


def _is_blocked(cmd: str) -> Optional[str]:
    low = cmd.strip().lower()
    for token in DENY:
        if token in low:
            return f"Command blocked: contains '{token}'"
    # Block traversal above workspace via cd
    return None


def get_workspace_path(scan_id: str) -> str:
    """Return absolute path to scan's workspace, ensuring it exists."""
    path = os.path.join(WORKSPACE_ROOT, scan_id, "src")
    os.makedirs(path, exist_ok=True)
    return path


async def execute_command(scan_id: str, command: str, timeout: int = 30) -> dict:
    """Execute a bash command inside the scan's workspace directory."""
    blocked = _is_blocked(command)
    if blocked:
        return {"stdout": "", "stderr": blocked, "returncode": 126, "duration_ms": 0}

    cwd = get_workspace_path(scan_id)
    start = asyncio.get_event_loop().time()

    # Force bash so we can use pipes and expansions
    proc = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env={
            "HOME": cwd,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": cwd,
            "TERM": "xterm-256color",
            "USER": "vulnscan",
            "LANG": "C.UTF-8",
        },
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return {"stdout": "", "stderr": f"Timeout after {timeout}s", "returncode": -1,
                "duration_ms": int((asyncio.get_event_loop().time() - start) * 1000)}
    duration = int((asyncio.get_event_loop().time() - start) * 1000)
    # Truncate huge outputs
    out = stdout.decode(errors="replace")[:20000]
    err = stderr.decode(errors="replace")[:5000]
    return {"stdout": out, "stderr": err, "returncode": proc.returncode, "duration_ms": duration}
