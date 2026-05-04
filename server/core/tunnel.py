import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

# Module-level variables to hold the process and URL
_tunnel_process: Optional[subprocess.Popen] = None
_tunnel_url: Optional[str] = None

def get_or_start_tunnel(port: int = 8000) -> str:
    """
    Ensure the localhost.run tunnel is running via SSH, pointing to the local port.
    Returns the lhr.life or lhr.rocks URL.
    """
    global _tunnel_process, _tunnel_url

    # Check if the process is still running
    if _tunnel_process is not None and _tunnel_process.poll() is None:
        if _tunnel_url:
            return _tunnel_url

    print(f"[TUNNEL] Starting localhost.run tunnel (SSH) for port {port}...")
    
    project_root = Path(__file__).parent.parent.parent
    log_dir = project_root / "server" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "tunnel.log"
    
    # Use SSH for the tunnel. 
    # -o StrictHostKeyChecking=no bypasses the fingerprint prompt
    # -o ExitOnForwardFailure=yes ensures the process fails if the port is busy
    cmd = [
        "ssh", 
        "-o", "StrictHostKeyChecking=no", 
        "-o", "ExitOnForwardFailure=yes",
        "-R", f"80:127.0.0.1:{port}", 
        "nokey@localhost.run"
    ]
    
    print(f"[TUNNEL] Command: {' '.join(cmd)}")
    
    log_file = open(log_path, "w")
    _tunnel_process = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    # Read the log file to find the URL
    start_time = time.time()
    url = None
    
    while time.time() - start_time < 30:
        if _tunnel_process.poll() is not None:
            with open(log_path, "r") as f:
                logs = f.read()
            raise RuntimeError(f"Tunnel (SSH) exited unexpectedly: {logs}")
        
        if log_path.exists():
            with open(log_path, "r") as f:
                content = f.read()
                # localhost.run URLs usually end in .lhr.life or .lhr.rocks
                match = re.search(r'(https://[a-zA-Z0-9-.]+\.lhr\.(?:life|rocks))', content)
                if match:
                    url = match.group(1)
                    break
        time.sleep(1)

    if not url:
        _tunnel_process.terminate()
        with open(log_path, "r") as f:
            logs = f.read()
        raise TimeoutError(f"Failed to extract tunnel URL from logs within timeout. Logs: {logs}")

    _tunnel_url = url
    print(f"[TUNNEL] Tunnel successfully started at {url}")
    return url

def stop_tunnel() -> None:
    """Stop the running tunnel and clear logs."""
    global _tunnel_process, _tunnel_url
    
    project_root = Path(__file__).parent.parent.parent
    log_path = project_root / "server" / "logs" / "tunnel.log"

    if _tunnel_process is not None:
        print("[TUNNEL] Stopping tunnel...")
        _tunnel_process.terminate()
        try:
            _tunnel_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _tunnel_process.kill()
        _tunnel_process = None
        _tunnel_url = None
        
        # Clear the log file
        if log_path.exists():
            try:
                log_path.write_text("")
                print(f"[TUNNEL] Logs cleared: {log_path}")
            except Exception as e:
                print(f"[TUNNEL] Failed to clear logs: {e}")

def get_tunnel_status() -> str | None:
    """Return the active tunnel URL if running, else None."""
    global _tunnel_process, _tunnel_url
    if _tunnel_process is not None and _tunnel_process.poll() is None:
        return _tunnel_url
    return None
