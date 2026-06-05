import json
import os
import fcntl
from datetime import datetime, timezone
from typing import Any

class GlobalToolCache:
    """A cross-cycle, cross-worker shared memory for executed tools."""

    def __init__(self, project_cache_dir: str, role: str):
        self.filepath = os.path.join(project_cache_dir, f"global_cache_{role}.json")

    def _read_cache(self) -> dict[str, Any]:
        if not os.path.exists(self.filepath):
            return {}
        try:
            with open(self.filepath, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_cache(self, data: dict[str, Any]) -> None:
        # Atomic write to handle basic concurrency
        tmp_path = self.filepath + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, self.filepath)

    def check_or_lock_signature(
        self, signature: str, tool_name: str, args: dict[str, Any], scenario_id: str
    ) -> tuple[bool, str]:
        """
        Check if the tool was already run. If not, lock it as RUNNING.
        Returns (is_blocked, error_message).
        """
        # We use a file lock to prevent race conditions between workers.
        lock_file = self.filepath + ".lock"
        with open(lock_file, "w") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_EX)
            try:
                cache = self._read_cache()
                entry = cache.get(signature)

                if entry:
                    if entry.get("status") == "RUNNING":
                        return True, f"This exact tool is currently being run by another worker. Wait or focus on a different task/target."
                    elif entry.get("status") == "COMPLETED":
                        return True, f"Duplicate tool invocation has a cached result: {entry.get('summary', 'Already completed.')}"
                
                # Lock it for this worker
                cache[signature] = {
                    "tool": tool_name,
                    "scenario_id": scenario_id,
                    "args": args,
                    "status": "RUNNING",
                    "summary": "",
                    "result": "",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                self._write_cache(cache)
                return False, ""
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)

    def get_completed_result(self, signature: str) -> dict[str, Any] | None:
        """Return a completed cache entry, if one exists."""
        cache = self._read_cache()
        entry = cache.get(signature)
        if not isinstance(entry, dict) or entry.get("status") != "COMPLETED":
            return None
        return dict(entry)

    def unlock_and_update(self, signature: str, summary: str, result: str = "") -> None:
        """Update the cache entry with the final summary."""
        lock_file = self.filepath + ".lock"
        with open(lock_file, "w") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_EX)
            try:
                cache = self._read_cache()
                if signature in cache:
                    cache[signature]["status"] = "COMPLETED"
                    cache[signature]["summary"] = summary
                    cache[signature]["result"] = str(result or "")
                    cache[signature]["updated_at"] = datetime.now(timezone.utc).isoformat()
                    self._write_cache(cache)
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)

    def unlock_and_fail(self, signature: str) -> None:
        """Release the lock if the tool failed, allowing it to be retried."""
        lock_file = self.filepath + ".lock"
        with open(lock_file, "w") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_EX)
            try:
                cache = self._read_cache()
                if signature in cache:
                    del cache[signature]
                    self._write_cache(cache)
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)

    def get_cache_summary(self) -> str:
        """Return a prompt-friendly string of past actions."""
        cache = self._read_cache()
        completed = [entry for entry in cache.values() if entry.get("status") == "COMPLETED"]
        if not completed:
            return ""
        
        lines = []
        for entry in completed:
            scenario = f"[{entry['scenario_id']}] " if entry.get('scenario_id') else ""
            lines.append(f"- {scenario}Ran {entry['tool']}: {entry['summary']}")
        
        return "\n".join(lines)
