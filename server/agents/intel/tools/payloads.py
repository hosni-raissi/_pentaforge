from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from server.core.tool import tool
from server.db.knowledge.config.settings import settings

from .constants import GITHUB_API

logger = structlog.get_logger(__name__)
_GITHUB_AUTH_ALLOWED = True


def _github_headers(*, include_auth: bool = True) -> dict[str, str]:
    headers = {
        "User-Agent": settings.user_agent,
        "Accept": "application/vnd.github+json",
    }
    token = settings.github_token or os.getenv("GITHUB_TOKEN", "")
    if include_auth and _GITHUB_AUTH_ALLOWED and token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _is_rate_limited(exc: Exception) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        if response.status_code == 403:
            remaining = response.headers.get("X-RateLimit-Remaining", "")
            if remaining == "0":
                return True
            try:
                msg = response.json().get("message", "")
            except Exception:
                msg = response.text
            if "rate limit" in str(msg).lower():
                return True
    return False


def _is_auth_failed(exc: Exception) -> bool:
    return isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 401


def _matches_category(path: str, category: str) -> bool:
    if not category:
        return True
    return category.lower() in path.lower()


def _file_to_result(f: dict, repo: dict[str, str], commit: dict) -> dict[str, Any]:
    path = f.get("filename", "")
    return {
        "repo": f"{repo['owner']}/{repo['repo']}",
        "path": path,
        "status": f.get("status", "modified"),
        "additions": f.get("additions", 0),
        "deletions": f.get("deletions", 0),
        "commit_date": commit.get("commit", {}).get("committer", {}).get("date", ""),
        "commit_message": commit.get("commit", {}).get("message", "")[:200],
        "raw_url": f"https://raw.githubusercontent.com/{repo['owner']}/{repo['repo']}/{repo['branch']}/{path}",
    }


async def _fetch_commit_detail(
    client: httpx.AsyncClient,
    repo: dict[str, str],
    sha: str,
    headers: dict[str, str],
    diagnostics: dict[str, Any],
) -> dict | None:
    try:
        resp = await client.get(
            f"{GITHUB_API}/repos/{repo['owner']}/{repo['repo']}/commits/{sha}",
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        diagnostics["rate_limited"] = diagnostics.get("rate_limited", False) or _is_rate_limited(exc)
        diagnostics.setdefault("errors", []).append({"repo": repo["repo"], "error": str(exc)})
        return None


def _collect_md_files(
    detail: dict,
    commit: dict,
    repo: dict[str, str],
    category: str,
    seen_paths: set[str],
    limit: int,
    current_count: int,
) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for f in detail.get("files", []):
        path = f.get("filename", "")
        if not path.endswith(".md") or path in seen_paths:
            continue
        if not _matches_category(path, category):
            continue
        seen_paths.add(path)
        collected.append(_file_to_result(f, repo, commit))
        if current_count + len(collected) >= limit:
            break
    return collected


async def _scan_commit_files(
    client: httpx.AsyncClient,
    repo: dict[str, str],
    commits: list[dict],
    category: str,
    limit: int,
    headers: dict[str, str],
    diagnostics: dict[str, Any],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for commit in commits:
        sha = commit.get("sha", "")
        if not sha:
            continue
        detail = await _fetch_commit_detail(client, repo, sha, headers, diagnostics)
        if not detail:
            continue
        collected = _collect_md_files(detail, commit, repo, category, seen_paths, limit, len(results))
        results.extend(collected)
        if len(results) >= limit:
            break
    return results


@tool(
    name="fetch_payloads",
    description=(
        "Fetch new techniques and payloads from PayloadsAllTheThings and HackTricks repos "
        "via the GitHub API. Accepts a category filter (e.g. 'XSS Injection', 'SQL Injection'). "
        "Returns recently updated files as JSON."
    ),
)
async def fetch_payloads(
    category: str = "",
    days_back: int = 30,
    max_results: int = 20,
) -> str:
    repos = [
        {"owner": "swisskyrepo", "repo": "PayloadsAllTheThings", "branch": "master"},
        {"owner": "HackTricks-wiki", "repo": "hacktricks", "branch": "master"},
    ]
    results: list[dict[str, Any]] = []
    since = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()

    rate_limited = False
    errors: list[dict[str, str]] = []

    global _GITHUB_AUTH_ALLOWED
    use_auth = _GITHUB_AUTH_ALLOWED and bool(settings.github_token or os.getenv("GITHUB_TOKEN", ""))
    active_headers = _github_headers(include_auth=use_auth)
    async with httpx.AsyncClient(timeout=30) as client:
        for r in repos:
            url = f"{GITHUB_API}/repos/{r['owner']}/{r['repo']}/commits"
            params: dict[str, str] = {"since": since, "per_page": "30", "sha": r["branch"]}
            try:
                resp = await client.get(url, params=params, headers=active_headers)
                resp.raise_for_status()
                commits = resp.json()
            except Exception as exc:
                if use_auth and _is_auth_failed(exc):
                    logger.warning(
                        "github_auth_failed_fallback_anonymous",
                        repo=r["repo"],
                        message="GitHub token rejected; retrying without Authorization header.",
                    )
                    _GITHUB_AUTH_ALLOWED = False
                    use_auth = False
                    active_headers = _github_headers(include_auth=False)
                    try:
                        resp = await client.get(url, params=params, headers=active_headers)
                        resp.raise_for_status()
                        commits = resp.json()
                    except Exception as retry_exc:
                        logger.warning("fetch_payloads_commits_error", repo=r["repo"], error=str(retry_exc))
                        if _is_rate_limited(retry_exc):
                            rate_limited = True
                        errors.append({"repo": r["repo"], "error": str(retry_exc)})
                        continue
                else:
                    logger.warning("fetch_payloads_commits_error", repo=r["repo"], error=str(exc))
                    if _is_rate_limited(exc):
                        rate_limited = True
                    errors.append({"repo": r["repo"], "error": str(exc)})
                    continue

            diagnostics = {"rate_limited": False, "errors": []}
            changed = await _scan_commit_files(
                client,
                r,
                commits,
                category,
                max_results - len(results),
                active_headers,
                diagnostics,
            )
            results.extend(changed)
            rate_limited = rate_limited or bool(diagnostics.get("rate_limited", False))
            errors.extend(diagnostics.get("errors", []))
            await asyncio.sleep(1)

    logger.info("fetch_payloads_done", count=len(results), category=category)
    return json.dumps(
        {
            "payloads": results[:max_results],
            "total": len(results),
            "rate_limited": rate_limited,
            "errors": errors,
        },
        default=str,
    )
