import asyncio
import json
import time

from server.agents.intel.agent import FORMATTER_ROUNDS, IntelAgent, IntelResult

TARGET_TYPE = "web"
INFO = "Target profile: public web app, auth flows, file upload and API-backed pages. Focus on ATT&CK/OWASP methodology and practical techniques."


async def test_parallel_pipeline() -> None:
    """Synthetic test: update pipeline and RAG snapshot should run in parallel."""

    class ParallelProbeAgent(IntelAgent):
        def __init__(self) -> None:
            super().__init__()
            self.update_started = asyncio.Event()
            self.rag_started = asyncio.Event()
            self.formatter_received: dict | None = None

        async def _run_update_pipeline(self, target_type: str, info: str) -> dict:
            self.update_started.set()
            await asyncio.sleep(0.2)
            return {
                "target_type": target_type,
                "info": info,
                "verified_sources": [],
                "stats": {
                    "new_payloads": 1,
                    "new_exploits": 0,
                    "total_embedded": 1,
                    "content_types_updated": ["attack_types"],
                    "domains_updated": [target_type],
                },
                "summary": "update pipeline done",
                "domains_considered": [target_type],
            }

        async def _collect_rag_snapshot(self, target_type: str) -> dict:
            self.rag_started.set()
            await asyncio.sleep(0.2)
            return {
                "query": f"{target_type} methodology techniques vulnerabilities",
                "domain": target_type,
                "results": {
                    "strategies": [{"id": "s1"}],
                    "attack_types": [{"id": "a1"}],
                    "exploits": [{"id": "e1"}],
                },
            }

        async def _run_formatter(self, target_type: str, info: str, pipeline_report: dict) -> IntelResult:
            self.formatter_received = pipeline_report
            return IntelResult(
                status="complete",
                summary="formatter ok",
                stats=pipeline_report.get("stats", {}),
            )

        async def _prepare_formatter_context(self, target_type: str, pipeline_report: dict) -> dict:
            # Keep synthetic test lightweight: no model load, no external search.
            return {
                "rag_prefetch": {},
                "coverage_counts": {"methods": 0, "techniques": 0, "vulnerabilities": 0},
                "web_fallback": {"used": False, "query": "", "results": []},
            }

    agent = ParallelProbeAgent()
    started = time.perf_counter()
    result = await agent.run(target_type="web", info="parallel test")
    elapsed = time.perf_counter() - started

    print("\n=== Synthetic Parallel Test ===")
    print(json.dumps(
        {
            "update_started": agent.update_started.is_set(),
            "rag_started": agent.rag_started.is_set(),
            "formatter_round_cap": FORMATTER_ROUNDS,
            "elapsed_seconds": round(elapsed, 3),
            "result_status": result.status,
            "merged_has_rag_snapshot": bool((agent.formatter_received or {}).get("rag_snapshot")),
            "merged_has_stats": bool((agent.formatter_received or {}).get("stats")),
        },
        indent=2,
        ensure_ascii=True,
    ))

async def main():
    await test_parallel_pipeline()

    agent = IntelAgent()
    result = await agent.run(target_type=TARGET_TYPE, info=INFO)

    stats = result.stats or {}
    total_embedded = int(stats.get("total_embedded", 0) or 0)
    new_payloads = int(stats.get("new_payloads", 0) or 0)
    new_exploits = int(stats.get("new_exploits", 0) or 0)
    action = "updated_rag" if total_embedded > 0 or new_payloads > 0 or new_exploits > 0 else "skipped_no_new_items"

    # Reuse already-initialized context to avoid reloading model and reinitializing clients.
    embedder = agent._context.embedder
    vector = agent._context.vector_store
    vector.ensure_all_collections()

    query = "web attack methodology techniques vulnerabilities exploitation"
    q = await embedder.embed_single(query, is_query=True)

    by_type = {}
    for ct in ("strategies", "attack_types", "exploits"):
        hits = vector.search(query_embedding=q, content_type=ct, domain="web", n_results=12)
        by_type[ct] = hits

    methods = set()
    techniques = set()
    vulns = set()

    keyword_map = {
        "xss": "XSS",
        "sql injection": "SQL Injection",
        "sqli": "SQL Injection",
        "ssrf": "SSRF",
        "ssti": "SSTI",
        "idor": "IDOR",
        "csrf": "CSRF",
        "xxe": "XXE",
        "request smuggling": "HTTP Request Smuggling",
        "open redirect": "Open Redirect",
        "deserialization": "Insecure Deserialization",
        "command injection": "Command Injection",
        "prototype pollution": "Prototype Pollution",
        "cache deception": "Web Cache Deception",
        "file upload": "Insecure File Upload",
        "waf bypass": "WAF Bypass",
    }

    for ct, hits in by_type.items():
        for h in hits:
            md = h.get("metadata", {}) or {}
            heading = str(md.get("heading") or "").strip()
            tags = md.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            content = (h.get("content") or "").lower()

            if ct == "strategies":
                if heading:
                    methods.add(heading)
                for t in tags:
                    methods.add(t)

            if ct == "attack_types":
                if heading:
                    techniques.add(heading)
                for t in tags:
                    techniques.add(t)

            if ct == "exploits":
                if heading:
                    vulns.add(heading)
                for t in tags:
                    vulns.add(t)

            for k, label in keyword_map.items():
                if k in content:
                    if ct == "strategies":
                        methods.add(label)
                    elif ct == "attack_types":
                        techniques.add(label)
                    else:
                        vulns.add(label)

    def top_items(s, limit=12):
        return sorted([x for x in s if x and len(x) < 120], key=lambda x: x.lower())[:limit]

    output = {
        "target_type": TARGET_TYPE,
        "info": INFO,
        "intel_result": {
            "status": result.status,
            "summary": result.summary,
            "stats": stats,
            "rag_action": action,
        },
        "rag_track": {
            "methods": top_items(methods),
            "techniques": top_items(techniques),
            "vulnerabilities": top_items(vulns),
            "counts": {
                "strategies_hits": len(by_type.get("strategies", [])),
                "attack_types_hits": len(by_type.get("attack_types", [])),
                "exploits_hits": len(by_type.get("exploits", [])),
            },
        },
    }

    print(json.dumps(output, indent=2, ensure_ascii=True))

asyncio.run(main())
