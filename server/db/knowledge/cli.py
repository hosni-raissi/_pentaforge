"""
CLI runner for the PentaForge cybersecurity knowledge base.

Usage:
    # Ingest a single source
    python -m server.db.knowledge.cli ingest --source HackTricks

    # Ingest all sources for a domain
    python -m server.db.knowledge.cli ingest --domain web

    # Ingest all enabled sources
    python -m server.db.knowledge.cli ingest --all

    # Search the knowledge base (auto-includes vector_shared)
    python -m server.db.knowledge.cli search "SQL injection bypass WAF" --domain web

    # On-demand CVE lookup
    python -m server.db.knowledge.cli cve lookup CVE-2024-3094

    # Search CVEs by keyword
    python -m server.db.knowledge.cli cve search "Apache Tomcat" --severity CRITICAL

    # Pre-seed CRITICAL CVEs
    python -m server.db.knowledge.cli cve seed

    # Show statistics
    python -m server.db.knowledge.cli stats

    # List available sources
    python -m server.db.knowledge.cli sources
    python -m server.db.knowledge.cli sources --domain web

    # Delete a source
    python -m server.db.knowledge.cli delete --source HackTricks

    # Reset entire knowledge base
    python -m server.db.knowledge.cli reset --confirm
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import json

import structlog

from server.db.knowledge.config.sources import (
    ALL_SOURCES,
    get_enabled_sources,
    get_sources_by_domain,
    get_all_domains,
)
from server.db.knowledge.orchestrator import KnowledgeOrchestrator

logger = structlog.get_logger(__name__)

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(colors=True),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pentaforge-knowledge",
        description="PentaForge Cybersecurity RAG Knowledge Base",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── ingest ────────────────────────────────────────────────────────
    ingest_p = sub.add_parser("ingest", help="Ingest knowledge sources")
    ingest_group = ingest_p.add_mutually_exclusive_group(required=True)
    ingest_group.add_argument(
        "--source", "-s",
        type=str,
        help="Source name to ingest (e.g. HackTricks)",
    )
    ingest_group.add_argument(
        "--domain", "-d",
        type=str,
        help="Ingest all sources for a domain (e.g. web, api, cloud)",
    )
    ingest_group.add_argument(
        "--all", "-a",
        action="store_true",
        dest="all_sources",
        help="Ingest all enabled sources",
    )
    ingest_p.add_argument(
        "--concurrency", "-c",
        type=int,
        default=1,
        help="Number of sources to ingest concurrently (default: 1)",
    )

    # ── search ────────────────────────────────────────────────────────
    search_p = sub.add_parser("search", help="Search the knowledge base")
    search_p.add_argument("query", type=str, help="Search query")
    search_p.add_argument(
        "--domain", "-d", type=str, default=None,
        help="Search within a domain (+ shared). Omit to search all.",
    )
    search_p.add_argument(
        "--source", "-s", type=str, default=None, help="Filter by source name"
    )
    search_p.add_argument(
        "-n", "--num-results", type=int, default=5, help="Number of results"
    )

    # ── stats ─────────────────────────────────────────────────────────
    sub.add_parser("stats", help="Show knowledge base statistics")

    # ── sources ───────────────────────────────────────────────────────
    sources_p = sub.add_parser("sources", help="List available knowledge sources")
    sources_p.add_argument(
        "--domain", "-d", type=str, default=None,
        help="Filter sources by domain",
    )

    # ── delete ────────────────────────────────────────────────────────
    delete_p = sub.add_parser("delete", help="Delete a source from the knowledge base")
    delete_p.add_argument(
        "--source", "-s", type=str, required=True, help="Source name to delete"
    )

    # ── cve (on-demand NVD lookups) ──────────────────────────────────
    cve_p = sub.add_parser("cve", help="On-demand NVD CVE lookup & search")
    cve_sub = cve_p.add_subparsers(dest="cve_command", help="CVE sub-commands")

    # cve lookup CVE-2024-3094
    cve_lookup = cve_sub.add_parser("lookup", help="Lookup a specific CVE by ID")
    cve_lookup.add_argument("cve_id", type=str, help="CVE ID (e.g. CVE-2024-3094)")

    # cve search "Apache Tomcat" --severity CRITICAL
    cve_search = cve_sub.add_parser("search", help="Search CVEs by product/keyword")
    cve_search.add_argument("keyword", type=str, help="Product or keyword to search")
    cve_search.add_argument(
        "--severity", type=str, default="CRITICAL",
        help="CVSS severity: CRITICAL, HIGH, MEDIUM, LOW (default: CRITICAL)",
    )
    cve_search.add_argument(
        "-n", "--max-results", type=int, default=20, help="Max CVEs to fetch"
    )
    cve_search.add_argument(
        "--days", type=int, default=365, help="Lookback period in days"
    )

    # cve seed
    cve_seed = cve_sub.add_parser(
        "seed", help="Pre-populate CRITICAL CVEs for common pentest targets"
    )
    cve_seed.add_argument(
        "--severity", type=str, default="CRITICAL", help="CVSS severity filter"
    )
    cve_seed.add_argument(
        "--days", type=int, default=90, help="Lookback period in days"
    )

    # ── reset ─────────────────────────────────────────────────────────
    reset_p = sub.add_parser("reset", help="Reset the entire knowledge base")
    reset_p.add_argument(
        "--confirm",
        action="store_true",
        required=True,
        help="Confirm destructive reset",
    )

    return parser


# ── Command handlers ──────────────────────────────────────────────────────


async def cmd_ingest(args: argparse.Namespace) -> int:
    """Handle 'ingest' command."""
    orchestrator = KnowledgeOrchestrator()
    await orchestrator.initialize()

    try:
        if args.all_sources:
            results = await orchestrator.ingest_all(concurrency=args.concurrency)
        elif hasattr(args, 'domain') and args.domain:
            results = await orchestrator.ingest_domain(args.domain, concurrency=args.concurrency)
        else:
            result = await orchestrator.ingest_source(args.source)
            results = [result]

        print("\n" + "=" * 80)
        print(f"{'Source':<30} {'Domain':<12} {'Docs':>6} {'Chunks':>8} {'Skip':>6} {'Time':>8} {'Status'}")
        print("-" * 80)

        for r in results:
            status = "OK" if r.success else ("WARN" if r.documents_extracted > 0 else "FAIL")
            print(
                f"{r.source_name:<30} {r.domain:<12} {r.documents_extracted:>6} "
                f"{r.chunks_created:>8} {r.skipped_existing:>6} "
                f"{r.duration_seconds:>7.1f}s {status}"
            )
            for err in r.errors:
                print(f"  ERROR: {err}")

        print("=" * 80)

        failed = sum(1 for r in results if not r.success and r.documents_extracted == 0)
        return 1 if failed > 0 else 0

    finally:
        await orchestrator.close()


async def cmd_search(args: argparse.Namespace) -> int:
    """Handle 'search' command."""
    orchestrator = KnowledgeOrchestrator()
    await orchestrator.initialize()

    try:
        results = await orchestrator.search(
            query=args.query,
            domain=args.domain,
            source_name=args.source,
            n_results=args.num_results,
        )

        if not results:
            print("No results found.")
            return 0

        for i, hit in enumerate(results, 1):
            meta = hit.get("metadata", {})
            distance = hit.get("distance", "?")
            print(f"\n{'─' * 60}")
            print(f"  [{i}] Score: {1 - (distance or 0):.4f}  |  Source: {meta.get('source_name', '?')}")
            print(f"  File: {meta.get('file_path', 'N/A')}")
            print(f"  Domain: {meta.get('domain', '?')}  |  Tags: {meta.get('tags', '')}")
            print(f"{'─' * 60}")
            content = hit.get("content", "")
            if len(content) > 500:
                content = content[:500] + "..."
            print(content)

        print(f"\n{len(results)} results returned.")
        return 0

    finally:
        await orchestrator.close()


async def cmd_stats(args: argparse.Namespace) -> int:
    """Handle 'stats' command."""
    orchestrator = KnowledgeOrchestrator()
    await orchestrator.initialize()

    try:
        stats = await orchestrator.get_stats()
        print(json.dumps(stats, indent=2, default=str))
        return 0
    finally:
        await orchestrator.close()


async def cmd_sources(args: argparse.Namespace) -> int:
    """Handle 'sources' command."""
    sources = ALL_SOURCES
    if args.domain:
        sources = get_sources_by_domain(args.domain)

    print(f"\n{'Name':<30} {'Domain':<12} {'Type':<15} {'Enabled':<8} {'URL'}")
    print("-" * 100)

    for cfg in sources:
        print(
            f"{cfg.name:<30} {cfg.domain:<12} {cfg.source_type.value:<15} "
            f"{'yes' if cfg.enabled else 'no':<8} {cfg.url}"
        )

    enabled = len([s for s in sources if s.enabled])
    print(f"\n{len(sources)} sources listed, {enabled} enabled.")
    if not args.domain:
        domains = get_all_domains()
        print(f"Domains: {', '.join(domains)}")
    return 0


async def cmd_delete(args: argparse.Namespace) -> int:
    """Handle 'delete' command."""
    orchestrator = KnowledgeOrchestrator()
    await orchestrator.initialize()

    try:
        await orchestrator.delete_source(args.source)
        print(f"Deleted source: {args.source}")
        return 0
    finally:
        await orchestrator.close()


async def cmd_reset(args: argparse.Namespace) -> int:
    """Handle 'reset' command."""
    orchestrator = KnowledgeOrchestrator()
    await orchestrator.initialize()

    try:
        orchestrator.vector_store.reset()
        # Delete all sources from PG
        for cfg in ALL_SOURCES:
            await orchestrator.pg_store.delete_by_source(cfg.name)

        print("Knowledge base reset complete.")
        return 0
    finally:
        await orchestrator.close()


async def cmd_cve(args: argparse.Namespace) -> int:
    """Handle 'cve' sub-commands (on-demand NVD lookups)."""
    orchestrator = KnowledgeOrchestrator()
    await orchestrator.initialize()

    try:
        if args.cve_command == "lookup":
            doc = await orchestrator.lookup_cve(args.cve_id)
            if doc:
                print(f"\n{'=' * 60}")
                print(f"  {doc.title}")
                print(f"  URL: {doc.metadata.source_url}")
                print(f"  Domain: {doc.domain}  |  Category: {doc.category}")
                print(f"  Tags: {', '.join(doc.tags[:10])}")
                print(f"{'=' * 60}")
                print(doc.content[:2000])
                if len(doc.content) > 2000:
                    print(f"\n... ({len(doc.content) - 2000} more chars)")
            else:
                print(f"CVE {args.cve_id} not found.")
            return 0

        elif args.cve_command == "search":
            result = await orchestrator.nvd.search_product(
                keyword=args.keyword,
                severity=args.severity,
                days_back=args.days,
                max_results=args.max_results,
            )
            print(f"\nNVD search: '{args.keyword}' | severity={args.severity} | days={args.days}")
            print(f"Fetched: {result.fetched} | Cached: {result.cached} | Total: {result.total}")
            print("-" * 70)
            for doc in result.documents:
                extra = doc.extra or {}
                print(
                    f"  {extra.get('cve_id', doc.title):<20} "
                    f"CVSS {extra.get('cvss_score', '?'):>4}  "
                    f"{extra.get('cvss_severity', '?'):<10} "
                    f"{doc.title[:50]}"
                )
            return 0

        elif args.cve_command == "seed":
            print(f"Seeding CRITICAL CVEs for common pentest targets (last {args.days} days)...")
            print("This may take a while due to NVD rate limits.\n")
            summary = await orchestrator.seed_nvd()

            print(f"\n{'Keyword':<30} {'Fetched':>8} {'Cached':>8} {'Total':>8}")
            print("-" * 58)
            for kw, stats in summary.items():
                print(f"{kw:<30} {stats['fetched']:>8} {stats['cached']:>8} {stats['total']:>8}")

            total = sum(s["fetched"] for s in summary.values())
            print(f"\nTotal new CVEs ingested: {total}")
            return 0

        else:
            print("Usage: pentaforge-knowledge cve {lookup|search|seed}")
            return 1

    finally:
        await orchestrator.close()


# ── Main ──────────────────────────────────────────────────────────────────


async def async_main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    handlers = {
        "ingest": cmd_ingest,
        "search": cmd_search,
        "stats": cmd_stats,
        "sources": cmd_sources,
        "delete": cmd_delete,
        "reset": cmd_reset,
        "cve": cmd_cve,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return await handler(args)


def main() -> None:
    exit_code = asyncio.run(async_main())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
