from __future__ import annotations

import json
from datetime import datetime, timezone

import structlog

from server.core.tool import tool

from .constants import REDIS_INTEL_CHANNEL

logger = structlog.get_logger(__name__)


@tool(
    name="notify_planner",
    description=(
        "Send a notification event to the Planner agent via Redis pub/sub. "
        "Used to signal that new intelligence has been ingested and the planner "
        "should refresh its knowledge. Include a summary of what was updated."
    ),
)
async def notify_planner(
    summary: str,
    updated_domains: str = "",
    new_payload_count: int = 0,
    new_exploit_count: int = 0,
) -> str:
    event = {
        "type": "intel_update",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "updated_domains": [d.strip() for d in updated_domains.split(",") if d.strip()] if updated_domains else [],
        "stats": {
            "new_payloads": new_payload_count,
            "new_exploits": new_exploit_count,
        },
    }

    published = False
    try:
        import redis.asyncio as aioredis

        from server.config.database import db_config

        r = aioredis.from_url(db_config.redis_url)
        await r.publish(REDIS_INTEL_CHANNEL, json.dumps(event))
        await r.close()
        published = True
        logger.info("notify_planner_published", channel=REDIS_INTEL_CHANNEL)
    except Exception as exc:
        logger.warning("notify_planner_redis_unavailable", error=str(exc))

    result = {
        "notified": published,
        "event": event,
        "channel": REDIS_INTEL_CHANNEL,
    }
    return json.dumps(result, default=str)
