import re

with open("server/agents/assistant/agent.py", "r") as f:
    content = f.read()

# 1. Remove all `next_context = await self._build_next_context(...)` block usages
# This matches `next_context = await self._build_next_context(...)\n`
content = re.sub(
    r'([ \t]+)next_context = await self\._build_next_context\([\s\S]*?\)\n',
    '',
    content
)
# And replace the yielding of `next_context` variable with an empty string
content = re.sub(
    r'yield \{"type": "context", "data": \{"next_context": next_context\}\}',
    r'yield {"type": "context", "data": {"next_context": ""}}',
    content
)

with open("server/agents/assistant/agent.py", "w") as f:
    f.write(content)
