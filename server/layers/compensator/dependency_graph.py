"""Dependency graph model for agent execution layers."""

from __future__ import annotations

from collections import defaultdict, deque


class DependencyGraph:
    """Directed acyclic-style graph helper for execution dependencies."""

    def __init__(self) -> None:
        self._forward: dict[str, set[str]] = defaultdict(set)
        self._reverse: dict[str, set[str]] = defaultdict(set)

    def add_dependency(self, *, parent: str, child: str) -> None:
        self._forward[parent].add(child)
        self._reverse[child].add(parent)
        self._forward.setdefault(child, set())
        self._reverse.setdefault(parent, set())

    def dependents_of(self, node: str) -> list[str]:
        return sorted(self._forward.get(node, set()))

    def dependencies_of(self, node: str) -> list[str]:
        return sorted(self._reverse.get(node, set()))

    def topological_like_order(self) -> list[str]:
        in_degree: dict[str, int] = {
            node: len(parents) for node, parents in self._reverse.items()
        }
        queue = deque(sorted([node for node, d in in_degree.items() if d == 0]))
        order: list[str] = []

        while queue:
            node = queue.popleft()
            order.append(node)
            for child in sorted(self._forward.get(node, set())):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
        return order

