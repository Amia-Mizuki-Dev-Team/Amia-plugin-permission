from __future__ import annotations

from collections.abc import Iterable, Mapping

from src.plugins.amia_core import ResolvedIdentity


PermissionRules = Mapping[str, Iterable[str]]


class StaticPermissionProvider:
    """Minimal default-deny permission provider.

    Rules are keyed by permission node. Context-specific rules use
    ``<node>@<context_id>``. Values are identity selectors.
    """

    def __init__(self, rules: PermissionRules | None = None) -> None:
        self._rules: dict[str, frozenset[str]] = {
            str(node): frozenset(str(selector) for selector in selectors)
            for node, selectors in (rules or {}).items()
        }

    async def has_permission(
        self,
        identity: ResolvedIdentity,
        permission_node: str,
        context_id: str,
    ) -> bool:
        node = str(permission_node).strip()
        context = str(context_id).strip()
        if not node:
            return False

        selectors = self._identity_selectors(identity)
        rule_keys = (
            f"{node}@{context}" if context else None,
            node,
            f"*@{context}" if context else None,
            "*",
        )

        for rule_key in rule_keys:
            if rule_key is None:
                continue
            allowed = self._rules.get(rule_key)
            if not allowed:
                continue
            if "*" in allowed or selectors.intersection(allowed):
                return True

        return False

    def replace_rules(self, rules: PermissionRules) -> None:
        self._rules = {
            str(node): frozenset(str(selector) for selector in selectors)
            for node, selectors in rules.items()
        }

    @staticmethod
    def _identity_selectors(identity: ResolvedIdentity) -> set[str]:
        selectors = {
            (
                "external:"
                f"{identity.external_key.self_id}:"
                f"{identity.external_key.user_id}"
            ),
            f"opaque:{identity.opaque_id}",
        }
        if identity.canonical_user_id:
            selectors.add(f"canonical:{identity.canonical_user_id}")
        return selectors
