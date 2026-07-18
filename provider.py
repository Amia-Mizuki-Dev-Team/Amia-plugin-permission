from __future__ import annotations

import asyncio
import fnmatch
import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nonebot import require


logger = logging.getLogger(__name__)

PermissionRules = Mapping[str, Any] | Sequence[Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class PermissionRule:
    permission: str
    selector: str
    effect: str = "allow"
    scope: str | None = None
    expires_at: str | None = None
    priority: int = 0
    source: str = "config"

    @property
    def key(self) -> str:
        scope = f"@{self.scope}" if self.scope else ""
        return f"{self.effect}:{self.permission}{scope}:{self.selector}"


def _utc_expiry(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        current = value
    elif isinstance(value, str):
        current = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise TypeError("expires_at must be a datetime, ISO string, or None")
    if current.tzinfo is None:
        raise ValueError("expires_at must include a timezone")
    return current.astimezone(timezone.utc).isoformat()


def _is_expired(value: str | None, *, now: datetime | None = None) -> bool:
    if value is None:
        return False
    current = datetime.fromisoformat(value.replace("Z", "+00:00"))
    reference = now or datetime.now(timezone.utc)
    return current <= reference.astimezone(timezone.utc)


def _identity_selectors(identity: Any) -> set[str]:
    external_key = identity.external_key
    selectors = {
        f"external:{external_key.self_id}:{external_key.user_id}",
    }
    opaque_id = getattr(identity, "opaque_id", None)
    if opaque_id:
        selectors.add(f"opaque:{opaque_id}")
    canonical = getattr(identity, "canonical_user_id", None)
    if canonical:
        selectors.add(f"canonical:{canonical}")
    return selectors


def _actor_identity(identity: Any) -> str:
    canonical = getattr(identity, "canonical_user_id", None)
    if canonical:
        return f"canonical:{canonical}"
    key = identity.external_key
    return f"external:{key.self_id}:{key.user_id}"


class StaticPermissionProvider:
    """Default-deny permission provider with deterministic rule precedence.

    Rule precedence is: blacklist, explicit deny, configured superuser,
    scoped allow, global allow.  A configured whitelist is a gate before
    normal rules.  Superuser bypass is opt-in through configuration and is not
    silently enabled by a user's display name.
    """

    def __init__(
        self,
        rules: PermissionRules | None = None,
        *,
        audit_required: bool = False,
        superuser_bypass_denies: bool = False,
    ) -> None:
        self._rules: list[PermissionRule] = []
        self._rule_index: dict[str, list[PermissionRule]] = {}
        self._wildcard_rules: list[PermissionRule] = []
        self._decision_cache: dict[tuple[tuple[str, ...], str, str], dict[str, Any]] = {}
        self._superusers: set[str] = set()
        self._blacklist: set[str] = set()
        self._whitelist: set[str] = set()
        self._audit_required = audit_required
        self._superuser_bypass_denies = superuser_bypass_denies
        self._lock = asyncio.Lock()
        self.replace_rules(rules or {})

    def configure_policy(
        self,
        *,
        audit_required: bool | None = None,
        superuser_bypass_denies: bool | None = None,
    ) -> None:
        if audit_required is not None:
            self._audit_required = bool(audit_required)
        if superuser_bypass_denies is not None:
            self._superuser_bypass_denies = bool(superuser_bypass_denies)

    def replace_rules(self, rules: PermissionRules) -> None:
        parsed: list[PermissionRule] = []
        superusers: set[str] = set()
        blacklist: set[str] = set()
        whitelist: set[str] = set()

        if isinstance(rules, Mapping):
            for selector in _as_selectors(rules.get("superusers", ())):
                superusers.add(selector)
            blacklist.update(_as_selectors(rules.get("blacklist", ())))
            whitelist.update(_as_selectors(rules.get("whitelist", ())))

            for raw_rule in _as_rule_sequence(rules.get("rules", ())):
                parsed.extend(self._parse_structured_rule(raw_rule))

            roles = rules.get("roles", {})
            if isinstance(roles, Mapping):
                for role_name, role_value in roles.items():
                    if not isinstance(role_value, Mapping):
                        continue
                    permissions = role_value.get("permissions", ())
                    selectors = _as_selectors(role_value.get("selectors", ()))
                    scope = role_value.get("scope")
                    expires_at = _utc_expiry(role_value.get("expires_at"))
                    for selector in selectors:
                        for permission in _as_strings(permissions):
                            parsed.append(
                                PermissionRule(
                                    permission=permission,
                                    selector=selector,
                                    scope=None if scope is None else str(scope),
                                    expires_at=expires_at,
                                    priority=20,
                                    source=f"role:{role_name}",
                                )
                            )

            for raw_rule in _as_rule_sequence(rules.get("role_bindings", ())):
                if not isinstance(raw_rule, Mapping):
                    continue
                role_name = str(raw_rule.get("role", "")).strip()
                role_value = roles.get(role_name) if isinstance(roles, Mapping) else None
                if not isinstance(role_value, Mapping):
                    continue
                selectors = _as_selectors(raw_rule.get("selectors", ()))
                if not selectors:
                    selectors = _as_selectors(role_value.get("selectors", ()))
                scope = raw_rule.get("scope", role_value.get("scope"))
                expires_at = _utc_expiry(raw_rule.get("expires_at", role_value.get("expires_at")))
                for selector in selectors:
                    for permission in _as_strings(role_value.get("permissions", ())):
                        parsed.append(
                            PermissionRule(
                                permission=permission,
                                selector=selector,
                                scope=None if scope is None else str(scope),
                                expires_at=expires_at,
                                priority=20,
                                source=f"role:{role_name}",
                            )
                        )

            reserved = {
                "rules",
                "roles",
                "role_bindings",
                "superusers",
                "blacklist",
                "whitelist",
            }
            for node, selectors in rules.items():
                if str(node) in reserved:
                    continue
                parsed.extend(self._parse_legacy_rule(str(node), selectors))
        elif isinstance(rules, Sequence) and not isinstance(rules, (str, bytes)):
            for raw_rule in rules:
                if isinstance(raw_rule, Mapping):
                    parsed.extend(self._parse_structured_rule(raw_rule))

        self._rules = parsed
        self._superusers = superusers
        self._blacklist = blacklist
        self._whitelist = whitelist
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        self._rule_index = {}
        self._wildcard_rules = []
        self._decision_cache.clear()
        for rule in self._rules:
            if any(character in rule.permission for character in "*?["):
                self._wildcard_rules.append(rule)
            else:
                self._rule_index.setdefault(rule.permission, []).append(rule)

    def _parse_legacy_rule(self, node: str, selectors: Any) -> list[PermissionRule]:
        permission, scope = _split_rule_key(node)
        return [
            PermissionRule(
                permission=permission,
                selector=selector,
                scope=scope,
                source="config",
            )
            for selector in _as_selectors(selectors)
        ]

    def _parse_structured_rule(self, value: Mapping[str, Any]) -> list[PermissionRule]:
        permission = str(value.get("permission", value.get("node", ""))).strip()
        if not permission:
            return []
        if "@" in permission and value.get("scope") is None:
            permission, parsed_scope = _split_rule_key(permission)
        else:
            parsed_scope = value.get("scope")
        effect = str(value.get("effect", "allow")).strip().lower()
        if effect not in {"allow", "deny"}:
            return []
        selectors = _as_selectors(value.get("selectors", value.get("selector", ())))
        expires_at = _utc_expiry(value.get("expires_at"))
        try:
            priority = int(value.get("priority", 100 if effect == "deny" else 0))
        except (TypeError, ValueError):
            priority = 0
        return [
            PermissionRule(
                permission=permission,
                selector=selector,
                effect=effect,
                scope=None if parsed_scope is None else str(parsed_scope),
                expires_at=expires_at,
                priority=priority,
                source=str(value.get("source", "config")),
            )
            for selector in selectors
        ]

    async def check_permission(
        self,
        identity: Any,
        permission_node: str,
        context_id: str = "",
    ) -> dict[str, Any]:
        node = str(permission_node).strip()
        context = str(context_id).strip()
        if not node:
            return _decision(False, "invalid_permission", None)

        selectors = _identity_selectors(identity)
        cache_key = (tuple(sorted(selectors)), node, context)
        async with self._lock:
            cached = self._decision_cache.get(cache_key)
            if cached is not None:
                return dict(cached)

            def finish(decision: dict[str, Any]) -> dict[str, Any]:
                self._decision_cache[cache_key] = decision
                return decision

            if self._matches_selector(selectors, self._blacklist):
                return finish(_decision(False, "blacklisted", "blacklist"))
            if self._whitelist and not self._matches_selector(selectors, self._whitelist):
                return finish(_decision(False, "not_whitelisted", "whitelist"))

            candidate_rules = self._rule_index.get(node, []) + self._wildcard_rules
            matching = [
                rule
                for rule in candidate_rules
                if not _is_expired(rule.expires_at)
                and self._rule_matches(rule, node, context, selectors)
            ]
            denies = [rule for rule in matching if rule.effect == "deny"]
            if denies:
                selected = max(denies, key=self._specificity)
                if not self._superuser_bypass_denies:
                    return finish(_decision(False, "explicit_deny", selected.key, selected.expires_at))
            if self._matches_selector(selectors, self._superusers):
                return finish(_decision(True, "superuser", "superuser"))
            if denies:
                selected = max(denies, key=self._specificity)
                return finish(_decision(False, "explicit_deny", selected.key, selected.expires_at))
            allows = [rule for rule in matching if rule.effect == "allow"]
            if allows:
                selected = max(allows, key=self._specificity)
                return finish(_decision(True, "matched_rule", selected.key, selected.expires_at))
            return finish(_decision(False, "no_matching_rule", None))

    async def has_permission(
        self,
        identity: Any,
        permission_node: str,
        context_id: str = "",
    ) -> bool:
        node = str(permission_node).strip()
        context = str(context_id).strip()
        if node:
            selectors = _identity_selectors(identity)
            cached = self._decision_cache.get(
                (tuple(sorted(selectors)), node, context)
            )
            if cached is not None:
                return bool(cached["allowed"])
        decision = await self.check_permission(identity, permission_node, context_id)
        return bool(decision["allowed"])

    async def require_permission(
        self,
        identity: Any,
        permission_node: str,
        context_id: str = "",
    ) -> dict[str, Any]:
        decision = await self.check_permission(identity, permission_node, context_id)
        if not decision["allowed"]:
            raise PermissionError(
                f"permission denied: {permission_node} ({decision['reason']})"
            )
        return decision

    async def grant_permission(
        self,
        permission_node: str,
        selector: str,
        *,
        context_id: str = "",
        expires_at: datetime | str | None = None,
        actor: Any | None = None,
        audit_required: bool | None = None,
    ) -> dict[str, Any]:
        rule = PermissionRule(
            permission=str(permission_node).strip(),
            selector=str(selector).strip(),
            scope=str(context_id).strip() or None,
            expires_at=_utc_expiry(expires_at),
            source="runtime",
        )
        if not rule.permission or not rule.selector:
            raise ValueError("permission_node and selector are required")
        async with self._lock:
            previous = list(self._rules)
            self._rules.append(rule)
            self._rebuild_index()
            audited = await self._audit_change(
                action="permission.grant",
                rule=rule,
                actor=actor,
                required=self._audit_required if audit_required is None else audit_required,
            )
            if not audited:
                self._rules = previous
                self._rebuild_index()
                raise RuntimeError("permission change was not audited")
        return _rule_dict(rule)

    async def revoke_permission(
        self,
        permission_node: str,
        selector: str,
        *,
        context_id: str = "",
        actor: Any | None = None,
        audit_required: bool | None = None,
    ) -> int:
        node = str(permission_node).strip()
        wanted_selector = str(selector).strip()
        scope = str(context_id).strip() or None
        async with self._lock:
            removed = [
                rule
                for rule in self._rules
                if rule.permission == node
                and rule.selector == wanted_selector
                and rule.scope == scope
                and rule.source == "runtime"
            ]
            if not removed:
                return 0
            previous = list(self._rules)
            self._rules = [rule for rule in self._rules if rule not in removed]
            self._rebuild_index()
            audited = await self._audit_change(
                action="permission.revoke",
                rule=removed[0],
                actor=actor,
                required=self._audit_required if audit_required is None else audit_required,
            )
            if not audited:
                self._rules = previous
                self._rebuild_index()
                raise RuntimeError("permission change was not audited")
            return len(removed)

    async def list_permissions(
        self,
        *,
        selector: str | None = None,
        context_id: str | None = None,
        include_expired: bool = False,
    ) -> list[dict[str, Any]]:
        async with self._lock:
            rules = list(self._rules)
        result = []
        for rule in rules:
            if selector is not None and rule.selector != selector:
                continue
            if context_id is not None and rule.scope != (context_id or None):
                continue
            if not include_expired and _is_expired(rule.expires_at):
                continue
            result.append(_rule_dict(rule))
        return sorted(result, key=lambda item: item["matched_rule"])

    async def clear_expired(self) -> int:
        async with self._lock:
            before = len(self._rules)
            self._rules = [rule for rule in self._rules if not _is_expired(rule.expires_at)]
            self._rebuild_index()
            return before - len(self._rules)

    async def health_check(self) -> dict[str, Any]:
        async with self._lock:
            active = sum(not _is_expired(rule.expires_at) for rule in self._rules)
            return {
                "ok": True,
                "status": "ready",
                "active_rules": active,
                "superusers": len(self._superusers),
                "blacklist": len(self._blacklist),
                "whitelist": len(self._whitelist),
            }

    async def _audit_change(
        self,
        *,
        action: str,
        rule: PermissionRule,
        actor: Any | None,
        required: bool,
    ) -> bool:
        if actor is None:
            if required:
                return False
            return True
        try:
            core = require("amia_core")
            audit = (
                core.registry.get_audit_logger("sqlite")
                or core.registry.get_audit_logger("local_file")
            )
            if audit is None:
                return not required
            target = f"permission:{rule.permission}"
            metadata = {
                "scope": rule.scope or "global",
                "result": "success",
                "source": rule.source,
                "expires_at": rule.expires_at,
            }
            if hasattr(audit, "record_event"):
                result = await audit.record_event(
                    action=action,
                    target_type="permission",
                    target_identity=target,
                    actor_identity=_actor_identity(actor),
                    scope=rule.scope or "global",
                    metadata=metadata,
                )
                return result is not None or not required
            await audit.log_action(actor, action, target, metadata)
            return True
        except Exception:
            logger.exception("permission audit failed action=%s", action)
            return not required

    def _rule_matches(
        self,
        rule: PermissionRule,
        node: str,
        context: str,
        selectors: set[str],
    ) -> bool:
        if rule.scope is not None and rule.scope != context:
            return False
        if not _pattern_matches(rule.permission, node):
            return False
        return rule.selector == "*" or bool(selectors.intersection({rule.selector}))

    @staticmethod
    def _specificity(rule: PermissionRule) -> tuple[int, int, int, str]:
        return (
            rule.priority,
            2 if rule.scope is not None else 1,
            2 if rule.permission != "*" else 1,
            rule.key,
        )

    @staticmethod
    def _matches_selector(selectors: set[str], configured: set[str]) -> bool:
        return "*" in configured or bool(selectors.intersection(configured))


def _pattern_matches(pattern: str, node: str) -> bool:
    return fnmatch.fnmatchcase(node, pattern)


def _split_rule_key(value: str) -> tuple[str, str | None]:
    if "@" not in value:
        return value.strip(), None
    permission, scope = value.split("@", 1)
    return permission.strip(), scope.strip() or None


def _as_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, Iterable) and not isinstance(value, (bytes, Mapping)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _as_selectors(value: Any) -> set[str]:
    return set(_as_strings(value))


def _as_rule_sequence(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _decision(
    allowed: bool,
    reason: str,
    matched_rule: str | None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    return {
        "allowed": allowed,
        "reason": reason,
        "matched_rule": matched_rule,
        "expires_at": expires_at,
    }


def _rule_dict(rule: PermissionRule) -> dict[str, Any]:
    return {
        "permission": rule.permission,
        "selector": rule.selector,
        "effect": rule.effect,
        "scope": rule.scope,
        "expires_at": rule.expires_at,
        "matched_rule": rule.key,
        "source": rule.source,
    }
