from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from typing import Any

from nonebot import get_driver, require
from nonebot.plugin import PluginMetadata

_core = require("amia_core")
registry = _core.registry

from .provider import StaticPermissionProvider


__plugin_meta__ = PluginMetadata(
    name="Amia Permission",
    description="Default-deny, scoped permission evaluation and grants.",
    usage="No user-facing matcher; other plugins use the public API or Core Registry.",
    type="application",
    supported_adapters=set(),
)

logger = logging.getLogger(__name__)
driver = get_driver()
permission_provider = StaticPermissionProvider()


def _load_rules(value: Any) -> Mapping[str, Any] | Sequence[Mapping[str, Any]]:
    if isinstance(value, str):
        if not value.strip():
            return {}
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            logger.warning("AMIA_PERMISSION_RULES is not valid JSON")
            return {}
    if isinstance(value, Mapping):
        return value
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [item for item in value if isinstance(item, Mapping)]
    return {}


@driver.on_startup
async def _register_permission_provider() -> None:
    configured_rules = getattr(driver.config, "amia_permission_rules", {})
    permission_provider.configure_policy(
        audit_required=bool(getattr(driver.config, "amia_permission_audit_required", False)),
        superuser_bypass_denies=bool(
            getattr(driver.config, "amia_permission_superuser_bypass_denies", False)
        ),
    )
    permission_provider.replace_rules(_load_rules(configured_rules))
    registry.register_permission_provider("static", permission_provider, replace=True)
    logger.info("registered static permission provider")


async def check_permission(identity: Any, permission_node: str, context_id: str = "") -> dict[str, Any]:
    return await permission_provider.check_permission(identity, permission_node, context_id)


async def require_permission(identity: Any, permission_node: str, context_id: str = "") -> dict[str, Any]:
    return await permission_provider.require_permission(identity, permission_node, context_id)


async def grant_permission(permission_node: str, selector: str, **kwargs: Any) -> dict[str, Any]:
    return await permission_provider.grant_permission(permission_node, selector, **kwargs)


async def revoke_permission(permission_node: str, selector: str, **kwargs: Any) -> int:
    return await permission_provider.revoke_permission(permission_node, selector, **kwargs)


async def list_permissions(**kwargs: Any) -> list[dict[str, Any]]:
    return await permission_provider.list_permissions(**kwargs)


async def health_check() -> dict[str, Any]:
    return await permission_provider.health_check()
