from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any

from nonebot import get_driver
from nonebot.plugin import PluginMetadata

from src.plugins.amia_core import registry

from .provider import StaticPermissionProvider


__plugin_meta__ = PluginMetadata(
    name="权限服务",
    description="为 Amia 插件生态提供默认拒绝的静态权限节点判断",
    usage="无用户指令，供其他插件通过 amia-core 调用",
    type="application",
    supported_adapters=set(),
)

logger = logging.getLogger(__name__)
driver = get_driver()
permission_provider = StaticPermissionProvider()


def _load_rules(value: Any) -> dict[str, list[str]]:
    if isinstance(value, str):
        if not value.strip():
            return {}
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            logger.warning("AMIA_PERMISSION_RULES is not valid JSON")
            return {}

    if not isinstance(value, Mapping):
        return {}

    rules: dict[str, list[str]] = {}
    for node, selectors in value.items():
        if isinstance(selectors, str):
            rules[str(node)] = [selectors]
        elif isinstance(selectors, (list, tuple, set)):
            rules[str(node)] = [str(item) for item in selectors]
        else:
            logger.warning(
                "ignored invalid permission rule %r: expected a list of selectors",
                node,
            )
    return rules


@driver.on_startup
async def _register_permission_provider() -> None:
    configured_rules = getattr(driver.config, "amia_permission_rules", {})
    permission_provider.replace_rules(_load_rules(configured_rules))
    registry.register_permission_provider(
        "static",
        permission_provider,
        replace=True,
    )
    logger.info("registered static permission provider")
