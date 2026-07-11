from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from src.plugins.amia_core import ResolvedIdentity, UserIdentityKey


MODULE_PATH = Path(__file__).resolve().parents[1] / "provider.py"
SPEC = importlib.util.spec_from_file_location(
    "amia_permission_provider",
    MODULE_PATH,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load permission provider module")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
StaticPermissionProvider = MODULE.StaticPermissionProvider


class TestStaticPermissionProvider(unittest.TestCase):
    def setUp(self) -> None:
        self.bound = ResolvedIdentity(
            UserIdentityKey(self_id="bot-1", user_id="user-1"),
            canonical_user_id="canonical-1",
        )
        self.unbound = ResolvedIdentity(
            UserIdentityKey(self_id="bot-1", user_id="user-2"),
        )

    def test_default_deny(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider()
            self.assertFalse(
                await provider.has_permission(
                    self.bound,
                    "group.notice.manage",
                    "group:1",
                )
            )

        import asyncio
        asyncio.run(run_test())

    def test_canonical_selector(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider(
                {
                    "group.notice.manage": [
                        "canonical:canonical-1",
                    ],
                }
            )
            self.assertTrue(
                await provider.has_permission(
                    self.bound,
                    "group.notice.manage",
                    "group:1",
                )
            )

        import asyncio
        asyncio.run(run_test())

    def test_external_selector(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider(
                {
                    "welcome.configure": [
                        "external:bot-1:user-2",
                    ],
                }
            )
            self.assertTrue(
                await provider.has_permission(
                    self.unbound,
                    "welcome.configure",
                    "group:1",
                )
            )

        import asyncio
        asyncio.run(run_test())

    def test_context_specific_rule(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider(
                {
                    "economy.admin@group:1": [
                        "canonical:canonical-1",
                    ],
                }
            )
            self.assertTrue(
                await provider.has_permission(
                    self.bound,
                    "economy.admin",
                    "group:1",
                )
            )
            self.assertFalse(
                await provider.has_permission(
                    self.bound,
                    "economy.admin",
                    "group:2",
                )
            )

        import asyncio
        asyncio.run(run_test())

    def test_node_and_identity_wildcards(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider(
                {
                    "*@group:1": ["canonical:canonical-1"],
                    "public.feature": ["*"],
                }
            )
            self.assertTrue(
                await provider.has_permission(
                    self.bound,
                    "anything",
                    "group:1",
                )
            )
            self.assertTrue(
                await provider.has_permission(
                    self.unbound,
                    "public.feature",
                    "group:2",
                )
            )

        import asyncio
        asyncio.run(run_test())

    def test_replace_rules(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider()
            provider.replace_rules(
                {
                    "audit.query": [
                        "canonical:canonical-1",
                    ],
                }
            )
            self.assertTrue(
                await provider.has_permission(
                    self.bound,
                    "audit.query",
                    "global",
                )
            )

        import asyncio
        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
