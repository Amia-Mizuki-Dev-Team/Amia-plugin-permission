from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
core = importlib.import_module("src.plugins.amia_core")

MODULE_PATH = Path(__file__).resolve().parents[1] / "provider.py"
SPEC = importlib.util.spec_from_file_location("amia_permission_provider", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load permission provider module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
StaticPermissionProvider = MODULE.StaticPermissionProvider


class TestStaticPermissionProvider(unittest.TestCase):
    def setUp(self) -> None:
        self.bound = core.ResolvedIdentity(
            core.UserIdentityKey(self_id="bot-1", user_id="user-1"),
            canonical_user_id="canonical-1",
        )
        self.unbound = core.ResolvedIdentity(
            core.UserIdentityKey(self_id="bot-1", user_id="user-2"),
        )

    def test_default_deny(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider()
            decision = await provider.check_permission(
                self.bound, "group.notice.manage", "group:1"
            )
            self.assertFalse(decision["allowed"])
            self.assertEqual(decision["reason"], "no_matching_rule")
            self.assertFalse(
                await provider.has_permission(self.bound, "group.notice.manage", "group:1")
            )

        asyncio.run(run_test())

    def test_canonical_and_external_selectors(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider(
                {
                    "group.notice.manage": ["canonical:canonical-1"],
                    "welcome.configure": ["external:bot-1:user-2"],
                }
            )
            self.assertTrue(
                await provider.has_permission(self.bound, "group.notice.manage", "group:1")
            )
            self.assertTrue(
                await provider.has_permission(self.unbound, "welcome.configure", "group:1")
            )

        asyncio.run(run_test())

    def test_scoped_rules_do_not_leak_between_groups(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider(
                {"economy.admin@group:1": ["canonical:canonical-1"]}
            )
            self.assertTrue(
                await provider.has_permission(self.bound, "economy.admin", "group:1")
            )
            self.assertFalse(
                await provider.has_permission(self.bound, "economy.admin", "group:2")
            )

        asyncio.run(run_test())

    def test_explicit_deny_beats_allow(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider(
                {
                    "rules": [
                        {
                            "permission": "economy.admin",
                            "selector": "canonical:canonical-1",
                            "effect": "allow",
                        },
                        {
                            "permission": "economy.admin",
                            "selector": "canonical:canonical-1",
                            "effect": "deny",
                        },
                    ]
                }
            )
            decision = await provider.check_permission(
                self.bound, "economy.admin", "group:1"
            )
            self.assertFalse(decision["allowed"])
            self.assertEqual(decision["reason"], "explicit_deny")

        asyncio.run(run_test())

    def test_temporary_grant_and_expiry_cleanup(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider()
            await provider.grant_permission(
                "temporary.action",
                "canonical:canonical-1",
                context_id="group:1",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            )
            self.assertTrue(
                await provider.has_permission(self.bound, "temporary.action", "group:1")
            )
            expired = StaticPermissionProvider(
                {
                    "rules": [
                        {
                            "permission": "expired.action",
                            "selector": "canonical:canonical-1",
                            "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1),
                        }
                    ]
                }
            )
            self.assertFalse(
                await expired.has_permission(self.bound, "expired.action", "group:1")
            )
            self.assertEqual(await expired.clear_expired(), 1)

        asyncio.run(run_test())

    def test_blacklist_whitelist_and_configured_superuser(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider(
                {
                    "rules": [
                        {
                            "permission": "admin.*",
                            "selector": "canonical:canonical-1",
                            "effect": "allow",
                        }
                    ],
                    "blacklist": ["canonical:canonical-1"],
                    "whitelist": ["canonical:other"],
                }
            )
            self.assertEqual(
                (await provider.check_permission(self.bound, "admin.view"))["reason"],
                "blacklisted",
            )
            superuser = StaticPermissionProvider(
                {
                    "superusers": ["canonical:canonical-1"],
                    "rules": [
                        {
                            "permission": "admin.*",
                            "selector": "canonical:canonical-1",
                            "effect": "allow",
                        }
                    ],
                }
            )
            decision = await superuser.check_permission(self.bound, "admin.view")
            self.assertTrue(decision["allowed"])
            self.assertEqual(decision["reason"], "superuser")

        asyncio.run(run_test())

    def test_roles_and_wildcards(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider(
                {
                    "roles": {
                        "moderator": {
                            "selectors": ["canonical:canonical-1"],
                            "permissions": ["group.notice.*"],
                            "scope": "group:1",
                        }
                    }
                }
            )
            self.assertTrue(
                await provider.has_permission(self.bound, "group.notice.edit", "group:1")
            )
            self.assertFalse(
                await provider.has_permission(self.bound, "group.notice.edit", "group:2")
            )

        asyncio.run(run_test())

    def test_runtime_grant_revoke_and_structured_list(self) -> None:
        async def run_test() -> None:
            provider = StaticPermissionProvider()
            rule = await provider.grant_permission(
                "audit.query",
                "canonical:canonical-1",
                context_id="global",
            )
            self.assertEqual(rule["source"], "runtime")
            listed = await provider.list_permissions(selector="canonical:canonical-1")
            self.assertEqual(len(listed), 1)
            self.assertEqual(
                await provider.revoke_permission(
                    "audit.query", "canonical:canonical-1", context_id="global"
                ),
                1,
            )
            self.assertFalse(await provider.has_permission(self.bound, "audit.query"))

        asyncio.run(run_test())

    def test_audit_available_and_required_failure_rolls_back(self) -> None:
        async def run_test() -> None:
            calls: list[dict[str, object]] = []

            class FakeAudit:
                async def record_event(self, **kwargs: object) -> dict[str, object]:
                    calls.append(kwargs)
                    return {"event_id": "audit-1"}

            fake_core = SimpleNamespace(
                registry=SimpleNamespace(
                    get_audit_logger=lambda name: FakeAudit() if name == "sqlite" else None
                )
            )
            original_require = MODULE.require
            MODULE.require = lambda name: fake_core
            try:
                provider = StaticPermissionProvider(audit_required=True)
                await provider.grant_permission(
                    "permission.manage",
                    "canonical:canonical-1",
                    actor=self.bound,
                )
                self.assertEqual(calls[0]["action"], "permission.grant")
                self.assertTrue(await provider.has_permission(self.bound, "permission.manage"))

                class FailedAudit:
                    async def record_event(self, **kwargs: object) -> None:
                        return None

                fake_core.registry.get_audit_logger = lambda name: (
                    FailedAudit() if name == "sqlite" else None
                )
                with self.assertRaises(RuntimeError):
                    await provider.grant_permission(
                        "permission.failed",
                        "canonical:canonical-1",
                        actor=self.bound,
                    )
                self.assertFalse(
                    await provider.has_permission(self.bound, "permission.failed")
                )
            finally:
                MODULE.require = original_require

        asyncio.run(run_test())

    def test_audit_missing_does_not_break_optional_change(self) -> None:
        async def run_test() -> None:
            original_require = MODULE.require
            MODULE.require = lambda name: SimpleNamespace(
                registry=SimpleNamespace(
                    get_audit_logger=lambda provider_name: None
                )
            )
            try:
                provider = StaticPermissionProvider(audit_required=False)
                await provider.grant_permission(
                    "optional.change",
                    "canonical:canonical-1",
                    actor=self.bound,
                )
                self.assertTrue(await provider.has_permission(self.bound, "optional.change"))
            finally:
                MODULE.require = original_require

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
