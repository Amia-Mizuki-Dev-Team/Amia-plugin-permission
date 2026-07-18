"""Offline permission benchmark for baseline and candidate providers."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median


def _repository() -> Path:
    return Path(
        os.environ.get(
            "AMIA_PERMISSION_BENCH_REPO",
            str(Path(__file__).resolve().parents[1]),
        )
    )


ROOT = next(
    parent
    for parent in Path(__file__).resolve().parents
    if (parent / "src" / "plugins" / "amia_core").is_dir()
)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_provider():
    path = _repository() / "provider.py"
    spec = importlib.util.spec_from_file_location(
        f"amia_permission_benchmark_{abs(hash(str(path)))}",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.StaticPermissionProvider


StaticPermissionProvider = _load_provider()
CORE = importlib.import_module("src.plugins.amia_core")
ResolvedIdentity = CORE.ResolvedIdentity
UserIdentityKey = CORE.UserIdentityKey


IDENTITY = ResolvedIdentity(
    UserIdentityKey(self_id="benchmark-bot", user_id="benchmark-user"),
    canonical_user_id="benchmark-user",
)


def _rules(count: int) -> dict[str, list[str]]:
    return {
        f"benchmark.action.{index}": [f"canonical:user-{index % 100}"]
        for index in range(count)
    }


async def _timed(coro_factory, *, warmups: int = 2, samples: int = 5):
    for _ in range(warmups):
        await coro_factory()
    values = []
    for _ in range(samples):
        started = time.perf_counter()
        await coro_factory()
        values.append((time.perf_counter() - started) * 1000)
    return {
        "median_ms": median(values),
        "min_ms": min(values),
        "max_ms": max(values),
        "samples": samples,
    }


async def _rule_lookup_benchmark(count: int):
    provider = StaticPermissionProvider(_rules(count))
    node = f"benchmark.action.{count - 1}"
    return await _timed(
        lambda: provider.has_permission(IDENTITY, node, "group:1")
    )


async def _check_count_benchmark(count: int):
    provider = StaticPermissionProvider(_rules(100))

    async def operation() -> None:
        for index in range(count):
            await provider.has_permission(
                IDENTITY,
                f"benchmark.action.{index % 100}",
                "group:1",
            )

    return await _timed(operation)


async def _expiry_benchmark():
    if not hasattr(StaticPermissionProvider, "clear_expired"):
        return "NOT MEASURED"
    provider = StaticPermissionProvider(
        {
            "rules": [
                {
                    "permission": f"expired.{index}",
                    "selector": "canonical:benchmark-user",
                    "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1),
                }
                for index in range(1000)
            ]
        }
    )
    return await _timed(provider.clear_expired)


async def _cache_benchmark():
    provider = StaticPermissionProvider(_rules(1000))
    node = "benchmark.action.999"
    await provider.has_permission(IDENTITY, node, "group:1")

    async def hit() -> None:
        await provider.has_permission(IDENTITY, node, "group:1")

    async def miss() -> None:
        cache = getattr(provider, "_decision_cache", None)
        if isinstance(cache, dict):
            cache.clear()
        await provider.has_permission(IDENTITY, node, "group:1")

    return {
        "hit": await _timed(hit),
        "miss": await _timed(miss),
    }


async def main() -> None:
    started = time.perf_counter()
    result: dict[str, object] = {
        "python": sys.version.split()[0],
        "warmups": 2,
        "samples": 5,
        "rule_lookup": {},
        "permission_checks": {},
    }
    for count in (100, 1000, 10000):
        result["rule_lookup"][str(count)] = await _rule_lookup_benchmark(count)  # type: ignore[index]
    for count in (1000, 10000, 100000):
        result["permission_checks"][str(count)] = await _check_count_benchmark(count)  # type: ignore[index]
    result["cache"] = await _cache_benchmark()
    result["expired_rule_cleanup"] = await _expiry_benchmark()
    result["elapsed_seconds"] = time.perf_counter() - started
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
