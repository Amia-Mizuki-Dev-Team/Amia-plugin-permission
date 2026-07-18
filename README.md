# Amia-plugin-permission

`Amia-plugin-permission` is the default-deny permission provider for the Amia
plugin ecosystem. It evaluates namespaced identities without depending on
display names, private plugin databases, or qbind.

## Public API

The provider is registered as `static` during NoneBot startup. Other plugins
should obtain it through `amia-core` or use the root functions:

```python
from nonebot import require

core = require("amia_core")
permission = core.registry.get_permission_provider("static")
decision = await permission.check_permission(
    resolved_identity,
    "group.notice.manage",
    "group:123",
)
```

The structured decision is:

```python
{
    "allowed": False,
    "reason": "no_matching_rule",
    "matched_rule": None,
    "expires_at": None,
}
```

The root module exports equivalent `check_permission`, `require_permission`,
`grant_permission`, `revoke_permission`, `list_permissions`, and
`health_check` functions. `require_permission` raises `PermissionError` for a
denied decision.

## Rule model and precedence

Rules support global and scoped permissions, roles, runtime grants, explicit
denies, temporary expiry, blacklist, whitelist, and opt-in superusers. A
permission key may be an exact value or a wildcard such as
`group.notice.*`. A scoped rule uses `permission@group:<id>` or a structured
`scope` field.

```json
{
  "superusers": ["canonical:10001"],
  "blacklist": ["external:adapter-1:blocked"],
  "whitelist": ["canonical:10001", "canonical:10002"],
  "rules": [
    {
      "permission": "group.notice.manage",
      "selector": "canonical:10002",
      "effect": "allow",
      "scope": "group:123"
    },
    {
      "permission": "group.notice.delete",
      "selector": "canonical:10002",
      "effect": "deny"
    }
  ],
  "roles": {
    "moderator": {
      "selectors": ["canonical:10002"],
      "permissions": ["group.notice.*"],
      "scope": "group:123"
    }
  }
}
```

Evaluation order is deterministic:

```text
blacklist
→ whitelist gate
→ explicit deny
→ configured superuser
→ scoped allow
→ global allow
→ default deny
```

By default even a configured superuser does not bypass an explicit deny;
`AMIA_PERMISSION_SUPERUSER_BYPASS_DENIES` can opt into that behavior. Rules
with an expired `expires_at` never match. Group context is exact and cannot
leak to another group.

Legacy allow-only configuration remains supported:

```json
{
  "group.notice.manage": ["canonical:10001"],
  "economy.admin@group:123": ["external:adapter-1:20002"]
}
```

## Audit integration

Runtime grants and revocations attempt to use the `sqlite` Audit provider
through the Core Registry. Permission checks continue to work if Audit is not
loaded. Set `AMIA_PERMISSION_AUDIT_REQUIRED` to require a successful audit for
runtime changes; a failed audit then rolls the change back. No caller writes an
Audit database directly.

Configuration names:

```text
AMIA_PERMISSION_RULES
AMIA_PERMISSION_AUDIT_REQUIRED
AMIA_PERMISSION_SUPERUSER_BYPASS_DENIES
```

## Validation

```powershell
$env:PYTHONPATH = "H:\Amia-Develop"
H:\Amia-Develop\.venv\Scripts\python.exe -m compileall -q .
H:\Amia-Develop\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The offline benchmark uses two warmups and five measured runs for 100/1,000/
10,000 rules, 1,000/10,000/100,000 permission checks, and expired-rule
cleanup. It uses synthetic identities and no network or production data.
