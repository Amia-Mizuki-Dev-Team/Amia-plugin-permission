# Amia-plugin-permission

Amia 插件生态的默认拒绝权限 Provider。它使用带命名空间的身份和精确作用域进行判断，不依赖显示昵称、其他插件私有数据库或 qbind 的内部文件。

## 公共接口

插件启动时以 `static` 名称注册到 `amia-core`：

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

返回结构：

```python
{
    "allowed": False,
    "reason": "no_matching_rule",
    "matched_rule": None,
    "expires_at": None,
}
```

根模块还提供 `check_permission`、`require_permission`、`grant_permission`、`revoke_permission`、`list_permissions` 和 `health_check`。`require_permission` 在拒绝时抛出 `PermissionError`。

## 规则与优先级

规则支持全局/作用域权限、角色、运行时授权、显式拒绝、临时过期、黑名单、白名单和可选 SUPERUSER。权限键支持精确值和 `group.notice.*` 通配符；作用域使用 `permission@group:<id>` 或结构化 `scope`。

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
  ]
}
```

判断顺序固定为：

```text
黑名单 → 白名单门禁 → 显式拒绝 → 配置 SUPERUSER
→ 作用域允许 → 全局允许 → 默认拒绝
```

默认情况下 SUPERUSER 也不能绕过显式拒绝。过期规则不会命中，群作用域必须精确匹配，不能泄漏到其他群。

## Audit 对接

运行时授权和撤销会尝试调用 `sqlite` Audit Provider。Audit 未加载时，普通权限检查仍可工作；设置 `AMIA_PERMISSION_AUDIT_REQUIRED=true` 后，审计失败会回滚运行时权限修改。

```text
AMIA_PERMISSION_RULES
AMIA_PERMISSION_AUDIT_REQUIRED
AMIA_PERMISSION_SUPERUSER_BYPASS_DENIES
```

## Release010 边界

- `self_id`、`user_id` 和群作用域均允许字符串/OpenID；
- 不从显示昵称推断权限；
- Provider 缺失时调用方必须安全拒绝；
- `compatibility.yml` 只记录自动化证据，真实管理员/SUPERUSER 场景未执行时保持未验证。

## 测试

```powershell
$env:PYTHONPATH = "H:\Amia-Develop"
H:\Amia-Develop\.venv\Scripts\python.exe -m unittest discover -s tests -v
H:\Amia-Develop\.venv\Scripts\python.exe -m compileall -q .
git diff --check
```

Benchmark 只使用虚构身份和离线规则，不访问网络或生产数据。

## 代码核验与十月状态（2026-10-14）

当前根模块通过 `provider.py` 提供默认拒绝的作用域权限判定，并注册 `static` 权限 Provider；本仓库没有普通用户交互命令。任何按钮隐藏或帮助菜单显示限制都不能代替服务端权限校验。2026-10-01 至 2026-10-14 默认分支未发现新提交。
