# Amia-plugin-permission

`Amia-plugin-permission` 是 Amia / Mizuki 插件生态的最小权限服务骨架。它实现 `amia-core` 的 `PermissionProvider` 协议，通过静态配置判断某个身份是否拥有权限节点。

当前版本的目标是提供稳定契约和默认拒绝行为，不提前建立复杂角色数据库、群内管理指令或网页后台。

## 当前能力

- 启动时注册 `PermissionProvider("static")`。
- 默认拒绝所有未配置权限。
- 支持 canonical identity。
- 支持未绑定的外部身份。
- 支持全局权限节点。
- 支持上下文级权限节点。
- 支持节点和身份通配符。
- 配置错误时降级为空规则，不阻断 NoneBot 启动。

## 权限接口

```python
await provider.has_permission(
    identity=resolved_identity,
    permission_node="group.notice.manage",
    context_id="group:123456",
)
```

返回：

```python
True | False
```

## 配置

配置项：

```text
AMIA_PERMISSION_RULES
```

可在 NoneBot 配置中提供字典，也可以提供 JSON 字符串。

示例：

```env
AMIA_PERMISSION_RULES={"group.notice.manage":["canonical:123456789"],"economy.admin@group:987654":["canonical:123456789","external:10001:20002"]}
```

等价结构：

```json
{
  "group.notice.manage": [
    "canonical:123456789"
  ],
  "economy.admin@group:987654": [
    "canonical:123456789",
    "external:10001:20002"
  ]
}
```

## 规则键

### 全局节点

```text
group.notice.manage
```

### 上下文节点

格式：

```text
<permission_node>@<context_id>
```

示例：

```text
group.notice.manage@group:123456
```

### 节点通配符

```text
*
*@group:123456
```

`*` 表示匹配所有权限节点。应谨慎使用，尤其不要向普通用户配置。

## 身份选择器

### canonical 身份

```text
canonical:<canonical_user_id>
```

示例：

```text
canonical:123456789
```

### 外部身份

```text
external:<self_id>:<user_id>
```

示例：

```text
external:10001:20002
```

适用于尚未完成 qbind 的身份，但该选择器与当前 Bot 实例绑定。

### opaque 身份

```text
opaque:<ResolvedIdentity.opaque_id>
```

绑定用户的 opaque ID 当前等于 canonical ID；未绑定身份格式为：

```text
opaque:unbound:<self_id>:<user_id>
```

新配置优先使用 `canonical:` 或 `external:`，不要依赖 opaque 内部格式作为长期公共接口。

### 身份通配符

规则值中使用：

```text
*
```

表示所有身份均允许。只建议用于完全公开的能力节点。

## 判断顺序

Provider 按以下顺序检查：

```text
<node>@<context>
<node>
*@<context>
*
```

任何一条规则包含当前身份选择器或 `*` 时返回 `True`。

未命中规则时返回 `False`。

## 使用方式

```python
from src.plugins.amia_core import registry

provider = registry.get_permission_provider("static")
if provider is None:
    # 权限服务未启动时默认拒绝
    allowed = False
else:
    allowed = await provider.has_permission(
        resolved_identity,
        "group.notice.manage",
        f"group:{event.group_id}",
    )
```

调用方应遵循：

- Provider 不存在时默认拒绝。
- 权限检查异常时默认拒绝。
- 不把昵称作为权限主体。
- 权限节点使用稳定的点分命名。

## 权限节点命名建议

```text
group.notice.view
group.notice.manage
economy.admin
economy.transfer.override
audit.query
permission.manage
welcome.configure
```

节点名称应表达能力，不应包含具体用户或群号。

## 当前不包含

- 角色继承。
- SQLite 权限数据库。
- 临时授权和到期时间。
- 群管理员自动同步。
- 黑名单/白名单管理指令。
- 网页管理面板。
- 审计查询指令。

这些功能应在静态 Provider 骨架经过实际使用验证后再增加。

## 测试

运行：

```powershell
$env:PYTHONPATH = '<project-root>'
python -m unittest discover -s src/plugins/Amia-plugin-permission/tests -v
```

测试应覆盖：

- 默认拒绝。
- canonical 身份命中。
- 外部身份命中。
- 上下文规则优先。
- 节点通配符。
- 身份通配符。
- 规则热替换。

## 后续开发建议

1. 先把 Group 公告管理接入 `group.notice.manage`。
2. 将高风险 Economy 管理能力接入明确节点。
3. 权限变更接入 `AuditLogger("sqlite")`。
4. 收集真实需求后再设计角色和持久化模型。
5. 增加持久化时必须提供迁移、备份和回滚方案。

## 安全边界

- 默认拒绝。
- 不因 Provider 缺失自动放行。
- 不以昵称、群名或显示名作为身份。
- 不将超级权限通配符作为默认配置。
- 不在日志中输出完整权限配置和敏感身份信息。
- 当前仓库尚未确定公开许可证。