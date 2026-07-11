# Amia-plugin-permission

`Amia-plugin-permission` 是 Amia / Mizuki 插件生态的最小权限服务。它实现 `amia-core.PermissionProvider`，通过静态配置判断某个身份是否拥有指定权限节点。

## 插件作用

它解决的是“其他插件不要各自写一套权限判断”的问题。

典型消费者：

```text
Amia-plugin-group      → 公告增删改权限
Amia-plugin-economy    → 高风险管理指令
Amia-plugin-audit      → 审计查询权限
Amia-plugin-welcome    → 群级欢迎配置权限
后续后台或管理插件      → permission.manage
```

当前版本只提供静态、默认拒绝、allow-only 的基础规则，不包含角色数据库、拒绝规则、临时授权或群管理员自动同步。

## 当前能力

- 启动时注册 `PermissionProvider("static")`；
- 默认拒绝所有未配置权限；
- 支持 canonical identity；
- 支持未绑定外部身份；
- 支持全局权限节点；
- 支持上下文级权限节点；
- 支持节点通配符和身份通配符；
- 配置错误时降级为空规则，不阻断 NoneBot 启动。

## Provider 接口

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

消费者应通过 Registry 获取：

```python
provider = registry.get_permission_provider("static")
```

Provider 不存在、超时或异常时必须默认拒绝。

## 配置

配置项：

```text
AMIA_PERMISSION_RULES
```

可提供字典或 JSON 字符串：

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

```text
<permission_node>@<context_id>
```

例如：

```text
group.notice.manage@group:123456
```

### 节点通配符

```text
*
*@group:123456
```

`*` 表示允许所有节点，应谨慎配置。

## 身份选择器

### canonical 身份

```text
canonical:<canonical_user_id>
```

### 外部身份

```text
external:<self_id>:<user_id>
```

适用于尚未完成 qbind 的身份，但与当前 Bot 实例绑定。

### opaque 身份

```text
opaque:<ResolvedIdentity.opaque_id>
```

不建议把 opaque 内部格式作为长期公共配置。新规则优先使用 `canonical:` 或 `external:`。

### 身份通配符

规则值中的：

```text
*
```

表示所有身份都允许该节点。

## allow-only 语义

当前 Provider 只有“允许”规则，没有显式 deny。

检查顺序：

```text
<node>@<context>
<node>
*@<context>
*
```

这些规则是累加关系，不是覆盖关系：

- 上下文规则命中时允许；
- 上下文规则未命中，但全局规则命中时仍然允许；
- 当前版本不能用上下文规则撤销一个全局允许；
- 未命中任何允许规则时返回 `False`。

例如：

```json
{
  "economy.admin": ["canonical:10001"],
  "economy.admin@group:123": ["canonical:10002"]
}
```

则：

- `10001` 在所有群都允许；
- `10002` 只在群 `123` 允许；
- 上下文规则不会阻止 `10001`。

如果以后需要显式 deny，必须扩展正式规则模型和优先级测试，不能直接在当前字符串规则中临时加前缀。

## 消费者接入示例

```python
from src.plugins.amia_core import call_provider_safe, registry

provider = registry.get_permission_provider("static")
if provider is None:
    allowed = False
else:
    result = await call_provider_safe(
        provider.has_permission,
        resolved_identity,
        "group.notice.manage",
        f"group:{event.group_id}",
        timeout=0.5,
    )
    allowed = bool(result.success and result.value)

if not allowed:
    await matcher.finish("权限不足")
```

调用方要求：

- Provider 缺失默认拒绝；
- 异常和超时默认拒绝；
- 不把昵称、群名或显示名当作权限主体；
- 不把具体用户或群号编码进权限节点名称；
- `context_id` 使用稳定格式，例如 `group:<group_id>`。

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

权限节点表示能力；作用群由 `context_id` 或规则键中的 `@<context>` 表达。

## 启动和注册

NoneBot startup 时读取配置并注册：

```python
registry.register_permission_provider(
    "static",
    permission_provider,
    replace=True,
)
```

推荐加载关系：

```text
amia-core
qbind / IdentityResolver
permission
业务消费者插件
```

Permission 本身不要求 qbind 存在，但 canonical 规则只有在上游解析出 canonical ID 时才会命中。未绑定用户可以使用 external 规则。

## 当前不包含

- 显式 deny；
- 角色和角色继承；
- SQLite 权限数据库；
- 临时授权和过期时间；
- 群管理员自动同步；
- 黑名单/白名单管理指令；
- 网页管理面板；
- 审计查询指令。

## 测试

```powershell
$env:PYTHONPATH = '<project-root>'
python -m unittest discover -s src/plugins/Amia-plugin-permission/tests -v
```

当前测试覆盖：

- 默认拒绝；
- canonical 身份；
- 外部身份；
- 上下文规则；
- 节点和身份通配符；
- 规则替换。

后续应补：

- Provider 配置 JSON 解析；
- 无效配置降级；
- 全局与上下文规则的累加语义；
- `call_provider_safe` 超时后的默认拒绝集成测试。

## 后续开发顺序

1. Group 公告管理接入 `group.notice.manage`；
2. Economy 高风险操作接入明确节点；
3. 权限变更接入 `AuditLogger("sqlite")`；
4. 收集真实使用需求；
5. 再决定是否需要角色、deny 和持久化。

新增持久化前必须先提供迁移、备份和回滚方案。

## 安全边界

- 默认拒绝；
- 不因 Provider 缺失自动放行；
- 不使用昵称作为身份；
- 不默认配置超级通配符；
- 不在日志中输出完整规则和敏感身份信息；
- 当前仓库尚未确定公开许可证。