# Cylism Account Go SDK

SDK 为独立的公开 Go module，要求 Go 1.24 或更高版本。Account 负责登录、角色、权限、审计和会话规则，SDK 负责协议校验、类型和 HTTP 通信。SDK 不依赖 Account 内部 Go 包、数据库或 Cylism UI。

## 已覆盖范围

Go SDK 提供现有 **82 个 JSON 接口**的类型化方法。完整操作名、HTTP 路径、认证范围和成功状态码见 [operations.json](operations.json)。

| 功能 | 内容 |
| --- | --- |
| 普通用户 | 资料、邮箱凭据、登录方式、绑定/解绑平台、重新验证、会话查询/撤销、退出 |
| 登录与注册 | 邮箱登录/注册/重置、验证码、GitHub/Google 入口、授权确认/拒绝 |
| 第一方应用 | 密码注册/登录、验证码、重置、opaque 会话验证/退出、受限用户目录 |
| 应用权限 | AuthZEN 单条/批量判断、应用用户角色/有效权限、准入策略、角色、权限目录、成员配置 |
| 管理后台 | 登录、MFA/恢复码、最近身份验证、概览、用户和会话、邀请、合并、注销、应用/密钥、平台、消息渠道、审计、管理员 |
| 运维 | liveness、readiness、OIDC discovery 与 JWKS |

此外，Go SDK 提供 OIDC discovery、授权码 + S256 PKCE、state/nonce 验证、RS256 ID Token 验证、userinfo 身份核对、严格刷新轮换、introspection、撤销和 net/http 鉴权中间件。协议重定向和令牌交换使用专用方法。第三方平台回调仍由 Account 处理。

Vue/React 页面直接调用自己的 Go 业务后端，由后端通过 Go SDK 对接 Account。应用密钥与令牌保留在后端。

## 安装与接入

~~~sh
go get github.com/SurryChen/cylism-account-sdk-go@v0.1.0
~~~

~~~go
import account "github.com/SurryChen/cylism-account-sdk-go"

client, err := account.New(account.Config{
    BaseURL: "https://account.crazycoding.top",
    ClientID: clientID,
    ClientSecret: clientSecret, // 仅从业务后端的环境或秘密存储读取
})
if err != nil { return err }
allowed, err := client.Can(ctx, verifiedSubject, "orders", "read")
if err != nil { return err }
if !allowed { return account.ErrForbidden }
~~~

verifiedSubject 必须来自已验证登录会话；资源类型与操作由后端决定。业务后端继续校验数据所属用户/租户。当前 Account 策略按资源类型判断权限，resource.id、properties、context 不参与计算。

下载本 SDK 不需要 Account 私有仓库访问权限或 GitHub 凭证。实际调用 API 仍需要 Account 分配的应用凭据及相应用户或管理员会话。

### 响应限制与 OAuth 端点

Config.MaxResponseBytes 为整个 SDK 设置响应体上限，包含成功/错误 JSON、OIDC discovery、JWKS、令牌、userinfo、introspection 和撤销请求。0 使用默认 2 MiB，负数被拒绝；依赖库可能有更严格的内建限制。注入的 HTTPClient 不会被修改，原有 Transport 和超时继续生效。

~~~go
client, err := account.New(account.Config{
    BaseURL: "https://account.example.com",
    ClientID: clientID,
    ClientSecret: clientSecret,
    MaxResponseBytes: 64 << 10,
    // 可选：同源的绝对 URL；显式配置优先于 discovery。
    IntrospectionEndpoint: "https://account.example.com/gateway/introspect",
    RevocationEndpoint: "https://account.example.com/gateway/revoke",
})
~~~

同一个 Client 成功执行 DiscoverOIDC 后，Introspect / Revoke 使用 discovery 返回的 introspection_endpoint / revocation_endpoint。未 discovery 或元数据缺省时，分别使用 /oauth/introspect 和 /oauth/revoke。显式配置不被 discovery 覆盖。所有端点都必须与 Account 同源，不允许用户名、查询串和 fragment；重定向继续被阻止。并发读取端点有锁保护，不为每次权限校验重复 discovery。

这支持同源自定义 OAuth 端点，不代表支持带路径的 BaseURL 或任意第三方 OIDC 服务。BaseURL 仍为 Account origin，其他业务 API 路径保持固定。

### Vue / React 前端

前端调用自己业务后端提供的登录入口、当前用户和业务接口，无需安装 Account 前端 SDK。Go 后端负责 OIDC、令牌刷新、会话和权限校验。

后端可返回当前用户的必要角色和权限，前端据此控制菜单/按钮展示；后端每次执行实际操作仍需鉴权。完整示例见下方示例文档。

## 登录、会话和权限

- DiscoverOIDC 固定 issuer、client、回调地址与 scope。BeginLogin 支持 Provider:"github" 或 "google"，值为已启用平台的 key。
- LoginTransaction 含 state/nonce/PKCE verifier，必须存在服务端、绑定发起登录的浏览器，并在回调时原子消费一次。不能相信浏览器提交的 transaction。CompleteLogin 验证有效期、state 和 ID Token。
- CompleteLogin / Refresh 只接受非空、类型为 Bearer、具有明确且未过期有效期的 access token。TokenSession 在保存轮换结果前及返回前再次检查；无效刷新结果使会话失效，不保存也不重放旧 refresh token。
- TokenSession 串行化单进程刷新，成功后先持久化新令牌。多实例需要共享存储和刷新锁/事务。无法确认结果时重新登录，不能重放旧 refresh token。
- Introspect 在线检查撤销、过期、subject 和客户端归属。AuthenticateBearer 建立可信 Principal；RequirePermission("orders:read") 必须位于认证之后。应用角色 admin 不隐含全部权限。
- OIDC token 与第一方 password bridge 的 opaque token 属于不同会话；后者使用 VerifyPasswordSession / LogoutPasswordSession，不能交给 OIDC introspection。
- 没有跨请求 allow 缓存。缺失 decision、批量结果不完整、网络/服务错误均不放行。离线 JWT 存在最长五分钟撤销延迟，本版中间件使用在线检查。

## 管理 API

管理操作仍要求 Account 管理员 Cookie、Origin 和独立 admin CSRF；权限配置仅限 super_admin，受最近身份验证与 MFA 控制。应用内 admin 无法管理 Account。

1. 每个人创建独立 Cookie 客户端，不全局共享用户会话。
2. AdminLogin 可能返回 MFA challenge，再调用 AdminMFA；challenge 不表示登录成功。生产强制 MFA，未完成绑定时只允许相应认证接口。
3. AdminMe 恢复 admin CSRF。敏感写入返回 reauth_required 时，用 AdminVerify 完成密码/MFA 验证，再由用户继续操作。
4. 配置写入携带读取时的 policy.version。409 后重新加载编辑，不自动覆盖或重试写入。
5. APIError 保留 code、status、request ID、Retry-After；远程 message 单独保留，默认错误字符串不包含响应正文。不要记录密码、token、授权码或完整响应。

Go Client 自带独立 cookie jar，不继承传入 HTTPClient 已有的 Cookie。flow/user/admin CSRF 分开保存，成功退出清理对应状态。

## 示例与校验

[可运行的 Go BFF + Vue + Cylism UI 示例](examples/README.md)支持 Account/GitHub/Google 登录、用户资料、角色权限、后端订单鉴权和退出。

~~~sh
go vet ./...
go test -race ./...
npm --prefix examples/vue ci --ignore-scripts --no-audit --no-fund
npm --prefix examples/vue run build
~~~

本仓库可独立构建和测试，不依赖 Account 源码或数据库。公开 CI 检查 Go SDK、操作清单和示例构建。真实服务集成测试及 OpenAPI 生成器由 Account 仓库维护；修改生成文件需同步其 API 契约和生成结果。

## 版本与许可

Go module 使用仓库根标签（如 v0.1.0）发布；接入方固定版本升级。源代码仓库公开不等于授予开源许可。当前保留所有权利，未授予第三方使用、修改或再分发许可，详见 [NOTICE](NOTICE)。需要对外授权时再补充正式许可。
