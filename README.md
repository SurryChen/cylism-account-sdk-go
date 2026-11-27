# Cylism Account Go SDK

SDK 为独立的公开 Go module，要求 Go 1.24 或更高版本。Account 负责登录、角色、权限、审计和会话规则，SDK 负责协议校验、类型和 HTTP 通信。SDK 不依赖 Account 内部 Go 包、数据库或 Cylism UI。

## 已覆盖范围

Go SDK 提供现有 **97 个 JSON 接口**的类型化方法。完整操作名、HTTP 路径、认证范围和成功状态码见 [operations.json](operations.json)。

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
- Introspect 首次在线检查撤销、过期、subject 和客户端归属，后续默认使用有效缓存，由后台刷新。AuthenticateBearer 建立可信 Principal；RequirePermission("orders:read") 必须位于认证之后。应用角色 admin 不隐含全部权限。
- OIDC token 与第一方 password bridge 的 opaque token 属于不同会话；后者使用 VerifyPasswordSession / LogoutPasswordSession，不能交给 OIDC introspection。
- 标准鉴权默认缓存身份和权限，后台定时刷新；权限撤销、封禁和会话撤销最多延迟一个缓存有效期。缺失 decision、批量结果不完整、没有有效缓存时的网络/服务错误均不放行。

### 默认缓存与后台刷新

复用一个服务级 Client。Can / CanResource / RequirePermission 使用用户最终权限快照；Introspect / AuthenticateBearer 缓存 OIDC 认证结果；VerifyPasswordSession 缓存密码桥接会话。首次访问各自查询一次 Account，后续有效缓存命中不发送请求。后台按单个用户或 token 查询，无需业务请求触发，不调用 GitHub/Google，也不自动刷新登录令牌。

~~~go
client, err := account.New(account.Config{
    BaseURL: "https://account.example.com",
    ClientID: clientID,
    ClientSecret: clientSecret,
    // 零值即以下默认配置；通常可以省略。
    Cache: account.CacheConfig{
        TTL: time.Minute,
        RefreshInterval: 30 * time.Second,
        IdleTimeout: 5 * time.Minute,
        MaxEntries: 10000,
        RefreshConcurrency: 4,
    },
})
if err != nil { return err }
defer client.Close() // 服务关闭时停止调度并取消未完成的缓存查询
~~~

- TTL 从查询开始计时，不能超过 60 秒；权限响应的 valid_until、token 的 exp 或密码会话到期时间会进一步缩短期限。RefreshInterval 必须小于 TTL；后台提前随机错峰刷新。权限快照返回 version 与 valid_until；版本用于诊断，SDK 每次刷新都读取状态和权限，不能只凭版本不变沿用授权。
- 身份和权限条目分别记录最近调用时间。后台刷新不会更新该时间；默认空闲五分钟后清理条目并停止轮询，回来后重新加载。一个用户的不同 token 分别认证，权限按用户共享。每个 Client 自带隔离缓存，多进程各自刷新；容量包含认证和权限条目，满额淘汰最久未使用条目。
- 同一条目的并发查询合并，后台与前台查询共享并发限制。单个请求取消只取消自身等待；共享查询仍受 HTTPClient 超时及 Close 控制。容量耗尽或关闭中的调用会返回错误。
- 刷新失败不延长旧授权；尚未过期的快照可以继续使用，过期后必须成功查询才能放行。明确的身份失效或权限拒绝立即清除旧授权。成功的 SDK 写操作和 Revoke 清理此 Client 的缓存；其他 Client、实例、管理后台的变更由后台刷新或硬过期发现。
- ApplicationEntitlements 返回副本，HasPermission / HasRole 检查其有效期。不要自行无限保存快照。权限判断适用于当前 resource:action 并集模型；数据所有权与租户约束由业务后端处理。
- 后台轮询仍受 Account 的接口限流约束；单实例活跃用户增加时须结合 Account 容量、IP 限额和刷新间隔评估。缓存容量不表示服务端允许同等数量用户同时轮询。

需要即时验证时，显式调用 CanOnline / CanResourceOnline、IntrospectOnline、VerifyPasswordSessionOnline 或 ApplicationEntitlementsOnline。EvaluateAccess / EvaluateAccessBatch 保持原始在线协议行为。敏感操作必须同时考虑身份和权限的新鲜度。Cache.Disabled=true 可整体切回在线模式。

升级顺序：先部署增加权限快照 version / valid_until 的 Account，再更新 SDK。新版 SDK 拒绝缺少有效期限的旧快照，避免静默使用没有服务端期限的授权。缓存模式改变了此前每次请求立即查撤销的语义，需按业务可接受的撤销延迟配置。

## Account 托管的 Web 应用会话

希望只保存浏览器 Cookie、无需业务应用维护登录会话库或刷新令牌时，使用 Account 应用会话扩展。普通标准 OIDC 接口和 CompleteLogin / Refresh 保持不变。

1. 服务端 DiscoverOIDC（通常只需 openid/profile/email）与 BeginLogin 发起标准授权码 + PKCE；将 LoginTransaction 加密保存在 HttpOnly、SameSite=Lax 的短期浏览器 Cookie，或现有服务端事务存储中。所有实例共享加密密钥，并验证 Cookie 期限、state 与回调 issuer。授权码由 Account 原子地单次消费，重放不能创建第二个会话。
2. 回调调用 CompleteApplicationLogin。SDK 先验证标准 OIDC state/nonce/PKCE/ID Token，再用有效 access token 交换 Account 不透明应用会话凭据。只将返回 Token 加密保存到本应用 HttpOnly Cookie；Cookie 期限取 CookieExpiresAt，旧服务未返回该字段时取 ExpiresAt。不要保存 OAuth access/refresh token，也不需要自行轮换它们。
3. 每次请求通过 VerifyApplicationSession 验证 Cookie 中的 Token，用户标识只能取验证结果。默认本地缓存并后台刷新；VerifyApplicationSessionOnline 适用于敏感操作。ValidUntil 限制缓存期限，ExpiresAt 为 Account 当前会话期限；AbsoluteExpiresAt 表示策略硬期限，其中 9999 年表示不强制定期登录，不能作为 Cookie 期限。缓存丢失后重新读取 Account 即可，无须用户重新登录。真实用户活跃请求按下文调用 RenewApplicationSession，单纯核验不会保活。
4. 退出调用 LogoutApplicationSession，Account 撤销同一应用会话并审计，成功后清除浏览器 Cookie。其他实例的 SDK 缓存最多仍有一个缓存有效期的传播延迟；需要即时生效的操作必须在线验证。

密码 API 新签发的 Token 也可使用统一验证/注销接口，但密码来源的会话仍要求现有独立密码 API 授权；不能通过统一接口绕过授权。撤销密码 API 授权只撤销密码桥接来源会话，不影响通过 Account 邮箱页面完成的 OIDC 会话。此能力仅供持有有效凭据的 confidential 服务端应用使用，不将 Client Secret 暴露给浏览器。

Account 需要先升级迁移 14。网络、服务或存储故障返回错误，接入应用应保留 Cookie 并提示重试，不能在没有有效缓存时放行；明确会话失效才清除登录。浏览器跨应用 SSO 仍通过 Account 域名的登录态完成，站内密码 API 不会替浏览器创建 Account 网站 Cookie。

## 管理 API

管理操作仍要求 Account 管理员 Cookie、Origin 和独立 admin CSRF；权限配置仅限 super_admin，受最近身份验证与 MFA 控制。应用内 admin 无法管理 Account。

已有应用的邮箱密码 API 授权由 ApplicationPasswordAPI / SetApplicationPasswordAPI 管理；ApplicationPasswordAPIEvents 查询该应用授权审计。只有超级管理员可修改，写入显式 Enabled 和读取时的 Version，授权独立于第一方标记和普通应用配置。启用不改变 Client ID/Secret、OIDC 配置、角色或会话；撤销作废密码桥接会话，保留 OIDC 会话。持有应用密钥本身不能调用这些管理接口。

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

## 动态策略与活跃续期（Account 迁移 15）

Account 管理端的「登录会话」配置普通用户及管理后台的独立策略。默认普通用户 30 天未活跃过期、不强制定期登录、7 天轮换凭据；管理后台默认空闲 30 分钟、最长 8 小时、1 小时轮换。敏感操作复验默认 5 分钟。策略修改版本化且审计，不需要重启；已过期或撤销的会话不会恢复。

VerifyApplicationSession / VerifyApplicationSessionOnline 只检查状态，后台刷新不会延长登录。只有真实用户交互触发的请求才调用 RenewApplicationSession；不要从定时器、SSE 心跳、后台任务或权限轮询调用它。SDK 对同一 token 的并发请求合并，并以服务端 renew_after 限制活跃上报；内存清空/重启后首次重报是安全的。续期回执不作为五分钟授权，SDK 仍独立验证最多 60 秒有效的身份缓存；敏感操作继续在线验证。

~~~go
identity, err := client.VerifyApplicationSession(ctx, account.VerifyApplicationSessionInput{Token: opaque})
if err != nil { return err }
if userInitiated {
    renewed, err := client.RenewApplicationSession(ctx, account.RenewApplicationSessionInput{Token: opaque})
    if err != nil { return err }
    // 若 renewed.Token != nil，替换加密 HttpOnly Cookie 中的不透明凭据。
    // Cookie 保存期限采用 renewed.CookieExpiresAt；按日或接近到期才续写，
    // 收到替换凭据时立即写入。不要使用无硬期限的 AbsoluteExpiresAt 作为 Cookie 年限。
    _ = renewed
}
_ = identity
~~~

Cookie 期限取 cookie_expires_at，身份有效期取 expires_at；absolute_expires_at 为兼容既有类型保留，9999 年表示策略不强制定期登录，并非应签发的 Cookie 期限。轮换先返回同一个待确认凭据，直到后续请求证明新凭据已收到才推进；旧凭据随后有 5 分钟并发宽限。响应丢失可使用旧凭据安全重试，SDK 不把续期请求加入后台刷新。凭据数据库以哈希查询，待确认和短期恢复材料使用 Account 密钥加密保存，不能记录日志。

ListSessionPolicies / SaveSessionPolicy / RevokePolicySessions 是管理员 API，不可由业务应用凭据调用。修改策略和按范围下线均要求超级管理员及近期复验；保存必须使用当前 version。先升级 Account 迁移 15，再更新 SDK 和接入应用；仅升级 SDK 不会自动将后台任务认定为用户活跃。
