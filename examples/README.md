# Go BFF + Vue 接入示例

后端：examples/bff；前端：examples/vue。前端使用 @cylism/expressive-vue，登录和权限由后端的 Go SDK 对接 Account，前端直接调用本示例的后端接口。

## 运行

在 Account 创建 confidential 应用，scope 包含 openid profile email offline_access，登记精确回调 http://127.0.0.1:18108/auth/callback 。按需启用 GitHub / Google，平台 key 与按钮一致。

仓库根目录构建：

~~~sh
npm --prefix examples/vue ci
npm --prefix examples/vue run build
~~~

在 SDK 仓库根目录启动，从环境或秘密存储提供应用凭据：

~~~sh
export ACCOUNT_ISSUER=https://account.crazycoding.top
export ACCOUNT_CLIENT_ID=你的应用客户端ID
# 设置 ACCOUNT_CLIENT_SECRET 为应用密钥，不要提交到仓库
go run ./examples/bff
~~~

打开 http://127.0.0.1:18108 。示例不自动创建用户/应用/权限。登录后在 Account 为该成员角色明确授予 orders:read，再点刷新权限；后端 /api/orders 每次仍在线检查登录和权限。

前端 npm run dev 的 18109 仅用于界面热更新；完整登录、退出使用 18108。生产改 HTTPS、Secure Cookie、真实回调和配置化 origin。

## 范围

单进程本地示例：内存会话和登录事务各最多 1000 条并带过期时间，重启后重新登录。登录事务在服务端绑定浏览器 Cookie 并原子消费。Account 令牌不进入浏览器，刷新串行化。退出删除本地会话并尽力撤销远程 token。

多实例上线需共享持久会话、刷新锁、Secure Cookie、部署限流和远程撤销重试策略。应用自行检查记录归属和租户边界。
