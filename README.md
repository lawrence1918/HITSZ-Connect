# HITSZ Connect

HITSZ Connect 是面向哈尔滨工业大学（深圳）aTrust 校园资源访问的客户端，提供原生 macOS App
和命令行程序。它支持 HITSZ 统一认证、多因素认证、校内 DNS 中继，以及与 Shadowrocket 的安全
分流协作。

当前发布版本为 **HITSZ Connect 1.3.10**，内置 CLI 版本为 **1.3.10-hitsz.1**。

> 非校方官方客户端。本软件按现状提供，不保证可用性、连续性或对任何网络环境的兼容性；请自行评估
> 风险并遵守学校网络与服务使用规定。

## 与 zju-connect 的关系

本项目是 [Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect) 的 HITSZ 专用
适配 fork；上游项目又基于已停止维护的
[EasierConnect](https://github.com/lyc8503/EasierConnect)。本项目保留上游的 EasyConnect/aTrust
通信核心和大量通用参数，并新增或调整：

- HITSZ CAS / 统一认证流程及默认 aTrust profile；
- HITSZ App、短信和安全令牌 OTP 多因素认证；
- 仅允许 HITSZ DNS 查询的本地 TCP/UDP relay；
- 面向 Shadowrocket 的本地 SOCKS5 分流、动态规则片段和 fail-closed ACL；
- 原生 SwiftUI App、每秒流量状态，以及由 AES-256-GCM 和 macOS 钥匙串保护的连接配置。

HITSZ 是本 fork 的维护和实际验证重点。其他学校及上游通用功能仍保留在源码中，但请以
`zju-connect` 上游项目为准，不能视为本 fork 的发布承诺。为保持与上游代码兼容，`go.mod` 和
内部 Go import path 目前仍沿用 `github.com/mythologyli/zju-connect`；项目目录、发行名和 Git
远端使用 `hitsz-connect`。

原项目的署名和 [AGPL-3.0](LICENSE) 许可证继续适用。

## 特性与边界

- 使用 `-profile hitsz` 自动选择 `trust.hitsz.edu.cn`、`hitcas` 和 HITSZ aTrust 默认值。
- 支持 HITSZ App、短信和本地生成的 TOTP/OTP MFA。
- App 和正式 CLI 共用 `~/Documents/hitsz-connect/*.hcenc` 加密配置；密码、OTP 种子和 aTrust
  会话数据不需要出现在 argv、环境变量或明文 TOML 中。
- 本地 SOCKS5 / HTTP 仅监听 `127.0.0.1:1080` / `127.0.0.1:1081`。
- DNS relay 仅接受 `hitsz.edu.cn` 及其子域，并经 aTrust TCP 栈访问 `10.248.98.30:53`；它不
  接管其它域名的 DNS。
- Shadowrocket 的动态规则会将服务器下发的资源域名，以及已确认的 `10.248.*`、`10.249.*`、
  `10.250.*` 校园资源转发至本地 SOCKS。未获 aTrust ACL 授权的目标会被拒绝，不会回落为直连。
- App 发起连接时会先静默暂停已有 Shadowrocket，再让 aTrust 认证使用系统路由；本地 SOCKS、
  HTTP 和 DNS relay 就绪后再静默恢复或连接。控制优先使用 `scutil --nc`；若 URL scheme 启动的
  活动 `utun` 不受该服务控制，则回退到 CLI 同款 `open -g -j` 隐藏后台命令，不会打开或置前窗口。
- 普通外网流量仍由你在 Shadowrocket 中选定的节点和 `FINAL,PROXY` 规则处理。

## 支持范围

| 项目 | 发布状态 |
| --- | --- |
| macOS 13+ / Apple Silicon (`darwin/arm64`) | App 与 CLI 正式交付并实测 |
| Shadowrocket 协作 | 仅 macOS |
| 其它平台 | 可自行从源码构建，未作为本 fork 的 HITSZ 正式交付目标 |
| 上游通用校园功能 | 保留源码，兼容性请参考上游项目 |

## 推荐方式：macOS App

使用 App 前仍需把
[基础 Shadowrocket 片段](dist/hitsz/shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf)
合并到活动配置，并将其中的 `[Rule]` 条目放在通用私网 `DIRECT` 与 `FINAL` 之前。App 可以连接或
断开 Shadowrocket，但不会替你导入、合并或激活配置。

仓库已构建的 Apple Silicon App 位于
[dist/macos/HITSZ Connect.app](<dist/macos/HITSZ Connect.app>)。本地安装可执行：

```sh
ditto "dist/macos/HITSZ Connect.app" "/Applications/HITSZ Connect.app"
open "/Applications/HITSZ Connect.app"
```

当前仓库内的 App 使用 ad-hoc 签名，适合本机测试，不等同于 Developer ID 签名和 Apple 公证。
若可信来源下载的副本被 macOS 隔离，可在核对来源后移除隔离属性：

```sh
xattr -dr com.apple.quarantine "/Applications/HITSZ Connect.app"
```

首次打开后：

1. 创建加密配置，填写学号或手机号、统一认证密码和 MFA 方式；OTP 方式还需填写 OTP 种子。
2. 按需启用“启动 aTrust 后连接 Shadowrocket”，保存并选择配置。
3. 点击“发起连接”。App/短信 MFA 会在 App 内请求验证码；OTP 在本机生成。
4. 主窗口和菜单栏可查看 aTrust、监听端口、Shadowrocket 状态及实时/累计流量；使用“关闭连接”
   可向内置 CLI 发送干净停止命令。

配置文件固定保存在 `~/Documents/hitsz-connect/`，扩展名为 `.hcenc`。目录权限为 `0700`，文件
权限为 `0600`；每个配置使用独立 AES-256-GCM 密钥，密钥位于当前 Mac 的钥匙串。单独复制
`.hcenc` 到另一台 Mac 不会复制密钥，因此不能在那里解密，应在目标设备重新创建配置。

## 加密配置 CLI

App 创建的加密配置也可由正式 CLI 直接使用。先列出 UUID、名称和更新时间：

```sh
./dist/hitsz/hitsz-connect-darwin-arm64 -list-secure-configs
```

再用 UUID 启动：

```sh
./dist/hitsz/hitsz-connect-darwin-arm64 -secure-config '<配置 UUID>'
```

`-secure-config` 与 `-list-secure-configs` 必须单独使用，不能再附加用户名、密码或其它运行参数；
请在 App 中编辑配置。连接成功后，更新的 aTrust `clientData` 会自动重新加密写回同一 `.hcenc`
文件。此工作流依赖 macOS 钥匙串和 cgo；正式 macOS CLI 必须使用 `CGO_ENABLED=1` 构建。

## 旧版明文 CLI（兼容模式）

正式 Apple Silicon 可执行文件位于
[dist/hitsz/hitsz-connect-darwin-arm64](dist/hitsz/hitsz-connect-darwin-arm64)。首次下载后如被
macOS 标记为隔离文件，可运行：

```sh
xattr -rd com.apple.quarantine ./hitsz-connect-darwin-arm64
```

先将 [基础 Shadowrocket 片段](dist/hitsz/shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf)
合并到活动配置。首次登录建议先只生成账户当前的规则片段：

```sh
./dist/hitsz/hitsz-connect-darwin-arm64 \
  -profile hitsz \
  -username '<学号或手机号>' \
  -password '<统一认证密码>' \
  -mfa-method otp \
  -mfa-otp-secret-file ./hitsz-otp.secret \
  -client-data-file ./hitsz-client-data.json \
  -shadowrocket off \
  -shadowrocket-config-fragment ./hitsz-shadowrocket.conf
```

将生成文件中 `[Proxy]`、`[Rule]`、`[Host]` 的条目合并到 Shadowrocket 的活动配置，且把规则放在
通用私网 `DIRECT` 与 `FINAL` 之前。随后使用同一命令加上 `-shadowrocket connect` 启动并连接。

使用 App 或短信 MFA 时，将 `-mfa-method` 改为 `app` 或 `sms`；程序会在终端提示输入动态码。

这些参数保留用于上游兼容和调试，不是 1.3.10 的推荐凭据存储方式：`-password` 可能进入 shell
历史和进程列表，`-mfa-otp-secret-file`、`-client-data-file`、`-config` 及生成的规则文件均为
明文文件。必须使用时，应限制文件权限、退出后妥善处置，并避免把任何内容提交、同步或贴入问题
报告。新安装优先使用 App 或 `-secure-config`。

## Shadowrocket 分流原则

- macOS App 优先通过系统 VPN 服务静默控制 Shadowrocket；当 `scutil` 状态与实际运行的
  Shadowrocket `utun` 不一致时，使用 `open -g -j` URL scheme 兜底。两条路径都不会打开或置前
  窗口；App 不会替你导入或激活配置，必须先合并规则。
- 不要将整个 `10.0.0.0/8` 指向 `HITSZ-aTrust`，也不要为 `10.248.98.30` 添加排除路由。
- `dist/hitsz/legacy/` 是面向旧官方 aTrust 客户端的历史配置，不能与内置 HITSZ relay 同时作为
  活动方案。
- 账户相关的 `-shadowrocket-config-fragment` 输出应在 aTrust 资源变化后重新生成；不要提交它。

## 登录 401 排查

- HITSZ profile 默认使用系统路由，不再强制把 CAS/IdP socket 绑定到自动检测的物理接口。只有明确
  需要时才手动启用 `-auto-detect-interface` 或指定 `-bind-interface`；Fake-IP VPN 同时运行时优先
  保持默认值。1.3.1 App 已保存的加密配置会在运行时自动迁移，无需删除或重新录入。
- 程序会在提交密码前执行官方验证码预检。需要滑块时，会在默认浏览器打开仅监听
  `127.0.0.1` 的临时验证页，并使用当前 HITSZ Connect 登录会话提交官方拼图结果；验证完成后
  自动继续连接。直接打开 `ids.hit.edu.cn` 可能复用浏览器自己的 CAS 会话，因此不能替代该页面。
- `-non-interactive` 不会打开滑块页面；服务端要求滑块时会明确退出。App 默认允许交互验证。
- 其余 HTTP 401 还可能表示密码被拒绝或账号风控。参考实现记录的已知风控条件包括累计并行会话或
  登录 IP 过多；程序不会自动绕过这类服务端限制。

## 安全注意事项

- 推荐使用 App / `-secure-config`；`.hcenc` 只保存密文，解密密钥保存在当前用户的 macOS 钥匙串。
- 密码、OTP 种子、验证码、CAS ticket、Cookie、订阅 URL、节点 URI 和
  `*-client-data.json` 都属于敏感数据，不能提交、同步或贴入问题报告。
- OTP 种子文件应为普通文件且仅当前用户可读，例如 `chmod 600 hitsz-otp.secret`。
- `-client-data-file` 保存登录会话，等同于凭据；请妥善保管。
- 本 profile 的代理默认仅绑定 loopback；不要将其暴露至局域网或公网。

## 文档与发行内容

- [HITSZ 使用说明](docs/hitsz/README.md)
- [Shadowrocket 说明](docs/hitsz_shadowrocket.md)
- [实现与验证说明](docs/hitsz/DEVELOPMENT.md)
- [参考资料与敏感数据边界](docs/hitsz/REFERENCES.md)
- [发行目录](dist/hitsz/README.md) 与 [SHA256SUMS](dist/hitsz/SHA256SUMS)
- [macOS App 说明](macos/README.md) 与 [App 交付目录](dist/macos/README.md)

## 构建与验证

```sh
go test ./...
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' \
  -o dist/hitsz/hitsz-connect-darwin-arm64 .
./macos/scripts/build-app.sh
codesign --verify --deep --strict --verbose=2 "dist/macos/HITSZ Connect.app"
```

加密配置需要 Security.framework，因此以上正式构建应在安装了 Xcode Command Line Tools 的 macOS
机器上完成，不能以 `CGO_ENABLED=0` 替代。请使用 `hitsz-connect-darwin-arm64 -version` 核对 CLI
版本。

`dist/hitsz/SHA256SUMS` 只覆盖 `dist/hitsz` 内列出的 CLI、文档和配置文件，可在该目录运行
`shasum -a 256 -c SHA256SUMS`。App 是目录 bundle，当前本地构建应使用上面的 `codesign` 命令验证；
面向公众分发时仍需 Developer ID 签名、公证，并为最终归档文件单独发布校验和。
