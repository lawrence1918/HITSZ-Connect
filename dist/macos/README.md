# HITSZ Connect macOS App 交付目录

本目录包含 **HITSZ Connect 1.3.8** 的 Apple Silicon App，支持 macOS 13 及以上版本。App bundle
内置 **HITSZ Connect CLI 1.3.8-hitsz.1**：SwiftUI 前端负责配置、MFA 交互和状态展示，实际的
HITSZ 认证、aTrust 通道、本地代理及 DNS relay 由
`HITSZ Connect.app/Contents/Resources/hitsz-connect` 提供。

## 安装与启动

从仓库根目录执行：

```sh
ditto "dist/macos/HITSZ Connect.app" "/Applications/HITSZ Connect.app"
open "/Applications/HITSZ Connect.app"
```

当前仓库内的 bundle 使用 ad-hoc 签名，适合本机测试，但不等同于 Developer ID 签名或 Apple
公证。如果你确认副本来自可信来源，却因下载隔离属性而无法打开，可在核对来源后执行：

```sh
xattr -dr com.apple.quarantine "/Applications/HITSZ Connect.app"
```

不要对来源不明的 App 移除隔离属性。

## 首次使用

使用 App 前，将
`dist/hitsz/shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf` 合并到 Shadowrocket 活动
配置，并把其中规则放在通用私网 `DIRECT` 和 `FINAL` 之前。App 可以按设置连接或断开
Shadowrocket，但不会替你导入、合并或激活配置。连接控制优先使用 macOS 的 `scutil --nc` 系统
VPN 服务；若该状态与实际 Shadowrocket `utun` 不一致，则使用 `open -g -j` 隐藏后台兜底。aTrust
认证前静默暂停已有 Shadowrocket，本地代理就绪后再恢复，不会打开或置前其窗口。

1. 打开 App，新建配置并填写学号或手机号、统一认证密码和 MFA 方式；OTP 方式还需填写 OTP 种子。
2. 按需启用“启动 aTrust 后连接 Shadowrocket”，保存并选中配置。
3. 点击“发起连接”；App/短信 MFA 会在界面中请求动态码，OTP 则在本机生成。
4. 在主窗口或菜单栏查看 aTrust、监听端口、Shadowrocket 和流量状态；使用“关闭连接”干净停止。

若统一认证要求滑块，App 会在默认浏览器打开仅监听 `127.0.0.1` 的临时拼图页；完成后自动继续。
直接打开统一认证主页可能复用浏览器的既有 CAS 会话，不能替代这个验证页。

配置固定保存为 `~/Documents/hitsz-connect/*.hcenc`。目录权限为 `0700`，文件权限为 `0600`；内容
使用 AES-256-GCM 加密，每个配置的独立密钥保存在当前用户的 macOS 钥匙串。单独复制 `.hcenc`
不会复制密钥，在另一台 Mac 上无法解密；应在目标设备重新创建配置。

## 从源码构建

在装有 Xcode Command Line Tools 的 Apple Silicon Mac 上，从仓库根目录运行：

```sh
./macos/scripts/build-app.sh
```

脚本会以 `CGO_ENABLED=1 GOOS=darwin GOARCH=arm64` 构建与当前源码匹配的 CLI，再编译 SwiftUI
前端、组装到 `dist/macos/HITSZ Connect.app` 并进行 ad-hoc 签名。可验证生成的 bundle：

```sh
codesign --verify --deep --strict --verbose=2 "dist/macos/HITSZ Connect.app"
```

公开分发前仍需 Developer ID 签名、公证，并为最终 `.zip` 或 `.dmg` 归档单独生成校验和。相邻的
`dist/hitsz/SHA256SUMS` 只覆盖 `dist/hitsz` 内列出的 CLI、文档和配置，不覆盖本 App 目录 bundle。
