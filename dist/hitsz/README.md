# HITSZ Connect CLI 交付目录

本目录包含 **HITSZ Connect CLI 1.3.9-hitsz.1** 的 Apple Silicon
(`darwin/arm64`) 构建，以及不含凭据的 Shadowrocket 配置。推荐 macOS 13+ 用户优先使用同仓库的
[HITSZ Connect.app](<../macos/HITSZ Connect.app>)；App 1.3.9 内置与本版本配套的 CLI，并用加密配置
代替命令行明文凭据。

## 内容

| 路径 | 用途 |
| --- | --- |
| `hitsz-connect-darwin-arm64` | HITSZ Connect CLI 1.3.9-hitsz.1，Apple Silicon 可执行文件。 |
| `shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf` | **推荐**导入/合并的基础 DNS 配置。 |
| `legacy/Shadowrocket-aTrust-HITSZ.conf` | 仅供官方 aTrust 客户端旧方案回溯的完整配置。 |
| `README-hitsz-connect.txt` | 随 CLI 发布的简短运行说明。 |
| `SHA256SUMS` | 仅覆盖本目录中列出的 CLI、文档和配置文件。 |

完整说明请阅读[项目 README](../../README.md)和
[HITSZ 使用文档](../../docs/hitsz/README.md)。

## 推荐：通过 macOS App 使用

先把 `shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf` 合并到 Shadowrocket 活动配置，并将
其中规则放在通用私网 `DIRECT` 和 `FINAL` 之前。App 可以按用户设置连接或断开 Shadowrocket，但
不会导入、合并或激活配置；App 优先通过系统 VPN 服务静默控制 Shadowrocket，并在服务状态与实际
`utun` 不一致时使用 `open -g -j` 隐藏后台兜底，不会打开或置前其窗口。

随后可在本目录安装并打开 App：

```sh
ditto "../macos/HITSZ Connect.app" "/Applications/HITSZ Connect.app"
open "/Applications/HITSZ Connect.app"
```

首次打开时创建连接配置并填写认证信息。配置保存在
`~/Documents/hitsz-connect/*.hcenc`：文件内容使用 AES-256-GCM 加密，每个配置的独立密钥保存在当前
Mac 的钥匙串中。`.hcenc` 文件权限为 `0600`，其目录权限为 `0700`；把文件单独复制到另一台 Mac
不会复制钥匙串密钥，因此不能在那里解密。

## 使用加密配置启动 CLI

App 创建的加密配置可以直接交给本目录的 CLI。先列出配置：

```sh
./hitsz-connect-darwin-arm64 -list-secure-configs
```

再选择列表中的 UUID：

```sh
./hitsz-connect-darwin-arm64 -secure-config '<配置 UUID>'
```

`-list-secure-configs` 和 `-secure-config` 必须单独使用，不能与用户名、密码或其它运行参数组合；如需
修改，请使用 App。连接成功后，CLI 会把更新的 aTrust `clientData` 重新加密写回原配置。此功能
依赖 macOS 钥匙串和 cgo；自行构建正式 CLI 时必须使用 `CGO_ENABLED=1`。

## 旧版明文 CLI（仅兼容与调试）

仍可使用 `-profile hitsz`、MFA 和 Shadowrocket 参数直接启动。例如：

```sh
./hitsz-connect-darwin-arm64 \
  -profile hitsz \
  -username '<学号或手机号>' \
  -password '<统一认证密码>' \
  -mfa-method otp \
  -mfa-otp-secret-file ./hitsz-otp.secret \
  -client-data-file ./hitsz-client-data.json \
  -shadowrocket connect
```

这不是新安装的推荐凭据存储方式：`-password` 可能进入 shell 历史和进程列表；
`-mfa-otp-secret-file`、`-client-data-file`、`-config` 及生成的规则文件都是明文。必须使用时，请限制
文件权限，不要提交、同步或粘贴到问题报告中。App 或短信 MFA 可把 `-mfa-method` 改为 `app` 或
`sms`，程序会在终端提示输入动态码。

不要将 `legacy/` 的完整配置和内置 HITSZ relay 同时作为活动方案使用；旧配置假定历史独立 relay，
可能与内置 relay 争用 `127.0.0.1:53535`。

## 完整性校验

在本目录运行：

```sh
shasum -a 256 -c SHA256SUMS
```

`SHA256SUMS` 只覆盖 `dist/hitsz` 内列出的文件，不覆盖相邻的 `dist/macos/HITSZ Connect.app` 目录
bundle。App 可使用 `codesign --verify --deep --strict --verbose=2` 验证当前本地签名；公开分发的归档
还需要单独发布校验和，并使用 Developer ID 签名和 Apple 公证。
