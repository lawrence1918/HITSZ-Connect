# HITSZ Connect macOS 交付目录

本目录包含已验证的 Apple Silicon (`darwin/arm64`) HITSZ/aTrust 构建和无凭据的
Shadowrocket 配置。

## 内容

| 路径 | 用途 |
| --- | --- |
| `hitsz-connect-darwin-arm64` | HITSZ Connect 的正式 Apple Silicon 可执行文件，已具备执行权限。 |
| `shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf` | **推荐**导入/合并的最小 DNS 配置。 |
| `legacy/Shadowrocket-aTrust-HITSZ.conf` | 仅供官方 aTrust 客户端的旧版完整配置回溯。 |
| `README-hitsz-connect.txt` | 发布时随附的简短运行说明。 |
| `SHA256SUMS` | 本目录各已交付文件的 SHA-256 清单。 |

请阅读 [开发与使用文档](../../docs/hitsz/README.md)，特别是 OTP 密钥、会话文件和 DNS 边界。

## 当前推荐组合

1. 在 Shadowrocket 中合并 `shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf`。
2. 启动本二进制并传入 `-profile hitsz` 和所需 MFA 参数。
3. 使用 `-shadowrocket connect`，或自行在 Shadowrocket 中选择并连接节点。

不要将 `legacy/` 的完整配置和内置 HITSZ relay 同时作为活动方案使用。该旧配置假定历史独立
relay，可能与内置 relay 争用 `127.0.0.1:53535`。

在本目录运行下列命令可以核验文件完整性：

```sh
shasum -a 256 -c SHA256SUMS
```
