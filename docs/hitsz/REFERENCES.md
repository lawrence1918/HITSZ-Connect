# HITSZ / aTrust 参考资料清单

本清单区分“可安全归档的公开参考源码”与“只允许在本机查看的敏感原件”。目标是让开发结论
可追溯，同时不把会话、OTP、订阅或账号数据带进项目目录。

## 已归档的公开参考源码

HITSZ Srun Login 工程中实际用于理解 HITSZ SSO、MFA、TOTP 和 Cookie 行为的文件已经按原样
快照到 [reference-source/hitsz-srun-login](reference-source/hitsz-srun-login)：

| 文件 | 作用 | SHA-256 |
| --- | --- | --- |
| `README.md` | CLI/MFA 行为与来源说明。 | `3e4355dcc12ecc3a4d4a02ec6bd108285170065c45b01d214fdc37c2f73e545b` |
| `LICENSE` | 上游 MIT License（PageChen04）。 | `8167b4deeb8b0543e5ed303b7e74aa8f9748cf7694f278b2062c40bc0cee6483` |
| `auth.go.txt` | 登录页、`pwdEncryptSalt` 与 AES 密码流程参考。 | `a5e89b804204549e895451a6e7b08f5e89385e73bd58459e9543fd566cdf83e9` |
| `mfa.go.txt` | MFA 类型、动态码和二次认证流程参考。 | `545ea82e8a20e5944709ec7bd2a23cc9cb11742ad1ac7e36e6198b9676b51e7b` |
| `otp.go.txt` | SHA-1/30 秒/6 位 TOTP 参考。 | `ba95455172e94b8d6c715723ef51df214eb6be8725cbca790bbaea5cae4feb2e` |
| `cookiejar.go.txt` | Cookie 持久化属性参考。 | `ba40dace63c0f7568451d628219fade1705f35edee2a125e1f03a8e80d09986f` |

这些文件的原始位置为
`/Users/heheyizhi/Documents/coding_program/hitsz-srun-login/`。快照保留其上游 LICENSE；
任何进一步的逐行复用或再发布都应继续保留该版权和许可证。

上游的四个 Go 源文件在本仓库中以 `.go.txt` 后缀保存，内容及 SHA-256 不变。这能明确它们
是文档快照，并避免 `go test ./...` 把参考工程误识别为本模块的可编译包。

## 浏览器抓包：只归档脱敏结论

下列原件用于确认真实浏览器的 CAS 回调、二次认证和 portal 顺序：

| 原件 | 原始位置 | 归档方式 |
| --- | --- | --- |
| `atrust.txt` | `/Users/heheyizhi/Downloads/atrust.txt` | 不复制；见 [抓包脱敏摘要](../hitsz-references/README.md)。 |
| `aTrust2.txt` | `/Users/heheyizhi/Downloads/aTrust2.txt` | 不复制；见同一摘要。 |
| `atrust3.txt` | `/Users/heheyizhi/Downloads/atrust3.txt` | 不复制；见同一摘要。 |

原始 Burp/HTTP 导出包含请求和响应正文、Cookie、CAS ticket、账号标识、验证码及会话字段。
即使这些值稍后过期，仍不能作为项目文档、测试 fixture 或附件保存。脱敏摘要只保留端点路径、
HTTP 方法、字段名、响应类别和顺序，并给出原件的 SHA-256 以便本机核对。

## 诊断资料：明确排除

以下资料曾用于排查 DNS/Fake-IP/订阅交互，但不作为项目归档物：

| 类别 | 排除原因 | 可替代内容 |
| --- | --- | --- |
| Quantumult X 配置与粘贴附件 | 包含订阅 URL token、节点 URI 和密码字段。 | 当前推荐的最小 [Shadowrocket DNS 片段](../../dist/hitsz/shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf)。 |
| 终端粘贴记录 | 可能含密码、token、一次性验证码或命令历史。 | [开发说明](DEVELOPMENT.md) 中的脱敏流程。 |
| OTP 密钥文件 | 长期认证凭据。 | 仅在运行时以 `-mfa-otp-secret-file` 读取。 |
| `hitsz-client-data.json` | aTrust/IdP Cookie 与设备状态。 | 每位用户本地创建，权限 `0600`。 |
| 独立历史 DNS relay 二进制/脚本 | 已被内置 relay 取代，且会同当前 relay 竞争 `53535`。 | 内置 `-profile hitsz` DNS relay。 |

## 可复核的交付物

已构建可执行文件和无凭据的 Shadowrocket 文件位于 [dist/hitsz](../../dist/hitsz)。其中：

- `shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf` 是当前推荐的、最小的配置。
- `legacy/Shadowrocket-aTrust-HITSZ.conf` 是历史的官方 aTrust 客户端兼容配置，只供回溯；
  它不含订阅或节点，但不应作为新方案默认配置。
- `SHA256SUMS` 可用于完整性核验。

归档前已检查以上交付物不含密码、OTP 种子、Cookie、CAS ticket、订阅 URL、AnyTLS URI 或
节点私钥。若以后从真实抓包生成示例，请先通过同等强度的脱敏审查。
