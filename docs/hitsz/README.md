# HITSZ Connect / aTrust 交付与使用说明

本目录记录 HITSZ Connect（基于 `zju-connect` 的 HITSZ 专用适配）的 HITSZ aTrust：HITSZ 统一认证、App/短信/OTP
多因素认证、仅限 HITSZ 域名的 DNS 中继，以及 macOS Shadowrocket 协作。

推荐从仓库根目录的 [dist/hitsz](../../dist/hitsz) 取得已构建的 Apple Silicon
可执行文件和配置片段。该二进制是 `darwin/arm64` Mach-O；它不适用于 Intel Mac、
Windows 或 Linux。

## 最短启动方式

先在 Shadowrocket 合并
[基础片段](../../dist/hitsz/shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf)，
然后在终端运行：

```sh
./dist/hitsz/hitsz-connect-darwin-arm64 \
  -profile hitsz \
  -username '<手机号或学号>' \
  -password '<统一认证密码>' \
  -mfa-method otp \
  -mfa-otp-secret-file /path/to/hitsz-otp.secret \
  -client-data-file ./hitsz-client-data.json \
  -shadowrocket connect
```

OTP 密钥文件只能包含一个 Base32 种子或 `otpauth://totp/...` URI，且必须为普通文件、
仅当前用户可读，例如 `chmod 600 /path/to/hitsz-otp.secret`。不要将密钥写入命令行、
TOML 文件、日志或 Git 仓库。

使用 App 或短信 MFA 时，将 `-mfa-method` 改为 `app` 或 `sms`。程序会发送动态码并在
终端提示输入；受控的无人值守场景才应使用 `-mfa-code` 和 `-non-interactive`。

## 推荐的 Shadowrocket 方式

`-profile hitsz` 会启动 `127.0.0.1:1080` 上仅限本机访问的 SOCKS5，以及
`127.0.0.1:53535` 上的 UDP/TCP DNS 中继。基础片段会：

1. 设置 `always-real-ip = *`，避免和 aTrust 的 Fake-IP 路由发生冲突；
2. 把 `hitsz.edu.cn` 与 `*.hitsz.edu.cn` 的 DNS 交给本地中继；
3. 新增 `HITSZ-aTrust = socks5, 127.0.0.1, 1080`，并把 HITSZ 域名及服务器下发的
   明确资源域名（例如馆藏资源）交给它。

中继只接受 HITSZ 域名，并通过 aTrust TCP 栈访问 `10.248.98.30:53`；其他查询返回
`REFUSED`，不会回落到系统 DNS、明文 DNS 或中国公共 DNS。因此 Shadowrocket 原有的加密
DNS 和其它分流规则仍然负责非 HITSZ 域名。

校内的直连 IP 服务还需要 aTrust 当前下发的精确前缀。登录后附加
`-shadowrocket-config-fragment /path/to/hitsz-shadowrocket.conf`，程序会写出可合并的
`IP-CIDR` 规则；这些规则只会覆盖已确认的 `10.248.0.0/16`、`10.249.0.0/16` 与
`10.250.0.0/16`，其他服务端下发的私网地址会被忽略，以免截获本地 LAN。将规则放在
Shadowrocket 的通用私网 `DIRECT` 规则和 `FINAL` 之前。不要把整个 `10.0.0.0/8` 指向本地
SOCKS。资源规则会随账号和服务器策略变化，应在资源更新后重新生成。

`-shadowrocket open` 或 `-shadowrocket connect` 会在本地 SOCKS 和 DNS relay 准备就绪后
调用 macOS 的 Shadowrocket URL scheme。它不会替用户导入或激活规则配置；必须先完成上述
一次合并。它只表示系统已接收启动/连接命令；Shadowrocket 没有可供本程序可靠读取的隧道
已建立状态回调。

AnyTLS 节点由 Shadowrocket 自身处理。若要导入一个节点，请把**唯一一行** `anytls://`
URI 放入权限受限的文件，再使用 `-shadowrocket-add-node-file <文件>`；程序只校验 URI 并
交给 Shadowrocket，绝不在自己的代理栈中传输该节点。

## 文档索引

| 文档 | 内容 |
| --- | --- |
| [DEVELOPMENT.md](DEVELOPMENT.md) | 架构、认证状态机、DNS 边界、生命周期与测试记录。 |
| [REFERENCES.md](REFERENCES.md) | 全部参考资料的来源、归档方式、许可证和敏感数据边界。 |
| [现有 Shadowrocket 说明](../hitsz_shadowrocket.md) | CLI 参数、OTP 秘钥处理和片段使用说明。 |
| [抓包脱敏摘要](../hitsz-references/README.md) | 三份浏览器抓包的端点顺序与实现结论；不含任何可重放内容。 |
| [发布目录说明](../../dist/hitsz/README-hitsz-connect.txt) | 二进制随附的简要使用说明。 |

## 旧版兼容配置

[dist/hitsz/legacy](../../dist/hitsz/legacy) 中保留了一份面向**官方 aTrust 客户端**的完整
Shadowrocket 配置，便于回溯旧方案。它使用固定 DoH、GEOIP 和全局规则，且假定另行启动历史
独立中继；不要与当前 `hitsz-connect -profile hitsz` 的内置中继同时使用（两者都会占用
`127.0.0.1:53535`）。当前适配的默认方案始终是上面的最小 DNS 片段。

## 安全与状态文件

- `-client-data-file` 保存 aTrust/IdP 会话状态，成功登录后以 `0600` 写入。它是凭据，
  不应归档、同步或提交。
- OTP 种子、验证码、密码、CAS ticket、Cookie、订阅 URL 和节点 URI 都不应出现在文档、
  截图、命令历史或问题报告中。
- HITSZ profile 禁止 Fake-IP、全局 DNS 劫持和 macOS `networksetup` DNS 改写；请不要再为
  `10.248.98.30` 添加 Shadowrocket 的 excluded route，否则可能覆盖 aTrust 的更具体路由。
