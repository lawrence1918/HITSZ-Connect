# HITSZ aTrust KOReader 插件

这个目录就是要复制到 Kindle 的 KOReader 插件目录中的完整目录：

```text
/mnt/us/koreader/plugins/hitsz_connect.koplugin/
```

## 先配置，再上传

1. 在电脑上复制 `config.lua.example` 为 `config.lua`，然后只编辑 `config.lua`。
2. 填写 `username`、`password`，并明确选择 `mfa_method = "app"`、`"sms"` 或 `"otp"`。
3. 选择 OTP 时，把 Base32 种子或 `otpauth://` URI 写入 `mfa_otp_secret`。
4. 确认 `config.lua` 中不再有 `REPLACE_WITH_` 占位符，然后把整个 `hitsz_connect.koplugin` 文件夹复制到上面的目录。
5. 重启 KOReader，进入“设置 → 网络 → HITSZ aTrust”，点击 “Connect”。

密码和 OTP 种子会以明文存在 `config.lua` 中；Kindle 的 USB 存储不提供可靠的 Unix 文件权限保护，
因此不要把配置文件分享给他人。插件启动时会尽力将运行目录限制为当前用户可读（`0700/0600`）。
仓库已忽略 `config.lua` 和 `state/`，避免误提交凭据与会话数据。

## MFA

- `app`：统一认证页面要求验证码时，KOReader 会弹出数字输入框。
- `sms`：插件会等待短信验证码，并在 KOReader 中弹出输入框。
- `otp`：由 Go 核心在设备本地生成 TOTP，不需要网络发送种子。

滑块安全验证仍由核心的临时本地网页处理；如果 Kindle 没有可用的 `xdg-open`，请查看
“Status / log” 中的 `http://127.0.0.1:端口/...` 地址，并在 Kindle 浏览器中手动打开。

连接后可供 Kindle 程序使用的本地代理是 `127.0.0.1:1080`（SOCKS5）和 `127.0.0.1:1081`
（HTTP）。插件不会修改 Kindle 系统 DNS。设备进入休眠或 Wi-Fi 断开后，通常需要重新点击
“Connect”。

插件固定使用代理模式，因此 `ping`、普通 SSH 和未配置代理的程序不会自动进入 aTrust。请为需要访问
内网的 Kindle 程序配置代理，例如：

```sh
curl --socks5-hostname 127.0.0.1:1080 http://net.hitsz.edu.cn/
curl -x http://127.0.0.1:1081 http://net.hitsz.edu.cn/
```

核心发出 `ready/connected` 事件后，插件会提示：`连接成功，请设置HTTP代理为http://127.0.0.1:1081`。

若日志出现 `x509: certificate signed by unknown authority`，可在 `config.lua` 中设置
`ca_cert_file`，指向 Kindle 上 KOReader 自带的 CA 证书文件。

如果核心无法启动，插件应显示错误而不会退出 KOReader。Lua 回调错误写入 `state/plugin.log`，
启动探测写入 `state/launcher.log`，核心输出写入 `state/connect.log`。包含凭据的一次性启动请求和
运行时控制 FIFO 都位于 `/tmp`，不会放进不支持命名管道的 Kindle USB 存储或 `state/`。

`state/client_data.b64` 用于复用 aTrust 设备与会话状态。插件会检查其 Base64/JSON 外形并采用临时文件
原子替换；发现旧缓存损坏时会自动删除，随后执行一次完整登录。

插件的 JSON 编码采用逐字节转义，兼容 Kindle KOReader 使用的 LuaJIT；不要换回包含 NUL 字节范围的
Lua pattern，否则 LuaJIT 会报告 `malformed pattern (missing ']')`。

插件加载时会将 KOReader 提供的相对插件路径转换为绝对路径，避免后台启动器进入插件目录后再次
拼接 `plugins/hitsz_connect.koplugin`，造成二进制存在却报告 `No such file or directory`。

## 架构

`bin/` 中包含 Kindle ARM（`armv7l/armv6l`）和 64 位 ARM（`aarch64`）核心。若需要重新构建，
在仓库根目录运行 `./koreader/build.sh`。
