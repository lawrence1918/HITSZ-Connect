# 参考源码快照说明

此目录是 `/Users/heheyizhi/Documents/coding_program/hitsz-srun-login/` 中本次 HITSZ/aTrust
适配实际参考的公开文件快照。它不是可执行依赖，也不应在此目录中保存 session、配置、账号、
密码或 OTP 秘钥。

为避免 Go 将参考工程混入本模块的构建，`auth.go`、`mfa.go`、`otp.go` 和 `cookiejar.go`
分别以 `*.go.txt` 文档文件保存；正文与原件逐字一致，校验和记录在下方链接的清单中。

快照文件及其 SHA-256 记录在 [../../REFERENCES.md](../../REFERENCES.md)。`LICENSE` 为上游
MIT License，必须随参考源码一同保留。

本项目基于这些文件的行为结论重新实现了 aTrust/CAS 适配，实际实现位于：

- `client/atrust/auth/hitsz_sso.go`
- `client/atrust/auth/hitsz_totp.go`
- `client/atrust/auth/hitsz_otp_secret.go`

请将此目录视为只读开发参考；功能变更应修改本项目实现和测试，而不是修改该快照。
