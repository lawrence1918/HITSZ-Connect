# HITSZ Connect for Android TV

这是面向 Android 机顶盒/Android TV 的原生 HITSZ aTrust 客户端。Go 核心保留 HITSZ 统一认证支持的全部 MFA 方式：

- `App 动态码`：界面收到服务器请求后输入动态码并提交；
- `短信动态码`：界面输入短信验证码并提交；
- `OTP 安全令牌`：界面填写普通 Base32 种子或 `otpauth://` URI，由 Go 核心在本机生成一次性密码。

连接成功后，`HITSZVpnService` 按服务器下发的资源前缀建立 Android 系统级分流 VPN，因此不需要 root，也不需要逐个应用设置代理。aTrust 认证在 VPN 建立前使用系统网络；认证完成后，Go 核心把 VPN 的 TUN fd 接入 aTrust L3 隧道，并把 HITSZ Connect 自身排除在 VPN 路由之外，避免 underlay 回流到自身 VPN。普通外网流量保持系统直连。服务使用 HITSZ DNS `10.248.98.30`，断开时关闭 VPN 和 aTrust 会话。

## 构建

需要 Android SDK/NDK、Android Studio JBR 17+、Gradle 8.4+ 和 `gomobile`。先在仓库根目录生成 AAR：

```sh
gomobile init
gomobile bind -target=android/arm,android/arm64 -androidapi=26 -o android/app/libs/zju-connect.aar ./mobile
gradle -p android :app:assembleDebug
```

也可以直接运行 `.github/workflows/build-android.yml`，工作流会生成 AAR 和可直接侧载的 Debug APK artifact。Android Studio 打开 `android/` 后，确认 `android/app/libs/zju-connect.aar` 存在即可构建。正式分发前应使用独立发布密钥签署 Release APK，不能沿用 Debug 签名。

## 机顶盒使用

首次点击“连接”时接受系统 VPN 权限。使用遥控器方向键移动焦点，输入学号、密码和 MFA 凭据；App/短信方式在状态变为“等待动态码”后输入验证码并选择“提交 MFA”。OTP 方式只需保存种子，不需要手动填写当前 6 位码。凭据和 aTrust client data 使用 Android Keystore 加密保存于应用私有存储，断开按钮会清理运行中的 VPN 会话。

Android 系统可能限制后台 VPN 服务；请把 HITSZ Connect 设为允许后台运行，并关闭机顶盒的省电清理策略。该客户端只负责 HITSZ aTrust 校园资源，不会替代系统的普通外网代理节点。

## 安全边界

密码、OTP 种子、动态码、Cookie 和 device ID 不进入进程参数或日志。`VpnService` 只把 aTrust 下发的 HITSZ 资源前缀交给隧道，普通外网流量不会进入 aTrust。
