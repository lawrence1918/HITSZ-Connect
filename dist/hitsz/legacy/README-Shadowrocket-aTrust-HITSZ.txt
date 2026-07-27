Shadowrocket + HITSZ aTrust 使用说明
====================================

诊断结论
--------
这不是订阅节点故障：61 个唯一节点端口全部可达；订阅中的 32 个 Trojan
节点均使用真实订阅凭据完成了代理 HTTP 请求（32/32 成功）。当前故障来自
Quantumult X 与 aTrust 同时使用 198.18.0.0/16 Fake-IP，以及 Quantumult X
全局真实 IP 例外模式绕过已配置 DoH 的组合冲突。

请勿再开启 Quantumult X 测试本方案。两个代理客户端不能同时启动。

文件
----
1. Shadowrocket-aTrust-HITSZ.conf：Shadowrocket 完整配置。
2. start-hitsz-dns-relay.command：启动 HITSZ 专用 DNS 中继。
3. hitsz-dns-tcp-relay：中继程序（Apple Silicon arm64）。

一次性设置
----------
1. 保持 Quantumult X 关闭。
2. 在 Shadowrocket 中导入你现有的同一订阅；不要把订阅令牌粘贴进配置文件。
3. 将 Shadowrocket-aTrust-HITSZ.conf 导入 Shadowrocket 的配置列表并选中。
4. 在 Shadowrocket 设置中关闭 “Force Route/强制路由（或 Enforce Routes）”
   和 “Include All Networks/包括所有网络”。

每次启动顺序
------------
1. 连接官方 aTrust，确认登录成功。
2. 双击 start-hitsz-dns-relay.command，保持该终端窗口运行。
3. 在 Shadowrocket 首页选择订阅中的一个 Trojan 节点。
4. 启动 Shadowrocket。

重要路由说明
------------
配置故意没有把 10.248.98.30/32 加入 tun-excluded-routes。排除这个 /32 会
生成指向 Wi-Fi 的主机路由，覆盖 aTrust 的 10.248.64.0/18 路由，从而使
HITSZ DNS 中继超时。aTrust 的 /18 比 Shadowrocket 默认路由更具体，会自然
优先，因此无需额外排除该 DNS 地址。

DNS 边界
--------
* hitsz.edu.cn 和 *.hitsz.edu.cn：只交给本地 127.0.0.1:53535 中继，最终
  通过 aTrust 使用 10.248.98.30:53/TCP。
* 其他域名、备用解析和节点域名：只使用 ControlD 与 Mullvad 的 DoH。
* 配置固定了两个 DoH 主机的引导 IP，不使用系统/Wi-Fi DNS。
* 常见硬编码明文 DNS 会被接管；其余 53 端口流量直接拒绝，避免泄漏。
* always-real-ip=* 避免与 aTrust 的 198.18.0.0/16 Fake-IP 路由冲突。

验证与回退
----------
启动 aTrust 和中继后，可先运行：

  dig +time=3 +tries=1 @127.0.0.1 -p 53535 trust.hitsz.edu.cn A

预期能得到 HITSZ 地址。随后再启动 Shadowrocket，分别访问校内域名和境外
网站。若需回退，只关闭 Shadowrocket；中继窗口可按 Control-C 停止。不要
在同一时间重新开启 Quantumult X。
