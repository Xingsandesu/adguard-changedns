# AdGuard ChangeDNS

针对 iKuai 做主路由分流转发，OpenWrt 配合 Passwall 海外线路接入的方案，使用 AdGuard 应对 OpenWRT 故障后内网 DNS 同样故障的三联动脚本。

## 功能

检查 iKuai 线路状态，在 WRT 故障后，自动切换 AdGuard 的上游服务器为公共 DNS 而不是 WRT 的 DNS 服务器。

## 组网原理

参考 [right.com.cn 论坛](https://www.right.com.cn/forum/thread-8252571-1-1.html)

实际方案略有不同，本人使用 iKuai 作为主路由，iKuai 虚拟机添加 WRT 并且使用自带的网桥作为海外线路接入分流的方案。配合自动更新国内 IP 段脚本，使用 [bncfbb/ikuai-chinaroute-xuefeng](https://hub.docker.com/r/bncfbb/ikuai-chinaroute-xuefeng) 更佳。

## 注意事项

使用 WRT 作为上游 DNS 时请关闭 AdGuard 自带的 DNS 缓存。

## Docker 存储库

- 稳定版: `bncfbb/adguard-changedns:2.0`

## 关于

- 初始作者：[Nanyo](https://github.com/bncfbb)
- 贡献者：[Fushinn](https://github.com/Xingsandesu)

## 配置样例

```yaml
ikuai:
  host: '爱快ip'
  port: 80
  user: 'admin'
  pwd: '爱快密码'
  check_wan: 'wan2'
openwrt:
  host: 'openwrt ip'
  port: 80
  user: 'root'
  pwd: 'openwrt密码'
  ssh_port: 22
  check_dns_domain:
    - 'itdog.cn'
    - 'ip.skk.moe'
  check_url:
    - 'https://www.google.com/generate_204'
  onfail_restart_passwall: true
  restart_mode: 0
  retry_count: 0
  retry_interval: 10
adguardhome:
  - host: 'adguard ip'
    port: 80
    user: 'admin'
    pwd: 'adguard密码'
    normal_upstream_dns:
      - 'openwrt ip'
    onfail_upstream_dns:
      - '国内dns'
check_interval: 30