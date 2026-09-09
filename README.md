# Fetch-IP

利用 PHP 在网页上展示本机网络接口的 IP 地址，并扫描局域网内其他设备的 IPv4/IPv6 地址（Windows / IIS 环境）。

## 功能

### 本机 IP 查看（index.php）
- 列出本机所有网络接口的 IPv4 / IPv6 地址及类型（如全局地址、链路本地地址、临时地址等）
- Windows 下优先使用 `socket_getifaddrs`，并通过 WMI（COM）获取网卡连接名与配置信息
- 非 Windows 环境自动降级为仅展示可获取的信息，页面会显示环境诊断信息

### 局域网设备扫描（lan.php）
- **IPv4**：通过 WMI 获取本机各网卡所在网段，对每个网段并行 ping 探测，解析 ARP 表获得 IP/MAC
- **IPv6**：对已连接接口 ping 全节点多播（`ff02::1` / `ff02::2`）填充邻居缓存，过滤隧道/组播/本机条目，对未确认状态的条目再做并行 ping 存活验证
- 按 MAC 地址关联同一设备的 IPv4/IPv6 地址，并尝试反向解析主机名
- 通过 OUI 数据（`oui_data.txt`，IEEE OUI 注册库）识别设备厂商
- 扫描进度实时上报，前端轮询展示；结果缓存于 `cache/` 目录

## 环境要求

- Windows + IIS（`web.config` 已配置默认文档 `index.php`）
- PHP 需启用以下扩展（php.ini）：
  - `extension=sockets`（获取接口地址）
  - `extension=php_com_dotnet.dll` 且 `com.allow_dcom = true`（WMI 查询，COM 返回的中文经 `comToUtf8()` 转为 UTF-8）
  - `extension=mbstring`（编码转换）
- WMI 查询使用 `Win32_NetworkAdapter` 将 `Index` 映射到 `NetConnectionID`，以唯一标识网卡（仅靠型号名分组会导致同型号多网卡合并）

## 文件结构

```
├── index.php        # 本机网络接口 IP 展示
├── index.html       # 本机 IP 页面模板（{{CONTENT}} / {{TIMESTAMP}} 占位）
├── lan.php          # 局域网设备扫描（IPv4 ping+ARP / IPv6 多播+邻居缓存）
├── lan.html         # 局域网扫描页面（重新扫描、IPv6 开关）
├── css/             # 样式（common / index / lan）
├── oui_data.txt     # IEEE OUI 厂商数据
├── web.config       # IIS 配置（默认文档）
└── cache/           # 运行时自动生成的缓存与扫描进度临时文件
```

## 使用

部署到 IIS 站点目录后访问：

- `/index.php` — 查看本机各网络接口的 IP 地址
- `/lan.php` — 扫描局域网设备（约需 15 秒，可勾选同时扫描 IPv6）

> 注意：若 IIS 的 php-cgi 环境未启用 COM 扩展，页面会显示演示数据而非实际查询结果。
