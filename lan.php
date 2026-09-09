<?php
// 局域网设备扫描：IPv4 = Ping 并行探测 + ARP 表解析；IPv6 = 多播发现 + 邻居缓存 + 存活验证
// IPv4：通过 WMI 获取本机各网卡的 IPv4 网段，对每个网段并行 ping 探测，读取 ARP 表获得 IP/MAC。
// IPv6：对已连接接口 ping 全节点多播（ff02::1/ff02::2）填充邻居缓存，仅解析局域网接口上的
//       条目并过滤隧道/组播/本机记录，对 Stale 等未确认状态的条目再做并行 ping 存活验证。
// 最后按 MAC 地址关联同一设备的 IPv4/IPv6 地址，并尝试反向解析主机名。

// 缓存目录：存放渲染结果缓存与扫描过程中的中间临时文件，目录不存在时自动创建
function getCacheDir() {
    $dir = __DIR__ . DIRECTORY_SEPARATOR . 'cache';
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    return $dir;
}

function comToUtf8($s) {
    $s = (string)$s;
    if ($s !== '' && !mb_check_encoding($s, 'UTF-8')) {
        $converted = @mb_convert_encoding($s, 'UTF-8', 'GBK');
        if ($converted !== false) {
            $s = $converted;
        }
    }
    return $s;
}

// WMI 返回的数组可能是 VARIANT 对象，统一转为 PHP 数组
function comVariantToList($v) {
    if (is_array($v)) {
        return array_values($v);
    }
    if (is_object($v)) {
        $list = [];
        try {
            foreach ($v as $item) {
                $list[] = (string)$item;
            }
        } catch (Exception $e) {
            return [];
        }
        return $list;
    }
    return [];
}

// 子网掩码转前缀长度，非法掩码返回 false
function maskToPrefix($mask) {
    if (!filter_var($mask, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }
    $bin = sprintf('%032b', ip2long($mask));
    if (strpos($bin, '01') !== false) { // 掩码位必须连续
        return false;
    }
    return substr_count($bin, '1');
}

// 获取本机所有 IPv4 网段（网络地址/前缀/本机IP/网卡描述）
// $ownIps 收集本机全部IP（含IPv6），$ownMacs 收集本机全部MAC（用于过滤邻居缓存中本机条目）
function getSubnets(&$debug, &$ownIps, &$ownMacs) {
    $subnets = [];
    $ownIps = [];
    $ownMacs = [];

    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' && class_exists('COM')) {
        try {
            $wmi = new COM('winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2');
            $adapters = $wmi->ExecQuery('SELECT Description, IPAddress, IPSubnet, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE');

            foreach ($adapters as $adapter) {
                $desc = trim(comToUtf8($adapter->Description ?? ''));
                $ips = comVariantToList($adapter->IPAddress);
                $masks = comVariantToList($adapter->IPSubnet);
                $mac = strtoupper(str_replace(':', '-', trim((string)($adapter->MACAddress ?? ''))));
                if ($mac !== '') {
                    $ownMacs[$mac] = true;
                }

                foreach ($ips as $i => $ip) {
                    $ownIps[strtolower($ip)] = true;
                    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        continue;
                    }
                    $mask = $masks[$i] ?? '';
                    $prefix = maskToPrefix($mask);
                    if ($prefix === false || $prefix < 8 || $prefix > 30) {
                        continue;
                    }

                    // 原始掩码对应的广播地址（用于排除 ARP 中的广播记录）
                    $broadcast = long2ip(ip2long($ip) | (~ip2long($mask) & 0xFFFFFFFF));

                    // 网段过大（超过 /22）时仅扫描本机所在的 /24，避免探测时间过长
                    if ($prefix < 22) {
                        $network = long2ip(ip2long($ip) & ip2long('255.255.255.0'));
                        $prefix = 24;
                    } else {
                        $network = long2ip(ip2long($ip) & ip2long($mask));
                    }

                    $key = $network . '/' . $prefix;
                    if (!isset($subnets[$key])) {
                        $subnets[$key] = [
                            'network' => $network,
                            'prefix' => $prefix,
                            'locals' => [$ip],
                            'iface' => $desc !== '' ? $desc : '未知网卡',
                            'broadcast' => $broadcast,
                        ];
                    } elseif (!in_array($ip, $subnets[$key]['locals'])) {
                        // 多个网卡位于同一网段（如有线+无线同时接入），都记录
                        $subnets[$key]['locals'][] = $ip;
                    }
                }
            }
        } catch (Exception $e) {
            $debug['WMI错误'] = $e->getMessage();
        }
    }

    // 最多扫描 8 个网段，防止虚拟网卡过多导致扫描时间失控
    if (count($subnets) > 8) {
        $subnets = array_slice($subnets, 0, 8, true);
    }

    return $subnets;
}

// 对网段内所有地址并行 ping 探测（每个 /24 块异步启动），返回探测的地址数
function pingSweep($subnets) {
    $count = 0;
    foreach ($subnets as $s) {
        $netL = ip2long($s['network']);
        $hostCount = pow(2, 32 - $s['prefix']) - 2;
        $end = $netL + $hostCount + 1; // 广播地址

        // 按 /24 块并行探测
        for ($base = $netL; $base < $end; $base += 256) {
            $baseIp = long2ip($base);
            $cmd = 'cmd /c "for /L %i in (1,1,254) do start /b ping -n 1 -w 300 ' . $baseIp . '.%i >nul 2>&1"';
            $h = @popen($cmd, 'r');
            if ($h) {
                pclose($h);
            }
            $count += min(254, max(0, $end - $base - 1));
        }
    }
    return $count;
}

// 解析 arp -a 输出（兼容中英文系统）
function parseArp() {
    $entries = [];
    $iface = '';
    exec('arp -a 2>nul', $out);

    foreach ((array)$out as $line) {
        $line = comToUtf8($line);
        if (preg_match('/(?:Interface|接口)\s*[:：]\s*(\d{1,3}(?:\.\d{1,3}){3})/i', $line, $m)) {
            $iface = $m[1];
            continue;
        }
        if (preg_match(
            '/^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\S+)/i',
            $line,
            $m
        )) {
            $typeRaw = strtolower($m[3]);
            $typeMap = ['动态' => 'dynamic', '静态' => 'static', 'dynamic' => 'dynamic', 'static' => 'static'];
            $entries[] = [
                'ip' => $m[1],
                'mac' => strtoupper(str_replace(':', '-', $m[2])),
                'type' => $typeMap[$typeRaw] ?? $typeRaw,
                'iface' => $iface,
            ];
        }
    }
    return $entries;
}

// IPv6 地址粗略分类
function classifyIpv6Addr($addr) {
    if (strpos($addr, 'fe80:') === 0) return 'link-local';
    if (strpos($addr, 'fc') === 0 || strpos($addr, 'fd') === 0) return 'unique-local';
    $first = substr($addr, 0, 1);
    if ($first === '2' || $first === '3') return 'global'; // 2000::/3 全球单播
    return 'other';
}

// 获取"已连接"状态的 IPv6 接口（索引=>名称），排除环回/隧道/覆盖网络等非局域网接口，
// 避免 Teredo、Tailscale 等隧道中的远程对端被误判为局域网设备
function getConnectedInterfaces6() {
    $excludedKeywords = ['loopback', 'teredo', 'isatap', 'tailscale', '6to4'];
    $result = [];
    exec('netsh interface ipv6 show interfaces 2>nul', $out);

    foreach ((array)$out as $line) {
        $line = comToUtf8($line);
        // 行格式: Idx Met MTU 状态 名称（兼容中英文 "connected/已连接"）
        if (preg_match('/^\s*(\d+)\s+\d+\s+\d+\s+(?:connected|已连接)\s+(.+)$/i', $line, $m)) {
            $name = trim($m[2]);
            $skip = false;
            foreach ($excludedKeywords as $kw) {
                if (stripos($name, $kw) !== false) {
                    $skip = true;
                    break;
                }
            }
            if (!$skip) {
                $result[(int)$m[1]] = $name;
            }
        }
    }
    return $result;
}

// 对已连接的 IPv6 接口多轮异步 ping 全节点多播地址（ff02::1）和路由器多播（ff02::2），
// 触发局域网内所有 IPv6 设备应答，从而填充系统 IPv6 邻居缓存
function pingMulticast6($ifaces, $rounds = 2) {
    for ($r = 0; $r < $rounds; $r++) {
        foreach (array_keys($ifaces) as $idx) {
            foreach (['ff02::1', 'ff02::2'] as $mc) {
                $cmd = 'cmd /c "start /b ping -6 -n 1 -w 800 ' . $mc . '%' . $idx . ' >nul 2>&1"';
                $h = @popen($cmd, 'r');
                if ($h) {
                    pclose($h);
                }
            }
        }
        if ($r < $rounds - 1) {
            usleep(500000); // 轮间隔，提高慢速设备的命中率
        }
    }
}

// 解析 netsh interface ipv6 show neighbors 输出（兼容中英文系统）
// 仅保留指定接口上的条目，返回 IPv6/MAC/状态/接口名/接口索引
function parseNeighbors6($allowedIfidx) {
    $entries = [];
    $iface = '';
    $ifidx = 0;
    exec('netsh interface ipv6 show neighbors 2>nul', $out);

    foreach ((array)$out as $line) {
        $line = comToUtf8($line);
        if (preg_match('/^(?:接口|Interface)\s+(\d+)\s*[:：]\s*(.*)$/iu', $line, $m)) {
            $ifidx = (int)$m[1];
            $iface = trim($m[2]);
            continue;
        }
        if (!in_array($ifidx, $allowedIfidx, true)) {
            continue; // 非目标接口（环回/隧道等）上的条目一律忽略
        }
        if (preg_match(
            '/^\s*([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){1,7})(?:%\d+)?\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\S+)/i',
            $line,
            $m
        )) {
            $entries[] = [
                'addr' => strtolower($m[1]),
                'mac' => strtoupper($m[2]),
                'state' => strtolower($m[3]),
                'iface' => $iface,
                'ifidx' => $ifidx,
            ];
        }
    }
    return $entries;
}

// 并行验证候选 IPv6 地址是否存活：后台 ping 输出重定向到临时文件后汇总判定。
// ping 输出为系统本地编码（中文系统为 GBK），需先转 UTF-8 再匹配；
// 存活判定兼容中英文输出（"Reply from"/"的回复"），返回 addr%ifidx => true 的存活集合
function verifyIpv6Alive($candidates, $waitMs = 2500) {
    if (empty($candidates)) {
        return [];
    }
    // 中间临时文件统一写入 cache 文件夹
    $dir = getCacheDir();
    $files = [];
    $i = 0;
    foreach ($candidates as $c) {
        $key = $c['addr'] . '%' . $c['ifidx'];
        if (isset($files[$key])) {
            continue;
        }
        $f = $dir . '\\lan_v6chk_' . getmypid() . '_' . ($i++) . '.tmp';
        $files[$key] = $f;
        $cmd = 'cmd /c "start /b ping -6 -n 1 -w 800 ' . $key . ' > ' . $f . ' 2>&1"';
        $h = @popen($cmd, 'r');
        if ($h) {
            pclose($h);
        }
    }
    usleep($waitMs * 1000);

    $alive = [];
    $readable = 0;
    foreach ($files as $key => $f) {
        $raw = @file_get_contents($f);
        if ($raw === false) {
            continue;
        }
        $readable++;
        @unlink($f);
        $out = comToUtf8($raw);
        if (stripos($out, 'reply from') !== false || strpos($out, '的回复') !== false) {
            $alive[$key] = true;
        }
    }
    // 临时文件全部不可读（如权限问题），说明验证机制失效，放行所有候选避免误删
    if ($readable === 0 && count($files) > 0) {
        foreach (array_keys($files) as $key) {
            $alive[$key] = true;
        }
    }
    return $alive;
}

function renderContent() {
    $debug = [];
    $t0 = microtime(true);

    // 1. 获取本机网段与本机全部 IP / MAC
    $ownIps = [];
    $ownMacs = [];
    $subnets = getSubnets($debug, $ownIps, $ownMacs);

    // 2. 并行 ping 探测：IPv6 多播发现（两轮，仅已连接的局域网接口）+ IPv4 网段扫描
    $pingCount = 0;
    $ifaces6 = getConnectedInterfaces6();
    pingMulticast6($ifaces6);
    if (!empty($subnets)) {
        $pingCount = pingSweep($subnets);
    }
    sleep(5);

    // 3. 读取 ARP 表与 IPv6 邻居缓存（仅限已连接的局域网接口，排除隧道/环回）
    $arp = parseArp();
    $neighbors6 = parseNeighbors6(array_keys($ifaces6));

    // 3.1 邻居条目结构化预过滤（组播地址/隧道地址/无效MAC/本机/去重），得到有效候选
    $freshStates = ['reachable', 'probe', 'delay'];
    $valid6 = [];
    $seen6 = [];
    foreach ($neighbors6 as $n) {
        if (strpos($n['addr'], 'ff') === 0) {
            continue; // 组播地址
        }
        if (strpos($n['addr'], '2001:0:') === 0 || strpos($n['addr'], ':5efe:') !== false) {
            continue; // Teredo/ISATAP 隧道地址，非局域网设备
        }
        if ($n['mac'] === '00-00-00-00-00-00' || strpos($n['mac'], '33-33') === 0) {
            continue; // 未解析出 MAC 或组播 MAC 的无效条目
        }
        if (isset($seen6[$n['addr']])) {
            continue; // 多接口重复记录
        }
        $seen6[$n['addr']] = true;
        if (isset($ownIps[$n['addr']])) {
            continue; // 本机 IPv6 地址
        }
        if (isset($ownMacs[$n['mac']])) {
            continue; // 本机网卡的条目
        }
        $valid6[] = $n;
    }

    // 3.2 存活验证：仅对有效候选中非 Reachable/Probe/Delay 状态的条目（如 Stale，
    //     表示近期未确认可达、设备可能已离线）逐个并行 ping 确认，剔除残留死条目
    $verifyCandidates = [];
    foreach ($valid6 as $n) {
        if (!in_array($n['state'], $freshStates, true)) {
            $verifyCandidates[] = ['addr' => $n['addr'], 'ifidx' => $n['ifidx']];
        }
    }
    $alive6 = verifyIpv6Alive($verifyCandidates);

    // 各网段广播地址集合，用于排除广播记录
    $broadcasts = [];
    foreach ($subnets as $s) {
        $broadcasts[$s['broadcast']] = true;
    }
    $broadcasts['255.255.255.255'] = true;

    // 4. 过滤（本机IP/组播/广播）、去重（同一IP出现在多个接口块）、归属网段
    $devices = [];
    $ungrouped = [];
    $seen = [];
    foreach ($arp as $entry) {
        $firstOctet = (int)substr($entry['ip'], 0, strpos($entry['ip'], '.'));
        if ($firstOctet >= 224) {
            continue; // 组播/保留地址
        }
        if (isset($ownIps[$entry['ip']])) {
            continue; // 本机地址
        }
        if (isset($broadcasts[$entry['ip']])) {
            continue; // 广播地址
        }
        if (isset($seen[$entry['ip']])) {
            continue; // 多个接口块中的重复记录
        }
        $seen[$entry['ip']] = true;

        // 反向 DNS 解析主机名
        $hostname = @gethostbyaddr($entry['ip']);
        if ($hostname === $entry['ip']) {
            $hostname = '';
        }
        $entry['hostname'] = $hostname;

        $matched = false;
        foreach ($subnets as $s) {
            if ($s['prefix'] === 24) {
                $mask = '255.255.255.0';
            } else {
                $mask = long2ip(0xFFFFFFFF << (32 - $s['prefix']) & 0xFFFFFFFF);
            }
            if ((ip2long($entry['ip']) & ip2long($mask)) === ip2long($s['network'])) {
                $devices[$s['network'] . '/' . $s['prefix']][] = $entry;
                $matched = true;
                break;
            }
        }
        if (!$matched) {
            $ungrouped[] = $entry;
        }
    }

    // 5. 有效 IPv6 候选经存活验证后按 MAC 分组
    $ipv6ByMac = [];
    foreach ($valid6 as $n) {
        // Stale 等未确认状态：需验证 ping 有应答才认定为在线（剔除已离线设备的残留缓存）
        if (!in_array($n['state'], $freshStates, true)
            && !isset($alive6[$n['addr'] . '%' . $n['ifidx']])) {
            continue;
        }
        $ipv6ByMac[$n['mac']][] = [
            'addr' => $n['addr'],
            'type' => classifyIpv6Addr($n['addr']),
            'iface' => $n['iface'],
        ];
    }

    // 每个 MAC 的 IPv6 地址排序：全球单播 > 唯一本地 > 链路本地 > 其他
    $v6Order = ['global' => 0, 'unique-local' => 1, 'link-local' => 2, 'other' => 3];
    foreach ($ipv6ByMac as &$v6list) {
        usort($v6list, function ($a, $b) use ($v6Order) {
            return $v6Order[$a['type']] - $v6Order[$b['type']];
        });
    }
    unset($v6list);

    // 6. 各网段内按 IP 排序
    $sortByIp = function ($a, $b) {
        return ip2long($a['ip']) - ip2long($b['ip']);
    };
    foreach ($devices as &$list) {
        usort($list, $sortByIp);
    }
    unset($list);
    usort($ungrouped, $sortByIp);

    $totalDevices = array_sum(array_map('count', $devices)) + count($ungrouped);
    // 已匹配到 IPv4 设备的 MAC 集合（用于找出仅 IPv6 可达的设备）
    $arpMacs = [];
    foreach ($arp as $entry) {
        if (!isset($ownIps[$entry['ip']])) {
            $arpMacs[$entry['mac']] = true;
        }
    }
    $ipv6OnlyMacs = array_diff_key($ipv6ByMac, $arpMacs);
    $ipv6DeviceCount = count($ipv6ByMac);
    $elapsed = round(microtime(true) - $t0, 1);

    // ---- 渲染 ----
    $html = '';

    // 摘要栏
    $html .= '<div class="summary-bar">';
    $html .= '<div>共发现 <strong>' . $totalDevices . '</strong> 台设备 · 其中 <strong>' . $ipv6DeviceCount . '</strong> 台支持IPv6</div>';
    $html .= '<div>扫描网段 ' . count($subnets) . ' 个 · 探测地址 ' . $pingCount . ' 个 · IPv6接口 ' . count($ifaces6) . ' 个 · 耗时 ' . $elapsed . ' 秒</div>';
    $html .= '</div>';

    // 按网段分组展示（包括未发现设备的网段）
    if (empty($subnets) && empty($ungrouped)) {
        $html .= '<div class="empty-subnet">未发现局域网中的其他设备</div>';
    } else {
        foreach ($subnets as $key => $s) {
            $list = $devices[$key] ?? [];
            $html .= '<div class="subnet-section">';
            $html .= '<div class="subnet-title">📡 ' . htmlspecialchars($key);
            $html .= '<span class="subnet-meta">' . htmlspecialchars($s['iface']) . ' · 本机 ' . htmlspecialchars(implode(' / ', $s['locals'])) . ' · ' . count($list) . ' 台设备</span></div>';
            if (empty($list)) {
                $html .= '<div class="empty-subnet">该网段未发现其他设备</div>';
            } else {
                $html .= renderDeviceTable($list, $ipv6ByMac);
            }
            $html .= '</div>';
        }
        if (!empty($ungrouped)) {
            $html .= '<div class="subnet-section">';
            $html .= '<div class="subnet-title">📡 其他ARP记录<span class="subnet-meta">' . count($ungrouped) . ' 条</span></div>';
            $html .= renderDeviceTable($ungrouped, $ipv6ByMac);
            $html .= '</div>';
        }
        if (!empty($ipv6OnlyMacs)) {
            $html .= '<div class="subnet-section">';
            $html .= '<div class="subnet-title">🛰️ 仅IPv6可达的设备<span class="subnet-meta">未发现对应IPv4地址 · ' . count($ipv6OnlyMacs) . ' 台</span></div>';
            $html .= renderIpv6OnlyTable($ipv6OnlyMacs);
            $html .= '</div>';
        }
    }

    // 调试信息
    $debug['COM扩展'] = class_exists('COM') ? '可用' : '不可用';
    $debug['扫描网段'] = empty($subnets) ? '无（回退为仅读取ARP表）' : implode('、', array_keys($subnets));
    $debug['ARP记录总数'] = count($arp);
    $debug['IPv6邻居记录总数'] = count($neighbors6);
    $debug['IPv6有效候选'] = count($valid6) . ' 个（已过滤隧道/组播/无效MAC/本机条目）';
    $debug['IPv6存活验证'] = '候选 ' . count($verifyCandidates) . ' 个 · 确认在线 ' . count($alive6) . ' 个';

    $html .= '<div class="subnet-section" style="background: #f8f9fa; border-radius: 8px; padding: 15px; margin-top: 25px;">';
    $html .= '<div class="subnet-title" style="font-size: 1rem;">🔧 扫描信息</div>';
    foreach ($debug as $k => $v) {
        $html .= '<div class="debug-item"><span>' . htmlspecialchars($k) . '</span><span>' . htmlspecialchars(is_array($v) ? implode(',', $v) : $v) . '</span></div>';
    }
    $html .= '</div>';

    return $html;
}

function renderDeviceTable($list, $ipv6ByMac = []) {
    $v6TypeNames = ['global' => '全球', 'unique-local' => '本地', 'link-local' => '链路本地', 'other' => '其他'];
    $html = '<table class="device-table">';
    $html .= '<thead><tr><th>IP地址</th><th>主机名</th><th>MAC地址</th><th>IPv6地址</th><th>类型</th></tr></thead><tbody>';
    foreach ($list as $d) {
        $badgeClass = $d['type'] === 'dynamic' ? 'badge-dynamic' : ($d['type'] === 'static' ? 'badge-static' : 'badge-other');
        $typeName = $d['type'] === 'dynamic' ? '动态' : ($d['type'] === 'static' ? '静态' : $d['type']);
        $html .= '<tr>';
        $html .= '<td class="ip-cell">' . htmlspecialchars($d['ip']) . '</td>';
        $html .= '<td class="hostname-cell">' . ($d['hostname'] !== '' ? htmlspecialchars($d['hostname']) : '<span style="color:#bbb">—</span>') . '</td>';
        $html .= '<td class="mac-cell">' . htmlspecialchars($d['mac']) . '</td>';

        // IPv6 地址列：按 MAC 关联邻居缓存中的 IPv6 地址
        $v6list = $ipv6ByMac[$d['mac']] ?? [];
        if (empty($v6list)) {
            $html .= '<td class="ipv6-cell"><span style="color:#bbb">—</span></td>';
        } else {
            $html .= '<td class="ipv6-cell">';
            foreach ($v6list as $v6) {
                $html .= '<div class="ipv6-line">';
                $html .= '<span class="ipv6-addr-text">' . htmlspecialchars($v6['addr']) . '</span>';
                $html .= '<span class="v6tag v6-' . htmlspecialchars($v6['type']) . '">' . $v6TypeNames[$v6['type']] . '</span>';
                $html .= '</div>';
            }
            $html .= '</td>';
        }

        $html .= '<td><span class="badge ' . $badgeClass . '">' . htmlspecialchars($typeName) . '</span></td>';
        $html .= '</tr>';
    }
    $html .= '</tbody></table>';
    return $html;
}

// 仅 IPv6 可达的设备表（无对应 IPv4 记录，无法获知主机名）
function renderIpv6OnlyTable($ipv6OnlyMacs) {
    $v6TypeNames = ['global' => '全球', 'unique-local' => '本地', 'link-local' => '链路本地', 'other' => '其他'];
    $html = '<table class="device-table">';
    $html .= '<thead><tr><th>MAC地址</th><th>IPv6地址</th><th>所在接口</th></tr></thead><tbody>';
    foreach ($ipv6OnlyMacs as $mac => $v6list) {
        $html .= '<tr>';
        $html .= '<td class="mac-cell">' . htmlspecialchars($mac) . '</td>';
        $html .= '<td class="ipv6-cell">';
        foreach ($v6list as $v6) {
            $html .= '<div class="ipv6-line">';
            $html .= '<span class="ipv6-addr-text">' . htmlspecialchars($v6['addr']) . '</span>';
            $html .= '<span class="v6tag v6-' . htmlspecialchars($v6['type']) . '">' . $v6TypeNames[$v6['type']] . '</span>';
            $html .= '</div>';
        }
        $html .= '</td>';
        $html .= '<td class="hostname-cell">' . htmlspecialchars($v6list[0]['iface'] !== '' ? $v6list[0]['iface'] : '—') . '</td>';
        $html .= '</tr>';
    }
    $html .= '</tbody></table>';
    return $html;
}

$template = file_get_contents('lan.html');
$template = str_replace('{{CONTENT}}', renderContent(), $template);
$template = str_replace('{{TIMESTAMP}}', date('Y-m-d H:i:s'), $template);

// 将渲染结果写入 cache 文件夹作为缓存文件（按扫描时间命名，便于回溯历史扫描结果）
@file_put_contents(getCacheDir() . DIRECTORY_SEPARATOR . 'lan_' . date('Ymd_His') . '.html', $template);

echo $template;
?>
