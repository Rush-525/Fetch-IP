<?php
// COM 返回的字符串可能是 GBK 编码（如中文连接名"以太网 2"），统一转为 UTF-8
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

function getIPv6Addresses() {
    $interfaces = [];
    $debugInfo = [];
    
    $debugInfo['PHP版本'] = PHP_VERSION;
    $debugInfo['操作系统'] = PHP_OS;
    $debugInfo['socket扩展'] = extension_loaded('sockets') ? '已加载' : '未加载';
    $debugInfo['socket_getifaddrs'] = function_exists('socket_getifaddrs') ? '可用' : '不可用';
    $debugInfo['COM扩展'] = class_exists('COM') ? '可用' : '不可用';
    
    if (function_exists('socket_getifaddrs')) {
        $ifaddrs = socket_getifaddrs();
        if ($ifaddrs !== false) {
            foreach ($ifaddrs as $ifaddr) {
                $interfaceName = $ifaddr['ifname'] ?? '未知接口';
                
                if (!isset($interfaces[$interfaceName])) {
                    $interfaces[$interfaceName] = [];
                }
                
                if (isset($ifaddr['family'])) {
                    if ($ifaddr['family'] === AF_INET6) {
                        $address = $ifaddr['addr'] ?? '';
                        if (!empty($address)) {
                            $interfaces[$interfaceName][] = [
                                'address' => $address,
                                'type' => classifyIPv6($address)
                            ];
                        }
                    } elseif ($ifaddr['family'] === AF_INET) {
                        $address = $ifaddr['addr'] ?? '';
                        if (!empty($address)) {
                            $interfaces[$interfaceName][] = [
                                'address' => $address,
                                'type' => 'ipv4'
                            ];
                        }
                    }
                }
            }
        }
    }
    
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' && class_exists('COM')) {
        try {
            $wmi = new COM('winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2');

            // 建立 Index => NetConnectionID 映射（如 "以太网"、"以太网 2"），用于区分多个有线以太网适配器
            $connectionNames = [];
            try {
                $nics = $wmi->ExecQuery('SELECT Index, NetConnectionID FROM Win32_NetworkAdapter');
                foreach ($nics as $nic) {
                    $nicIndex = (int)($nic->Index ?? -1);
                    $connId = trim(comToUtf8($nic->NetConnectionID ?? ''));
                    if ($nicIndex >= 0 && $connId !== '') {
                        $connectionNames[$nicIndex] = $connId;
                    }
                }
            } catch (Exception $e) {
                $debugInfo['WMI连接名查询错误'] = $e->getMessage();
            }

            $adapters = $wmi->ExecQuery('SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE');

            $usedNames = [];
            foreach ($adapters as $adapter) {
                $adapterIndex = (int)($adapter->Index ?? -1);
                $description = trim(comToUtf8($adapter->Description ?? ''));
                if ($description === '') {
                    $description = '未知适配器';
                }

                // 每个适配器独立成组：优先用系统连接名，相同名称时附加索引避免合并
                $connId = $connectionNames[$adapterIndex] ?? '';
                $interfaceName = ($connId !== '' && $connId !== $description)
                    ? $connId . '（' . $description . '）'
                    : $description;
                if (isset($usedNames[$interfaceName])) {
                    $interfaceName .= ' #' . ($adapterIndex >= 0 ? $adapterIndex : (count($usedNames) + 1));
                }
                $usedNames[$interfaceName] = true;

                $ipAddresses = $adapter->IPAddress;

                // WMI 的 IPAddress 可能是 PHP 数组，也可能是 VARIANT safe-array 对象（com_saproxy），统一转为数组
                $ipList = [];
                if (is_array($ipAddresses)) {
                    $ipList = $ipAddresses;
                } elseif (is_object($ipAddresses)) {
                    try {
                        foreach ($ipAddresses as $addr) {
                            $ipList[] = (string)$addr;
                        }
                    } catch (Exception $e) {
                        // 单个适配器地址读取失败则跳过
                        continue;
                    }
                }

                if (!empty($ipList)) {
                    if (!isset($interfaces[$interfaceName])) {
                        $interfaces[$interfaceName] = [];
                    }

                    foreach ($ipList as $address) {
                        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                            $interfaces[$interfaceName][] = [
                                'address' => $address,
                                'type' => classifyIPv6($address)
                            ];
                        } elseif (filter_var($address, FILTER_VALIDATE_IP)) {
                            $interfaces[$interfaceName][] = [
                                'address' => $address,
                                'type' => 'ipv4'
                            ];
                        }
                    }
                }
            }
        } catch (Exception $e) {
            $debugInfo['WMI错误'] = $e->getMessage();
        }
    }
    
    if (empty($interfaces)) {
        $interfaces = getDemoData($debugInfo);
    }
    
    foreach ($interfaces as &$addresses) {
        usort($addresses, function($a, $b) {
            $order = ['global' => 0, 'unique-local' => 1, 'link-local' => 2, 'loopback' => 3, 'ipv4' => 4, 'documentation' => 5, 'unknown' => 6];
            return $order[$a['type']] - $order[$b['type']];
        });
    }
    
    return ['interfaces' => $interfaces, 'debug' => $debugInfo];
}

function getDemoData($debugInfo) {
    $interfaces = [];
    
    $interfaces['以太网适配器'][] = [
        'address' => 'fe80::abcd:1234:5678:90ef',
        'type' => 'link-local'
    ];
    $interfaces['以太网适配器'][] = [
        'address' => '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        'type' => 'documentation'
    ];
    $interfaces['以太网适配器'][] = [
        'address' => '192.168.1.100',
        'type' => 'ipv4'
    ];
    
    $interfaces['无线局域网适配器'][] = [
        'address' => 'fd00::1234:5678:90ab:cdef',
        'type' => 'unique-local'
    ];
    $interfaces['无线局域网适配器'][] = [
        'address' => '10.0.0.50',
        'type' => 'ipv4'
    ];
    
    $interfaces['本地环回'][] = [
        'address' => '::1',
        'type' => 'loopback'
    ];
    $interfaces['本地环回'][] = [
        'address' => '127.0.0.1',
        'type' => 'ipv4'
    ];
    
    $interfaces['系统信息'][] = [
        'address' => '演示模式',
        'type' => 'unknown'
    ];
    
    return $interfaces;
}

function classifyIPv6($address) {
    $address = strtolower(trim($address));
    
    if (strpos($address, '::1') !== false || $address === '::1') {
        return 'loopback';
    }
    
    if (strpos($address, 'fe80:') === 0) {
        return 'link-local';
    }
    
    if (strpos($address, 'fc00:') === 0 || strpos($address, 'fd00:') === 0) {
        return 'unique-local';
    }
    
    if (strpos($address, '2001:0db8:') === 0) {
        return 'documentation';
    }
    
    $firstTwoBytes = substr($address, 0, 4);
    if (ctype_xdigit($firstTwoBytes)) {
        $value = hexdec($firstTwoBytes);
        if ($value >= 0x2000 && $value <= 0x3fff) {
            return 'global';
        }
        if ($value >= 0xfc00 && $value <= 0xfdff) {
            return 'unique-local';
        }
    }
    
    return 'unknown';
}

function getIPv6TypeName($type) {
    $names = [
        'global' => '全球单播地址',
        'link-local' => '链路本地地址',
        'loopback' => '环回地址',
        'unique-local' => '唯一本地地址',
        'documentation' => '文档地址',
        'ipv4' => 'IPv4地址',
        'unknown' => '未知类型'
    ];
    return $names[$type] ?? '未知类型';
}

function renderContent() {
    $result = getIPv6Addresses();
    $ipv6Data = $result['interfaces'];
    $debugInfo = $result['debug'];
    
    $html = '';
    
    $html .= '<div class="interface-item" style="background: #f0f0f0; border-radius: 8px; padding: 15px; margin-bottom: 20px;">';
    $html .= '<div class="interface-name">🔧 系统信息</div>';
    $html .= '<div style="margin-left: 20px;">';
    foreach ($debugInfo as $key => $value) {
        $html .= '<div style="padding: 5px 0; display: flex; justify-content: space-between;">';
        $html .= '<span style="color: #666;">' . htmlspecialchars($key) . '</span>';
        $html .= '<span style="font-weight: bold; color: ' . ($value === '可用' || $value === '已加载' ? 'green' : 'red') . '">' . htmlspecialchars($value) . '</span>';
        $html .= '</div>';
    }
    $html .= '</div>';
    $html .= '</div>';
    
    if (empty($ipv6Data)) {
        $html .= '<div class="empty-state">' .
               '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' .
               '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>' .
               '</svg>' .
               '<h3>未找到IPv6地址</h3>' .
               '<p>当前系统中没有配置IPv6地址</p>' .
               '</div>';
    } else {
        foreach ($ipv6Data as $interfaceName => $addresses) {
            $html .= '<div class="interface-item">';
            $html .= '<div class="interface-name">' . htmlspecialchars($interfaceName) . '</div>';
            $html .= '<div class="ipv6-list">';
            foreach ($addresses as $info) {
                $typeClass = $info['type'] === 'ipv4' ? 'type-unknown' : 'type-' . htmlspecialchars($info['type']);
                $html .= '<div class="ipv6-item">';
                $html .= '<span class="ipv6-address">' . htmlspecialchars($info['address']) . '</span>';
                $html .= '<span class="ipv6-type ' . $typeClass . '">' . getIPv6TypeName($info['type']) . '</span>';
                $html .= '</div>';
            }
            $html .= '</div>';
            $html .= '</div>';
        }
    }
    
    return $html;
}

$template = file_get_contents('index.html');
$template = str_replace('{{CONTENT}}', renderContent(), $template);
$template = str_replace('{{TIMESTAMP}}', date('Y-m-d H:i:s'), $template);

echo $template;
?>