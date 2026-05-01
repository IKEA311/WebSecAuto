#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scanner.py - 资产探测模块
=========================
功能: 端口扫描、服务识别、Banner抓取
依赖: python-nmap (可选), socket (内置回退)
"""

import socket
import sys
import os
import json
import subprocess
from datetime import datetime


# 常见端口与服务映射
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2181: "ZooKeeper",
    2375: "Docker", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5672: "RabbitMQ", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9000: "PHP-FPM", 9092: "Kafka",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    50070: "HDFS"
}


def print_scan_usage():
    """打印扫描模块使用帮助"""
    print("用法: python websecauto.py scan <目标> [选项]\n")
    print("参数:")
    print("  目标\t\tIP地址或域名 (支持: 192.168.1.1, example.com)")
    print("  -p\t\t端口范围 (默认: 常见Top 20端口)")
    print("  \t\t  格式: 80,443,3306 或 1-1024")
    print("  -t\t\t超时时间秒数 (默认: 2)")
    print("  -o\t\t输出文件路径 (默认: results/scan_时间.json)\n")
    print("示例:")
    print("  python websecauto.py scan 192.168.1.1")
    print("  python websecauto.py scan 192.168.1.1 -p 1-1000")
    print("  python websecauto.py scan example.com -p 80,443 -o result.json")


def parse_port_string(port_str):
    """
    解析端口参数字符串
    支持格式: "80,443,3306" 或 "1-1024" 或 "80"

    Args:
        port_str: 端口参数字符串

    Returns:
        list[int]: 端口列表
    """
    ports = []

    if not port_str:
        return list(COMMON_PORTS.keys())

    # 逗号分隔
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            # 范围格式: 1-1024
            try:
                start, end = part.split("-")
                start, end = int(start), int(end)
                if start > end:
                    start, end = end, start
                if start < 1:
                    start = 1
                if end > 65535:
                    end = 65535
                ports.extend(range(start, end + 1))
            except ValueError:
                print(f"[!] 端口范围格式错误: {part}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
                else:
                    print(f"[!] 端口超出范围: {p}")
            except ValueError:
                print(f"[!] 无效端口: {part}")

    return sorted(set(ports))


def get_service_name(port):
    """根据端口号返回常见服务名称"""
    return COMMON_PORTS.get(port, "unknown")


def tcp_connect_scan(ip, port, timeout=2):
    """
    TCP Connect方式扫描单个端口

    通过建立完整的TCP三次握手来判断端口是否开放。
    如果connect()成功返回，说明端口开放；
    如果连接被拒绝(ECONNREFUSED)，说明端口关闭；
    如果超时，说明端口可能被防火墙过滤。

    Args:
        ip: 目标IP
        port: 目标端口
        timeout: 超时秒数

    Returns:
        bool: 端口是否开放
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = False
    try:
        sock.connect((ip, port))
        result = True
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    finally:
        sock.close()
    return result


def grab_banner(ip, port, timeout=2):
    """
    抓取端口Banner信息

    对开放端口发送探测请求，获取服务返回的标识信息。
    HTTP端口发送GET请求，其他端口直接接收。

    Args:
        ip: 目标IP
        port: 目标端口
        timeout: 超时秒数

    Returns:
        str: Banner信息（最多100字符）
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner = ""

    try:
        sock.connect((ip, port))

        # HTTP端口发送GET请求
        if port in (80, 8080, 8000):
            http_req = "GET / HTTP/1.0\r\nHost: {}\r\n\r\n".format(ip)
            sock.send(http_req.encode())

        # 接收响应
        data = sock.recv(1024)
        if data:
            # 过滤不可打印字符
            banner = "".join(chr(b) for b in data if 32 <= b < 127)
            if len(banner) > 100:
                banner = banner[:100]

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    finally:
        sock.close()

    return banner.strip()


def try_nmap_scan(target, ports, timeout=2):
    """
    尝试使用Nmap进行扫描（如果已安装Nmap）

    使用系统安装的Nmap进行更准确的端口扫描。
    如果Nmap未安装或执行失败，则回退到Python内置扫描。

    Args:
        target: 目标IP/域名
        ports: 端口列表
        timeout: 超时

    Returns:
        list[dict] or None: 扫描结果，失败返回None
    """
    try:
        # 检查nmap是否可用
        subprocess.run(["nmap", "--version"],
                       capture_output=True, check=True)

        # 构建端口字符串
        port_str = ",".join(str(p) for p in ports)
        cmd = ["nmap", "-sT", "-Pn", "-n",
               "--open",
               "-T4",
               "--host-timeout", "{}s".format(timeout * 5),
               "-p", port_str,
               "-oX", "-",  # XML格式输出到stdout
               target]

        print("[*] 正在使用Nmap扫描...")
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        output = result.stdout.decode("utf-8", errors="replace")

        # 简单解析Nmap XML输出
        results = []
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(output)
            for host in root.findall("host"):
                ip_elem = host.find("address")
                host_ip = ip_elem.get("addr", target) if ip_elem is not None else target

                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue

                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    port_num = int(port_elem.get("portid", "0"))
                    service_elem = port_elem.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"

                    results.append({
                        "ip": host_ip,
                        "port": port_num,
                        "service": service_name,
                        "banner": ""
                    })
        except ET.ParseError:
            return None

        return results

    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def resolve_target(target):
    """解析目标（域名转IP）"""
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print("[*] 域名 {} 解析为 IP: {}".format(target, ip))
        return ip
    except socket.gaierror:
        print("[!] 无法解析域名: {}".format(target))
        return None


def expand_cidr(cidr_str):
    """
    展开CIDR网段为IP列表

    支持 /24 到 /30 的网段，更大的网段会被限制。

    Args:
        cidr_str: CIDR格式字符串，如 "192.168.1.0/24"

    Returns:
        list[str]: IP地址列表
    """
    if "/" not in cidr_str:
        return [cidr_str]

    import ipaddress
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        ips = [str(ip) for ip in network.hosts()]

        # 限制数量避免扫描过大网段
        if len(ips) > 256:
            print("[!] 网段过大，限制为前256个IP")
            ips = ips[:256]

        return ips
    except ValueError as e:
        print("[!] CIDR格式错误: {}".format(e))
        return []


def run_scan(args):
    """
    扫描入口函数

    使用Socket或Nmap对目标进行端口扫描，识别开放端口和服务。
    支持单IP、域名、CIDR网段。

    Args:
        args: 命令行参数列表
    """
    if not args or args[0] in ("--help", "-h"):
        print_scan_usage()
        return

    target = args[0]
    port_range = ""
    output_file = ""
    timeout = 2

    # 解析可选参数
    i = 1
    while i < len(args):
        if args[i] == "-p" and i + 1 < len(args):
            port_range = args[i + 1]
            i += 2
        elif args[i] == "-t" and i + 1 < len(args):
            try:
                timeout = max(1, min(30, int(args[i + 1])))
            except ValueError:
                pass
            i += 2
        elif args[i] == "-o" and i + 1 < len(args):
            output_file = args[i + 1]
            i += 2
        else:
            i += 1

    # 解析端口
    ports = parse_port_string(port_range)
    print("[*] 待扫描端口数: {}".format(len(ports)))
    print("[*] 超时设置: {}s\n".format(timeout))

    # 解析目标
    targets = []
    if "/" in target:
        targets = expand_cidr(target)
    else:
        ip = resolve_target(target)
        if ip:
            targets = [ip]

    if not targets:
        print("[!] 没有有效的扫描目标")
        return

    # 确保results目录存在
    if not output_file:
        os.makedirs("results", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = "results/scan_{}.json".format(timestamp)

    all_results = []

    for ip in targets:
        print("\n" + "=" * 40)
        print("[*] 扫描目标: {}".format(ip))
        print("=" * 40)

        # 优先尝试Nmap扫描
        nmap_results = try_nmap_scan(ip, ports, timeout)

        if nmap_results is not None:
            print("[*] Nmap扫描完成, 发现 {} 个开放端口\n".format(len(nmap_results)))
            all_results.extend(nmap_results)
        else:
            # 回退到Python Socket扫描
            print("[*] Nmap不可用, 使用Python内置扫描器\n")
            open_ports = []

            for port in ports:
                sys.stdout.write("\r[*] 扫描进度: {}/{}".format(
                    ports.index(port) + 1, len(ports)))
                sys.stdout.flush()

                try:
                    if tcp_connect_scan(ip, port, timeout):
                        open_ports.append(port)
                except KeyboardInterrupt:
                    print("\n[!] 扫描被用户中断")
                    break

            print("\n")

            for port in open_ports:
                service = get_service_name(port)
                print("  [+] 端口 {}/tcp 开放 ({})".format(port, service))

                banner = ""
                if port in (80, 443, 8080, 22, 21, 3306):
                    banner = grab_banner(ip, port, timeout)
                    if banner:
                        print("      Banner: {}".format(banner[:60]))

                all_results.append({
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "banner": banner
                })

    # 输出结果
    print("\n" + "=" * 40)
    print("扫描结果汇总")
    print("=" * 40)
    print("IP\t\t端口\t服务")
    print("-" * 40)
    for r in all_results:
        print("{}\t{}\t{}".format(r["ip"], r["port"], r["service"]))

    # 保存结果
    output_data = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "total_open": len(all_results),
        "results": all_results
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    print("\n[*] 扫描结果已保存到: {}".format(output_file))
