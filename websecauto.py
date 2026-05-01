#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSecAuto - 自动化Web安全检测与漏洞验证平台
=============================================
轻量级Web安全检测框架，支持资产发现、漏洞检测与报告生成。

使用方式:
    python websecauto.py scan    <目标> [选项]    # 资产扫描
    python websecauto.py detect  <URL> [选项]     # 漏洞检测
    python websecauto.py report  <输入文件>        # 生成报告
"""

import sys
import os


def print_banner():
    """打印程序Banner"""
    banner = """
============================================
  WebSecAuto v1.0
  自动化Web安全检测与漏洞验证平台
============================================
"""
    print(banner)


def print_usage():
    """打印使用帮助"""
    print("用法:")
    print("  python websecauto.py <命令> [参数]\n")
    print("命令:")
    print("  scan    <目标IP/域名>   资产扫描 (端口探测 + 服务识别)")
    print("  detect  <目标URL>       漏洞检测 (SQL注入/XSS等)")
    print("  report  <结果文件>      生成HTML格式检测报告")
    print("  help                    显示帮助信息\n")
    print("示例:")
    print("  python websecauto.py scan 192.168.1.1")
    print("  python websecauto.py scan 192.168.1.0/24 -p 80,443")
    print("  python websecauto.py detect http://192.168.1.1")
    print("  python websecauto.py detect http://testphp.vulnweb.com --crawl")
    print("  python websecauto.py report results/scan_result.json\n")


def main():
    """主入口"""
    print_banner()

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "scan":
        from scanner import run_scan
        run_scan(sys.argv[2:])

    elif command == "detect":
        from vuln_check import run_detect
        run_detect(sys.argv[2:])

    elif command == "report":
        from reporter import run_report
        run_report(sys.argv[2:])

    elif command in ("help", "--help", "-h"):
        print_usage()

    else:
        print(f"[!] 未知命令: {command}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
