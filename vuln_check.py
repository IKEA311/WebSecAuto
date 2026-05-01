#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_check.py - 漏洞检测模块
=============================
功能: 检测常见Web漏洞（SQL注入、XSS、敏感信息泄露等）
使用简单的Payload发送和响应分析来判断漏洞存在性。
"""

import sys
import os
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse, urljoin


# 忽略SSL证书验证（测试环境常用）
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


# ============================================================
# Payload库
# ============================================================

SQL_INJECTION_PAYLOADS = [
    # 基于错误的SQL注入检测
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "1' OR '1'='1",
    "1' AND '1'='1",
    "admin' --",
    "admin' #",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT 1,2,3,4 --",
    "'; DROP TABLE users --",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
]

# SQL注入的典型错误关键字
SQL_ERROR_KEYWORDS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "You have an error in your SQL",
    "Unclosed quotation mark",
    "Warning: mysql",
    "Warning: pg_",
    "SQLite3::",
    "ORA-",
    "MYSQL",
    "mysql error",
    "syntax error",
    "unexpected T_",
    "PDOException",
    "SQLSTATE",
    "Division by zero",
]


def print_detect_usage():
    """打印漏洞检测模块使用帮助"""
    print("用法: python websecauto.py detect <URL> [选项]\n")
    print("参数:")
    print("  URL\t\t\t目标URL (如 http://example.com/page.php?id=1)")
    print("  --crawl\t\t启用简单爬取 (自动发现更多URL)\n")
    print("示例:")
    print("  python websecauto.py detect http://testphp.vulnweb.com/artists.php?artist=1")
    print("  python websecauto.py detect http://example.com/page.php?id=1 --crawl")
    print("  python websecauto.py detect http://192.168.1.1")


def send_http_request(url, timeout=10):
    """
    发送HTTP GET请求并返回响应

    Args:
        url: 目标URL
        timeout: 超时秒数

    Returns:
        tuple: (响应状态码, 响应文本, 响应头) 或 (None, None, None)
    """
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSecAuto/1.0",
                "Accept": "text/html,application/xhtml+xml,*/*",
            }
        )
        resp = urllib.request.urlopen(req, timeout=timeout, context=ssl_context)
        body = resp.read().decode("utf-8", errors="replace")
        return (resp.status, body, dict(resp.headers))

    except urllib.error.HTTPError as e:
        # HTTP错误也读取响应体，有时错误页包含SQL错误信息
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return (e.code, body, dict(e.headers))

    except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
        print("    [!] 请求失败: {}".format(e))
        return (None, None, None)


def check_sql_injection(url, timeout=10):
    """
    检测SQL注入漏洞

    通过在URL参数或路径中注入SQL特殊字符，判断响应中是否包含数据库错误信息
    或出现异常响应差异。

    Args:
        url: 目标URL
        timeout: 超时秒数

    Returns:
        list[dict]: 检测到的潜在漏洞列表
    """
    vulnerabilities = []

    # 解析URL中的参数
    parsed = urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        # 没有查询参数，尝试注入到路径末尾
        for payload in SQL_INJECTION_PAYLOADS:
            test_url = url.rstrip("/") + "/" + urllib.parse.quote(payload)
            status, body, _ = send_http_request(test_url, timeout)
            if body and any(kw.lower() in body.lower() for kw in SQL_ERROR_KEYWORDS):
                vulnerabilities.append({
                    "type": "SQL注入",
                    "url": test_url,
                    "payload": payload,
                    "evidence": "检测到SQL错误信息"
                })
                break  # 发现一个即可
        return vulnerabilities

    # 遍历每个参数进行测试
    for param in query_params:
        original_value = query_params[param][0]

        for payload in SQL_INJECTION_PAYLOADS:
            # 构造注入URL
            new_params = query_params.copy()
            new_params[param] = [payload]
            test_url = url.replace(
                original_value,
                urllib.parse.quote(payload)
            )

            status, body, _ = send_http_request(test_url, timeout)

            if body is None:
                continue

            # 检查响应中是否包含数据库错误信息
            matched_keywords = []
            body_lower = body.lower()

            for kw in SQL_ERROR_KEYWORDS:
                if kw.lower() in body_lower:
                    matched_keywords.append(kw)

            if matched_keywords:
                # 截取错误上下文证据
                evidence = " | ".join(matched_keywords[:3])
                vulnerabilities.append({
                    "type": "SQL注入",
                    "url": test_url,
                    "payload": payload,
                    "evidence": evidence[:100]
                })

                # 发现一个有效的注入点就继续测下一个参数
                break

    return vulnerabilities


def check_xss(url, timeout=10):
    """
    检测反射型XSS漏洞

    向URL参数注入XSS Payload，检查响应中是否原样反射。

    Args:
        url: 目标URL
        timeout: 超时秒数

    Returns:
        list[dict]: 检测到的潜在漏洞列表
    """
    vulnerabilities = []
    parsed = urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        return vulnerabilities  # 无参数时无法检测反射型XSS

    for param in query_params:
        for payload in XSS_PAYLOADS:
            # 构造测试URL
            new_params = query_params.copy()
            new_params[param] = [payload]
            test_url = url.replace(query_params[param][0], urllib.parse.quote(payload))

            status, body, _ = send_http_request(test_url, timeout)

            if body and payload in body:
                vulnerabilities.append({
                    "type": "反射型XSS",
                    "url": test_url,
                    "payload": payload,
                    "evidence": "Payload在响应中未经过滤输出"
                })
                break  # 找到一个即可

    return vulnerabilities


def check_sensitive_info(url, timeout=10):
    """
    检测敏感信息泄露

    检查常见敏感路径和响应头中的信息泄露。

    Args:
        url: 目标URL
        timeout: 超时秒数

    Returns:
        list[dict]: 检测到的信息泄露列表
    """
    vulnerabilities = []
    base_url = "{0.scheme}://{0.netloc}".format(urlparse(url))

    # 常见敏感路径
    sensitive_paths = [
        "/.git/config",
        "/.env",
        "/robots.txt",
        "/phpinfo.php",
        "/info.php",
        "/.htaccess",
        "/config.php",
        "/wp-config.php",
        "/WEB-INF/web.xml",
        "/crossdomain.xml",
        "/sitemap.xml",
        "/admin/",
        "/backup/",
    ]

    for path in sensitive_paths:
        test_url = base_url + path
        status, body, headers = send_http_request(test_url, timeout)

        if status and status < 400:
            vulnerability = {
                "type": "敏感信息泄露",
                "url": test_url,
                "payload": "",
                "evidence": "HTTP状态码: {}，路径可访问".format(status)
            }

            # 根据内容判断泄露了哪些敏感信息
            if body:
                if "Index of /" in body:
                    vulnerability["evidence"] += " (目录遍历)"
                elif path == "/robots.txt" and "Disallow:" in body:
                    vulnerability["evidence"] += " (发现敏感路径)"
                elif path == "/.env" and "DB_" in body:
                    vulnerability["evidence"] += " (发现数据库配置)"

            vulnerabilities.append(vulnerability)

    # 检查响应头中的信息泄露
    _, _, headers = send_http_request(base_url, timeout)
    if headers:
        server = headers.get("Server", "")
        if server:
            vulnerabilities.append({
                "type": "敏感信息泄露",
                "url": base_url,
                "payload": "",
                "evidence": "响应头泄露Server版本: {}".format(server[:50])
            })
        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            vulnerabilities.append({
                "type": "敏感信息泄露",
                "url": base_url,
                "payload": "",
                "evidence": "响应头泄露技术栈: {}".format(x_powered)
            })

    return vulnerabilities


def check_missing_headers(url, timeout=10):
    """
    检查安全响应头缺失

    常见的Web安全响应头及其说明:
    - X-Frame-Options: 防止点击劫持
    - X-Content-Type-Options: 防止MIME类型嗅探
    - Content-Security-Policy: 防止XSS和数据注入
    - Strict-Transport-Security: 强制HTTPS
    """
    vulnerabilities = []
    security_headers = {
        "X-Frame-Options": "缺少X-Frame-Options，存在点击劫持风险",
        "X-Content-Type-Options": "缺少X-Content-Type-Options，存在MIME嗅探风险",
        "Content-Security-Policy": "缺少Content-Security-Policy，增加XSS风险",
        "Strict-Transport-Security": "缺少HSTS，存在中间人攻击风险",
        "X-XSS-Protection": "缺少X-XSS-Protection头",
    }

    _, _, headers = send_http_request(url, timeout)
    if headers:
        for header, desc in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    "type": "安全头缺失",
                    "url": url,
                    "payload": "",
                    "evidence": desc
                })

    return vulnerabilities


def crawl_links(url, timeout=10, max_links=20):
    """
    简单爬虫：提取页面中的链接

    解析HTML页面中的<a>标签，提取同域名下的链接。
    用于扩展检测范围。

    Args:
        url: 起始URL
        timeout: 超时秒数
        max_links: 最大提取链接数

    Returns:
        list[str]: 发现的URL列表
    """
    status, body, _ = send_http_request(url, timeout)
    if not body:
        return []

    links = []
    base_domain = urlparse(url).netloc

    # 简单提取href链接
    import re
    href_pattern = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)

    for href in href_pattern.findall(body):
        # 处理相对路径
        full_url = urljoin(url, href)
        # 只保留同域名且非空链接
        if urlparse(full_url).netloc == base_domain and full_url not in links:
            # 过滤静态资源
            if not any(ext in full_url for ext in [".css", ".js", ".png", ".jpg", ".ico", ".woff"]):
                links.append(full_url)
                if len(links) >= max_links:
                    break

    return links


def run_detect(args):
    """
    漏洞检测入口函数

    对目标URL执行多项安全检查:
    1. SQL注入检测
    2. XSS检测
    3. 敏感信息泄露检测
    4. 安全响应头检查
    5. 可选: 爬取更多链接后递归检测

    Args:
        args: 命令行参数列表
    """
    if not args or args[0] in ("--help", "-h"):
        print_detect_usage()
        return

    target_url = args[0]
    enable_crawl = "--crawl" in args
    timeout = 10

    # 确保URL格式完整
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
        print("[*] 自动补全协议: {}".format(target_url))

    print("[*] 目标: {}".format(target_url))
    print("[*] 超时: {}s".format(timeout))
    if enable_crawl:
        print("[*] 爬取模式: 开启\n")
    else:
        print("[*] 爬取模式: 关闭\n")

    # 收集待检测的URL列表
    urls_to_check = [target_url]

    if enable_crawl:
        print("[*] 正在爬取页面链接...")
        discovered = crawl_links(target_url, timeout)
        print("[*] 发现 {} 个页面链接\n".format(len(discovered)))
        urls_to_check.extend(discovered)

    all_vulnerabilities = []

    for idx, url in enumerate(urls_to_check, 1):
        print("\n[{}/{}] 检测: {}".format(idx, len(urls_to_check), url))

        # 1. SQL注入检测
        print("  [-] 正在检测SQL注入...")
        sql_vulns = check_sql_injection(url, timeout)
        for v in sql_vulns:
            print("    [高危] 发现{}: {}".format(v["type"], v["evidence"]))
        all_vulnerabilities.extend(sql_vulns)

        # 2. XSS检测
        print("  [-] 正在检测XSS...")
        xss_vulns = check_xss(url, timeout)
        for v in xss_vulns:
            print("    [中危] 发现{}: {}".format(v["type"], v["evidence"]))
        all_vulnerabilities.extend(xss_vulns)

        # 3. 敏感信息泄露（只在主URL检测一次）
        if idx == 1:
            print("  [-] 正在检测敏感信息泄露...")
            info_vulns = check_sensitive_info(url, timeout)
            for v in info_vulns:
                print("    [{}] 发现{}: {}".format(
                    "高危" if "密码" in v.get("evidence", "") else "中危",
                    v["type"], v["evidence"][:80]))
            all_vulnerabilities.extend(info_vulns)

            # 4. 安全头检测
            print("  [-] 正在检查安全响应头...")
            header_vulns = check_missing_headers(url, timeout)
            for v in header_vulns:
                print("    [低危] {}: {}".format(v["type"], v["evidence"]))
            all_vulnerabilities.extend(header_vulns)

    # 保存结果
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = "results/detect_{}.json".format(timestamp)

    output_data = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target_url,
        "total_vulnerabilities": len(all_vulnerabilities),
        "total_urls_checked": len(urls_to_check),
        "crawl_enabled": enable_crawl,
        "vulnerabilities": all_vulnerabilities
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 40)
    print("检测完成")
    print("=" * 40)
    print("检测URL数: {}".format(len(urls_to_check)))
    print("发现漏洞: {} 个".format(len(all_vulnerabilities)))

    if all_vulnerabilities:
        risk_count = sum(1 for v in all_vulnerabilities if v["type"] in ("SQL注入",))
        print("  高危: {} 个".format(risk_count))
        medium_count = sum(1 for v in all_vulnerabilities if v["type"] in ("反射型XSS", "敏感信息泄露"))
        print("  中危: {} 个".format(medium_count))
        low_count = sum(1 for v in all_vulnerabilities if v["type"] == "安全头缺失")
        print("  低危: {} 个".format(low_count))

    print("\n[*] 检测结果已保存到: {}".format(output_file))
