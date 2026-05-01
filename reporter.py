#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reporter.py - 报告生成模块
===========================
功能: 将扫描/检测结果生成为HTML格式的渗透测试报告
支持: 加载JSON结果文件，生成格式化的HTML报告
"""

import sys
import os
import json
from datetime import datetime


def print_report_usage():
    """打印报告模块使用帮助"""
    print("用法: python websecauto.py report <结果文件>\n")
    print("说明:")
    print("  将scan或detect命令生成的JSON结果文件转换为HTML报告\n")
    print("示例:")
    print("  python websecauto.py report results/scan_20260401_120000.json")
    print("  python websecauto.py report results/detect_20260401_120000.json")


def color_for_risk(risk_type):
    """根据风险类型返回对应颜色"""
    risk_colors = {
        "SQL注入": "#dc3545",
        "反射型XSS": "#fd7e14",
        "敏感信息泄露": "#fd7e14",
        "安全头缺失": "#ffc107",
    }
    return risk_colors.get(risk_type, "#6c757d")


def level_for_type(risk_type):
    """根据风险类型返回严重等级"""
    levels = {
        "SQL注入": "高危",
        "反射型XSS": "中危",
        "敏感信息泄露": "中危",
        "安全头缺失": "低危",
    }
    return levels.get(risk_type, "信息")


def generate_scan_report(data, output_path):
    """
    生成资产扫描报告

    Args:
        data: 扫描结果数据
        output_path: 输出HTML路径
    """
    results = data.get("results", [])
    open_ports = [r for r in results if r.get("state", "open") == "open"]

    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>资产扫描报告 - WebSecAuto</title>
    <style>
        body { font-family: 'Microsoft YaHei', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }
        .header h1 { margin: 0; font-size: 24px; }
        .header p { margin: 10px 0 0; opacity: 0.8; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; flex: 1; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card .num { font-size: 32px; font-weight: bold; color: #2c3e50; }
        .stat-card .label { font-size: 14px; color: #666; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #2c3e50; color: white; padding: 12px 15px; text-align: left; }
        td { padding: 10px 15px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }
        .service-tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .service-http { background: #d4edda; color: #155724; }
        .service-db { background: #fff3cd; color: #856404; }
        .service-other { background: #e2e3e5; color: #383d41; }
        .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>资产扫描报告</h1>
            <p>扫描时间: {time} | 扫描目标: {target}</p>
        </div>
        <div class="stats">
            <div class="stat-card">
                <div class="num">{total}</div>
                <div class="label">开放端口数</div>
            </div>
            <div class="stat-card">
                <div class="num">{hosts}</div>
                <div class="label">存活主机数</div>
            </div>
            <div class="stat-card">
                <div class="num">{ports_scanned}</div>
                <div class="label">扫描端口数</div>
            </div>
        </div>
        <table>
            <thead>
                <tr><th>IP地址</th><th>端口</th><th>服务</th><th>Banner</th></tr>
            </thead>
            <tbody>
""".format(
        time=data.get("scan_time", "N/A"),
        target=data.get("target", "N/A"),
        total=data.get("total_open", len(open_ports)),
        hosts=1,  # 简化处理
        ports_scanned=data.get("total_open", len(open_ports))
    )

    for r in results:
        service = r.get("service", "unknown")
        css_class = "service-http" if service in ("http", "https") else "service-db" if service in ("mysql", "mssql", "postgresql", "redis", "mongodb") else "service-other"
        banner = r.get("banner", "")
        if len(banner) > 60:
            banner = banner[:60] + "..."

        html += """                <tr>
                    <td>{ip}</td>
                    <td>{port}</td>
                    <td><span class="service-tag {css}">{svc}</span></td>
                    <td>{banner}</td>
                </tr>
""".format(
            ip=r.get("ip", "N/A"),
            port=r.get("port", "N/A"),
            css=css_class,
            svc=service,
            banner=banner
        )

    html += """            </tbody>
        </table>
        <div class="footer">
            <p>由 WebSecAuto v1.0 自动生成 | {time}</p>
        </div>
    </div>
</body>
</html>
""".format(time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("[*] 资产扫描报告已生成: {}".format(output_path))


def generate_detect_report(data, output_path):
    """
    生成漏洞检测报告

    Args:
        data: 检测结果数据
        output_path: 输出HTML路径
    """
    vulns = data.get("vulnerabilities", [])

    # 按风险等级分组
    high_risk = [v for v in vulns if v["type"] == "SQL注入"]
    medium_risk = [v for v in vulns if v["type"] in ("反射型XSS", "敏感信息泄露")]
    low_risk = [v for v in vulns if v["type"] == "安全头缺失"]

    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>漏洞检测报告 - WebSecAuto</title>
    <style>
        body { font-family: 'Microsoft YaHei', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { background: #c0392b; color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }
        .header h1 { margin: 0; font-size: 24px; }
        .header p { margin: 10px 0 0; opacity: 0.8; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; flex: 1; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card .num { font-size: 32px; font-weight: bold; }
        .stat-card .label { font-size: 14px; color: #666; margin-top: 5px; }
        .risk-high .num { color: #dc3545; }
        .risk-medium .num { color: #fd7e14; }
        .risk-low .num { color: #ffc107; }
        .vuln-card { background: white; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .vuln-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
        .vuln-type { font-weight: bold; font-size: 16px; }
        .vuln-level { padding: 3px 10px; border-radius: 4px; font-size: 12px; color: white; }
        .level-high { background: #dc3545; }
        .level-medium { background: #fd7e14; }
        .level-low { background: #ffc107; color: #333; }
        .vuln-body { padding: 0 20px 15px; }
        .vuln-url { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 13px; word-break: break-all; }
        .vuln-evidence { margin-top: 10px; font-size: 14px; color: #555; }
        .vuln-repair { margin-top: 10px; padding: 10px; background: #e8f5e9; border-radius: 4px; font-size: 13px; }
        .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
        .no-vuln { text-align: center; padding: 40px; color: #28a745; font-size: 18px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>漏洞检测报告</h1>
            <p>检测时间: {time} | 目标: {target}</p>
        </div>
        <div class="stats">
            <div class="stat-card risk-high">
                <div class="num">{high}</div>
                <div class="label">高危漏洞</div>
            </div>
            <div class="stat-card risk-medium">
                <div class="num">{medium}</div>
                <div class="label">中危漏洞</div>
            </div>
            <div class="stat-card risk-low">
                <div class="num">{low}</div>
                <div class="label">低危漏洞</div>
            </div>
        </div>
""".format(
        time=data.get("scan_time", "N/A"),
        target=data.get("target", "N/A"),
        high=len(high_risk),
        medium=len(medium_risk),
        low=len(low_risk)
    )

    # 修复建议字典
    repair_suggestions = {
        "SQL注入": "使用参数化查询(PreparedStatement)或ORM框架；对用户输入进行严格过滤和转义；最小化数据库权限",
        "反射型XSS": "对用户输入进行HTML实体编码；使用Content-Security-Policy头；避免直接将用户输入拼接到HTML中",
        "敏感信息泄露": "移除响应头中的Server/X-Powered-By信息；限制敏感路径的访问权限；不要在响应中暴露配置信息",
        "安全头缺失": "在Web服务器配置中添加缺失的安全响应头",
    }

    if vulns:
        for v in vulns:
            vuln_type = v.get("type", "未知")
            level = level_for_type(vuln_type)
            color = color_for_risk(vuln_type)
            level_class = "level-high" if level == "高危" else "level-medium" if level == "中危" else "level-low"
            repair = repair_suggestions.get(vuln_type, "请根据具体漏洞情况修复")

            html += """        <div class="vuln-card">
            <div class="vuln-header">
                <span class="vuln-type">{type}</span>
                <span class="vuln-level {level_class}">{level}</span>
            </div>
            <div class="vuln-body">
                <div class="vuln-url">URL: {url}</div>
                <div class="vuln-evidence"><strong>发现:</strong> {evidence}</div>
                <div class="vuln-repair"><strong>修复建议:</strong> {repair}</div>
            </div>
        </div>
""".format(
                type=vuln_type,
                level_class=level_class,
                level=level,
                url=v.get("url", "N/A"),
                evidence=v.get("evidence", "N/A"),
                repair=repair
            )
    else:
        html += '        <div class="no-vuln">未发现安全漏洞</div>\n'

    html += """        <div class="footer">
            <p>由 WebSecAuto v1.0 自动生成 | {time}</p>
        </div>
    </div>
</body>
</html>
""".format(time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("[*] 漏洞检测报告已生成: {}".format(output_path))


def run_report(args):
    """
    报告生成入口函数

    加载JSON结果文件，根据内容类型自动选择报告模板。

    Args:
        args: 命令行参数列表
    """
    if not args or args[0] in ("--help", "-h"):
        print_report_usage()
        return

    input_file = args[0]

    if not os.path.exists(input_file):
        print("[!] 文件不存在: {}".format(input_file))
        return

    # 读取JSON结果
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print("[!] JSON解析失败: {}".format(e))
        return
    except Exception as e:
        print("[!] 读取文件失败: {}".format(e))
        return

    # 根据内容判断报告类型
    output_dir = "reports"
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if "vulnerabilities" in data:
        # 漏洞检测报告
        output_path = "{}/vuln_report_{}.html".format(output_dir, timestamp)
        generate_detect_report(data, output_path)
    elif "results" in data:
        # 资产扫描报告
        output_path = "{}/scan_report_{}.html".format(output_dir, timestamp)
        generate_scan_report(data, output_path)
    else:
        print("[!] 无法识别的结果文件格式")
        print("    支持的格式: scan命令生成的JSON 或 detect命令生成的JSON")
