# WebSecAuto — 自动化Web安全检测与漏洞验证平台

## 项目简介

WebSecAuto 是一个轻量级 Web 安全检测框架，使用 Python 实现。支持资产扫描（端口探测）、漏洞检测（SQL注入、XSS等）和报告生成。**零外部依赖**，基于 Python 标准库即可运行。

## 功能特性

| 模块 | 功能 | 说明 |
|------|------|------|
| `scan` | 资产扫描 | 端口探测 + 服务识别 + Banner抓取 |
| `detect` | 漏洞检测 | SQL注入、XSS、敏感信息泄露、安全头检查 |
| `report` | 报告生成 | HTML格式渗透测试报告 |

## 环境要求

- Python 3.6+
- 可选：Nmap（安装后自动调用，否则使用Python内置扫描）

## 快速开始

### 资产扫描

```bash
# 扫描常见端口
python websecauto.py scan 192.168.1.1

# 指定端口范围
python websecauto.py scan 192.168.1.1 -p 1-1024

# CIDR网段扫描
python websecauto.py scan 192.168.1.0/24 -p 80,443

# 自定义超时和输出文件
python websecauto.py scan example.com -p 80,443,3306 -t 3 -o result.json
```

### 漏洞检测

```bash
# 检测SQL注入
python websecauto.py detect http://testphp.vulnweb.com/artists.php?artist=1

# 开启爬取模式（自动发现更多页面）
python websecauto.py detect http://192.168.1.1 --crawl
```

### 生成报告

```bash
# 将扫描结果生成HTML报告
python websecauto.py report results/scan_20260401_120000.json

# 将漏洞检测结果生成HTML报告
python websecauto.py report results/detect_20260401_120000.json
```

## 项目结构

```
WebSecAuto/
├── websecauto.py      # 主入口，命令分发
├── scanner.py         # 资产扫描模块（端口+服务）
├── vuln_check.py      # 漏洞检测模块（SQL注入/XSS/信息泄露）
├── reporter.py        # 报告生成模块（HTML格式）
├── requirements.txt   # 依赖清单
├── README.md          # 使用文档
├── results/           # 扫描结果（JSON格式）
└── reports/           # 生成报告（HTML格式）
```

## 检测原理

### SQL注入检测
向URL参数注入 SQL 特殊字符（`'`、`"`、`--` 等），通过响应中是否包含数据库错误信息（如 `mysql_fetch`、`SQL syntax`、`ORA-` 等关键字）来判断是否存在注入风险。

### XSS检测
向URL参数注入 `<script>alert(1)</script>` 等 Payload，检查响应中是否原样反射了这些 Payload（未经过滤转义）。

### 敏感信息泄露
检测常见敏感路径（`.git/config`、`.env`、`phpinfo.php` 等）的可访问性，以及响应头中的 Server/X-Powered-By 信息。

## 使用示例

```
============================================
  WebSecAuto v1.0
  自动化Web安全检测与漏洞验证平台
============================================

[*] 目标: http://testphp.vulnweb.com/artists.php?artist=1
[*] 超时: 10s
[*] 爬取模式: 关闭

[1/1] 检测: http://testphp.vulnweb.com/artists.php?artist=1
  [-] 正在检测SQL注入...
    [高危] 发现SQL注入: 检测到SQL错误信息
  [-] 正在检测XSS...
  [-] 正在检测敏感信息泄露...
    [中危] 发现敏感信息泄露: HTTP状态码: 200，路径可访问
  [-] 正在检查安全响应头...
    [低危] 安全头缺失: 缺少X-Frame-Options

============================================
检测完成
发现漏洞: 2 个
  高危: 1 个
  中危: 1 个

[*] 检测结果已保存到: results/detect_20260401_120000.json
```

## 注意事项

1. 测试前请确保已获得目标授权
2. 扫描会发送大量请求，注意不要对生产环境造成影响
3. 漏洞检测结果为辅助判断，建议人工复核确认
4. 本工具仅限授权测试、CTF 竞赛、安全研究等合法用途

## 后续扩展方向

- [ ] 增加更多漏洞检测模块（文件上传、SSRF、命令注入等）
- [ ] 增加WAF识别与绕过模块
- [ ] 增加分布式扫描支持
- [ ] 增加漏洞利用（PoC）验证模块
