# ✈️ AjiPilot (Ajiasu Web Controller)

> 一个极致精简、具备“自愈能力”的 Ajiasu 命令行 Web 控制面板。

**AjiPilot** 是一个单文件 Python 脚本，旨在为 `ajiasu` 命令行工具提供一个现代化的 Web 界面。它不仅仅是一个 UI，更是一个**进程守护者**，解决了长时间运行下的僵尸进程、连接残留和协议管理问题。

## ✨ 核心特性

* **⚡️ 智能协议管理**：默认首选 **lwip** 协议（兼容性与性能的最佳平衡），同时支持 TCP/UDP/Proxy。
* **🧟‍♂️ 僵尸进程收割器 (Zombie Reaper)**：内置后台线程，自动清理 defunct 僵尸进程，防止系统资源耗尽。
* **🛡️ 连接守护与自愈**：
    * **严格单连接**：确保同一时间只有一个 VPN 连接，多余连接会被强制杀除。
    * **断线自愈**：检测到无连接时，自动重连至可用节点。
    * **启动清理**：启动或操作前，暴力清理残留的 `ajiasu` 进程组。
* **🔄 自动轮换 (Auto-Switch)**：支持每 12~24 小时自动切换节点，保持 IP 活跃度。
* **📊 实时状态**：显示当前节点、连接协议以及通过外网查询到的真实 IP。

## 🛠️ 部署指南

### 1. 环境要求
* Linux 环境 (CentOS/Ubuntu/Debian 等)
* Python 3.6+
* `ajiasu` 二进制文件已安装

### 2. 快速启动

只需安装 Flask 即可运行：

```bash
# 安装依赖
pip3 install flask

# 赋予脚本执行权限
chmod +x ajiasu_web_lwip.py

# 启动 (默认端口 8000)
python3 ajiasu_web_lwip.py
