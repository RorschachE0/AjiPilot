#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ajiasu — 最简 Web 面板（含：启动清理、连接/断开一律清理、协议选择、当前选择+外网IP 显示）

变更要点（本次修复）：
- 默认协议改为 **lwip**（前端默认选中；后端未传协议时也默认 lwip）。
- 解决 kill 不干净 / 僵尸进程：
  - 增强清理：进程组 SIGTERM → 短等待 → 进程组 SIGKILL；循环确认消亡；如仍残留再补杀一轮。
  - 新增后台 **僵尸收割器 (reaper)**：周期调用 waitpid(-1, WNOHANG) 收割子进程，避免 defunct。
- 严格识别 `ajiasu connect`：解析命令行为 token，要求 `tokens[0]` 的可执行文件名为 `ajiasu` 且 `tokens[1] == 'connect'`。
- 强约束你的需求：
  1) 启动时必定先杀掉 **所有** `ajiasu connect`；
  2) 点击“连接所选节点”前，**无条件**先杀掉 **所有** `ajiasu connect`；
  3) 点击“断开当前连接”时，也**无条件**杀掉 **所有** `ajiasu connect`。

功能
- 列出节点：调用 `./ajiasu list` 并解析
- 连接节点：`./ajiasu connect "城市 #编号"`，把选定协议 (udp/tcp/lwip/proxy) 写入 stdin（默认 lwip）
- 状态栏：显示“已选择/已连接的节点标签 + 通过 `curl ifconfig.me` 查询的外网 IP”

健壮性
- 不依赖 `__file__`；通过环境变量/工作目录/系统 PATH 自动找 `ajiasu`
- 找不到二进制时不崩溃，接口返回清晰错误 JSON
- 禁用 Flask reloader；自动探测端口，避免 SystemExit(1)

使用
  pip install flask
  export AJIASU_DIR=/path/to/dir           # 可选
  export AJIASU_BIN=/path/to/ajiasu        # 建议显式设置；否则在 CWD 或 PATH 中寻找
  ## /etc/profile
    export AJIASU_BIN=/root/ajiasu
    export AJIASU_AUTOSWITCH_SEC=43200     # 可改，不低于300
  python3 ajiasu_web.py
  打开 http://127.0.0.1:8000

自测
  python3 ajiasu_web.py --selftest
  GET /api/selftest
"""

import os
import re
import sys
import json
import time
import socket
import shutil
import signal
import shlex
import threading
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from flask import Flask, jsonify, request, Response

# ---------------------------------------------------------------------------
# 路径解析（不硬依赖 __file__）
# ---------------------------------------------------------------------------

def _get_base_dir() -> Path:
    env_dir = os.environ.get("AJIASU_DIR")
    if env_dir:
        return Path(env_dir)
    try:
        return Path(__file__).resolve().parent  # type: ignore[name-defined]
    except NameError:
        return Path.cwd()

BASE_DIR = _get_base_dir()


def _find_ajiasu_path() -> Optional[str]:
    env_bin = os.environ.get("AJIASU_BIN")
    if env_bin:
        return env_bin
    candidate = BASE_DIR / "ajiasu"
    if candidate.exists():
        return str(candidate)
    found = shutil.which("ajiasu")
    if found:
        return found
    return None

AJIASU_PATH: Optional[str] = _find_ajiasu_path()

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
APP_HOST = os.environ.get("AJIASU_HOST", "0.0.0.0")
APP_PORT_DEFAULT = int(os.environ.get("AJIASU_PORT", "8000"))
ALLOWED_PROTOCOLS = {"udp", "tcp", "lwip", "proxy"}
# 自动切换配置（默认开启，每 24 小时切换一次）
AUTOSWITCH_ENABLED = os.environ.get("AJIASU_AUTOSWITCH", "1") != "0"
# 安全下限：至少 300 秒，防误设导致频繁切换
try:
    _autoswitch_env = int(os.environ.get("AJIASU_AUTOSWITCH_SEC", str(12*3600)))
except Exception:
    _autoswitch_env = 12*3600
AUTOSWITCH_INTERVAL_SEC = max(_autoswitch_env, 300)

# ---------------------------------------------------------------------------
# 解析输出
# ---------------------------------------------------------------------------
NODE_LINE_RE = re.compile(r"^(?P<id>\S+)\s+(?P<status>\S+)\s+(?P<city>\S+)\s+#(?P<num>\d+)\s*$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def parse_list_output(text: str) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if set(line) <= {"=", "-", "_", " "}:
            continue
        m = NODE_LINE_RE.match(line)
        if m:
            node_id = m.group("id")
            status = m.group("status")
            city = m.group("city")
            num = int(m.group("num"))
            label = f"{city} #{num}"
            nodes.append({
                "id": node_id,
                "status": status,
                "city": city,
                "num": num,
                "label": label,
            })
            continue
        if line.startswith("Web Site:"):
            summary["website"] = line.split(":", 1)[1].strip()
        elif line.startswith("Login Result:"):
            summary["login_result"] = line.split(":", 1)[1].strip()
        elif line.startswith("Membership:"):
            summary["membership"] = line.split(":", 1)[1].strip()
        elif line.startswith("Expiration:"):
            summary["expiration"] = line.split(":", 1)[1].strip()
    return {"nodes": nodes, "summary": summary}

# ---------------------------------------------------------------------------
# 命令执行 & 健康检查
# ---------------------------------------------------------------------------

def _ensure_ajiasu_available(path: Optional[str]) -> Tuple[bool, str]:
    if not path:
        return False, (
            "AJIASU_BIN 未设置，且未在工作目录或 PATH 中找到 'ajiasu'。"
        )
    p = Path(path)
    if not p.exists():
        return False, f"未找到 ajiasu 二进制：{path}"
    if not os.access(str(p), os.X_OK):
        return False, f"ajiasu 不可执行：{path}"
    return True, "ok"


def run_cmd(args: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=str(BASE_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )

# 最近一次列表（用于校验 label）
_last_nodes_lock = threading.Lock()
_last_nodes: List[Dict[str, Any]] = []
_last_list_ts: Optional[float] = None

# 当前连接（label/protocol/pid）
_current_conn_lock = threading.Lock()
_current_conn: Optional[Dict[str, Any]] = None

# 全局操作锁：串行化连接/断开/清理，杜绝并发产生多个 connect
_op_lock = threading.RLock()

# 自愈(自动保持至少 1 个连接)的退避控制
_last_autoc_ts = 0.0
_AUTOCONNECT_MIN_BACKOFF = float(os.environ.get("AJIASU_AUTOCONNECT_BACKOFF", "3"))

# ---------------------------------------------------------------------------
# 连接生命周期 & 启动/操作清理（基于 token 的 connect 识别）
# ---------------------------------------------------------------------------

def _is_connect_cmdline(cmdline: str) -> bool:
    """严格识别：第一个 token 的可执行名必须是 'ajiasu'，第二个 token 必须是 'connect'。"""
    try:
        tokens = shlex.split(cmdline)
    except Exception:
        tokens = cmdline.split()
    if len(tokens) < 2:
        return False
    exec_name = Path(tokens[0]).name  # 允许 '/root/ajiasu'
    subcmd = tokens[1]
    return exec_name == "ajiasu" and subcmd == "connect"


def _collect_connect_pids() -> List[int]:
    """尽量只命中 'ajiasu connect' 进程。优先 pgrep；其次 ps。"""
    pids: List[int] = []
    # 1) pgrep
    if shutil.which("pgrep"):
        try:
            out = subprocess.run(
                ["pgrep", "-fa", "ajiasu"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            ).stdout or ""
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(" ", 1)
                if len(parts) != 2:
                    continue
                pid_str, cmdline = parts
                if pid_str.isdigit() and _is_connect_cmdline(cmdline):
                    pids.append(int(pid_str))
        except Exception:
            pass
    # 2) ps fallback（更可靠：查看完整 args）
    try:
        out = subprocess.run(
            ["ps", "-eo", "pid,args", "--no-headers"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        ).stdout or ""
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            pid_str, cmdline = parts
            if pid_str.isdigit() and _is_connect_cmdline(cmdline):
                pids.append(int(pid_str))
    except Exception:
        pass

    return sorted(set(pids))


def _kill_pids(pids: List[int]) -> Dict[str, Any]:
    """
    尽可能把 ajiasu connect 及其同进程组的子进程杀干净。
    先 SIGTERM，短暂等待；仍存活则 SIGKILL；循环多轮直到消失或超时。
    """
    killed, errors = [], []

    # 先尝试 TERM 整个进程组
    for pid in pids:
        try:
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGTERM)
            except Exception:
                os.kill(pid, signal.SIGTERM)
        except Exception as e:
            errors.append({"pid": pid, "error": f"sigterm_failed:{e}"})

    # 等一小会
    time.sleep(0.25)

    # 升级为 KILL，并在一个小时间窗内确认进程确实消失
    deadline = time.time() + 5.0  # 最多等 5 秒
    still = set(pids)

    while still and time.time() < deadline:
        # 尝试 KILL 进程组
        for pid in list(still):
            try:
                # 0 信号检测是否仍存在
                os.kill(pid, 0)
                try:
                    pgid = os.getpgid(pid)
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                    except Exception:
                        os.kill(pid, signal.SIGKILL)
                except Exception:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except Exception:
                        pass
            except OSError:
                # 不存在/已退出
                killed.append(pid)
                still.discard(pid)

        time.sleep(0.2)

        # 再扫一遍，去掉已经没了的
        for pid in list(still):
            try:
                os.kill(pid, 0)
            except OSError:
                killed.append(pid)
                still.discard(pid)

    # 超时还残留，记录错误
    for pid in still:
        errors.append({"pid": pid, "error": "still_alive_after_kill"})

    return {"killed": sorted(set(killed)), "errors": errors}


def kill_all_connects(reason: str) -> Dict[str, Any]:
    """
    无条件清理：用于启动、连接前、手动断开。
    确保循环检测直到没有任何 ajiasu connect 残留。
    """
    global _current_conn
    with _op_lock:
        found = _collect_connect_pids()
        result = {"killed": [], "errors": []}
        if found:
            print(f"[cleanup] {reason}: found={found}")
            result = _kill_pids(found)
            remain = _collect_connect_pids()
            if remain:
                print(f"[cleanup] remain after kill -> {remain}, trying again")
                final = _kill_pids(remain)
                result["killed"].extend(final["killed"])
                result["errors"].extend(final["errors"])
        with _current_conn_lock:
            _current_conn = None
        print(f"[cleanup] {reason}: killed={result['killed']} errors={result['errors']}")
        return {"reason": reason, "found": found, "killed": sorted(set(result["killed"])), "errors": result["errors"]}


def graceful_disconnect(reason: str = "manual") -> Dict[str, Any]:
    """优先调用 `ajiasu disconnect`，若不奏效则回退为 kill_all_connects。"""
    ok, _ = _ensure_ajiasu_available(AJIASU_PATH)
    if ok:
        try:
            proc = run_cmd([AJIASU_PATH, "disconnect"], timeout=15)
            if proc.returncode == 0:
                with _current_conn_lock:
                    global _current_conn
                    _current_conn = None
                return {
                    "ok": True,
                    "via": "cli",
                    "returncode": 0,
                    "stdout": proc.stdout.decode("utf-8", errors="replace"),
                    "stderr": proc.stderr.decode("utf-8", errors="replace"),
                }
        except Exception as e:
            # fallthrough to kill
            return kill_all_connects(f"cli_failed:{e}")
    # 无 ajiasu 或 CLI 失败
    return kill_all_connects("no_cli_or_failed")


# ---------------------------------------------------------------------------
# 僵尸收割器（reaper）+ 单实例强制器：避免 defunct，强制最多 1 个 connect
# ---------------------------------------------------------------------------

def _reaper_loop():
    """后台收割子进程，避免 defunct（僵尸）堆积；Linux + Python3.6 兼容。"""
    while True:
        try:
            while True:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
        except ChildProcessError:
            pass
        except Exception:
            pass
        time.sleep(0.5)

# ---------------- 自愈：确保始终至少 1 个连接 ----------------

def _default_label() -> Optional[str]:
    """确定一个可用标签：优先当前；否则取最近列表第一个；再不行就 None。"""
    with _current_conn_lock:
        if _current_conn and _current_conn.get("label"):
            return str(_current_conn["label"])  # type: ignore
    with _last_nodes_lock:
        nodes = list(_last_nodes)
    if not nodes:
        nodes = _refresh_nodes() or []
    if nodes:
        return nodes[0]["label"]
    return None

def _ensure_one_connection(reason: str = "watchdog") -> Dict[str, Any]:
    """若系统内没有任何 `ajiasu connect`，则自动以 lwip 连接一个默认节点。"""
    global _last_autoc_ts
    with _op_lock:
        pids = _collect_connect_pids()
        if pids:
            return {"ok": True, "existing": pids}
        now = time.time()
        if now - _last_autoc_ts < _AUTOCONNECT_MIN_BACKOFF:
            return {"ok": False, "skipped": "backoff"}
        label = _default_label()
        if not label:
            print("[heal] abort: no label available")
            return {"ok": False, "error": "no_label"}
        ok, msg = _ensure_ajiasu_available(AJIASU_PATH)
        if not ok:
            print(f"[heal] abort: {msg}")
            return {"ok": False, "error": msg}
        try:
            proc = subprocess.Popen(
                [AJIASU_PATH, "connect", label],
                cwd=str(BASE_DIR),
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                if proc.stdin:
                    proc.stdin.write(("lwip\n").encode("utf-8", errors="ignore"))
                    proc.stdin.flush()
                    proc.stdin.close()
            except Exception:
                pass
            with _current_conn_lock:
                global _current_conn
                _current_conn = {"pid": proc.pid, "label": label, "protocol": "lwip", "started_at": time.time()}
            _last_autoc_ts = now
            print(f"[heal] {reason}: connected {label} pid={proc.pid}")
            return {"ok": True, "pid": proc.pid, "label": label}
        except Exception as e:
            print(f"[heal] error: {e}")
            return {"ok": False, "error": str(e)}

def _proc_start_ticks(pid: int) -> int:
    """读取 /proc/<pid>/stat 的 starttime（时钟 tick），越大越新。失败则返回 -1。"""
    try:
        with open("/proc/%d/stat" % pid, "r") as f:
            data = f.read()
        # stat 字段：第 22 个（从 1 开始，索引21）为 starttime
        # 但第二个字段 comm 可能带空格且括号包裹，简单做法：从右侧切 20 个字段
        tail = data.rsplit(" ", 20)
        start_str = tail[0].split()[-1]
        return int(start_str)
    except Exception:
        return -1

def _enforce_single_connect(prefer_pid: Optional[int] = None) -> Dict[str, Any]:
    """确保系统里最多只有一个 `ajiasu connect`。如果只有 0/1 个，绝不杀。"""
    with _op_lock:
        pids = _collect_connect_pids()
        if len(pids) <= 1:
            keep_pid = pids[0] if pids else None
            print(f"[enforcer] ok: found={pids} keep={keep_pid}")
            return {"kept": keep_pid, "killed": [], "found": pids}
        keep: Optional[int] = None
        if prefer_pid and prefer_pid in pids:
            keep = prefer_pid
        elif _current_conn and isinstance(_current_conn.get("pid"), int) and _current_conn["pid"] in pids:
            keep = int(_current_conn["pid"])  # type: ignore
        else:
            # 选 starttime 最大（最新）的那个；失败则以最大 PID 兜底
            best = (-1, None)  # (ticks, pid)
            for pid in pids:
                t = _proc_start_ticks(pid)
                if t > best[0]:
                    best = (t, pid)
            keep = best[1] or max(pids)
        # 需要杀掉的
        to_kill = [p for p in pids if p != keep]
        killed = []
        if to_kill:
            r = _kill_pids(to_kill)
            killed = r.get("killed", [])
        print(f"[enforcer] fix: found={pids} keep={keep} killed={killed}")
        return {"kept": keep, "killed": killed, "found": pids}

def _enforcer_loop():
    """后台强制器：仅在发现 ≥2 个 connect 时才动作；为 0 时自动自愈连接；单个连接绝不干扰。"""
    while True:
        try:
            pids = _collect_connect_pids()
            if len(pids) == 0:
                _ensure_one_connection("enforcer")
            elif len(pids) > 1:
                _enforce_single_connect()
        except Exception as e:
            print(f"[enforcer] error: {e}")
        time.sleep(2.0)

# ---------------------------------------------------------------------------
# 外网 IP（curl ifconfig.me）
# ---------------------------------------------------------------------------

def _is_ip(text: str) -> bool:
    s = text.strip()
    return bool(IPV4_RE.match(s) or IPV6_RE.match(s))


def get_external_ip(timeout: int = 5) -> Dict[str, Any]:
    for url in ["ifconfig.me", "https://ifconfig.me", "https://ipinfo.io/ip", "https://icanhazip.com"]:
        try:
            if shutil.which("curl"):
                cp = subprocess.run(
                    ["curl", "-s", "--max-time", str(timeout), url],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
                )
                ip = (cp.stdout or "").strip()
            else:
                import urllib.request  # noqa
                with urllib.request.urlopen(url, timeout=timeout) as resp:
                    ip = resp.read().decode("utf-8", errors="ignore").strip()
            if _is_ip(ip):
                return {"ok": True, "ip": ip, "source": url}
        except Exception:
            continue
    return {"ok": False, "error": "无法获取外网 IP（curl/网络受限）"}

# ---------------------------------------------------------------------------
# Web App（单文件）
# ---------------------------------------------------------------------------
app = Flask(__name__)

@app.get("/")
def index() -> Response:
    html = """
<!doctype html>
<html lang=\"zh-CN\">
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>ajiasu — 最简节点面板</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;max-width:920px;margin:20px auto;padding:0 12px;color:#e5e7eb;background:#0b0f14}
button,select,input{background:#0f172a;color:#e5e7eb;border:1px solid #1f2937;border-radius:8px;padding:8px 10px}
.btn{background:#2563eb;border:none}
.card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:12px;margin:12px 0}
.table{width:100%;border-collapse:collapse}
.table th,.table td{border-bottom:1px dashed #1f2937;padding:8px;text-align:left}
.mono{font-family:ui-monospace,Consolas,Menlo,monospace}
.badge{padding:1px 6px;border:1px solid #1f2937;border-radius:999px}
small{color:#9ca3af}
.notice{margin-top:6px}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.statusbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.pill{padding:2px 8px;border:1px solid #1f2937;border-radius:999px;background:#0b1220}
</style>
<h2>ajiasu — 最简节点面板</h2>
<div class=\"card\">
  <div class=\"controls\">
    <button class=\"btn\" id=\"btn-list\">列出节点 (./ajiasu list)</button>
    <select id=\"protocol\">
      <option selected>lwip</option>
      <option>tcp</option>
      <option>udp</option>
      <option>proxy</option>
    </select>
    <button class=\"btn\" id=\"btn-connect\" disabled>连接所选节点</button>
    <button id=\"btn-disconnect\">断开当前连接</button>
  </div>
  <div class=\"notice\"><small>说明：连接/断开/启动都会先清理所有 `ajiasu connect` 进程；连接时把所选协议写入 ajiasu 的 stdin（默认 lwip）。</small></div>
</div>
<div class=\"card\">
  <div class=\"statusbar\">
    <div>已选择/已连接：<span id=\"selLabel\" class=\"pill\">无</span></div>
    <div>外网 IP（curl ifconfig.me）：<span id=\"extIp\" class=\"pill\">未知</span></div>
  </div>
</div>
<div class=\"card\">
  <table class=\"table\">
    <thead><tr><th style=\"width:60px\">选</th><th>节点ID</th><th style=\"width:90px\">状态</th><th style=\"width:80px\">城市</th><th style=\"width:120px\">标签</th></tr></thead>
    <tbody id=\"tbody\"></tbody>
  </table>
  <div><small>共 <span id=\"count\">0</span> 个</small></div>
</div>
<div class=\"card mono\" id=\"out\" style=\"white-space:pre-wrap\"></div>
<script>
const $=s=>document.querySelector(s); const tbody=$('#tbody'); const out=$('#out');
let NODES=[]; let SELECTED=null; let CURRENT=null;
function setSelectedLabel(lbl){ $('#selLabel').textContent = lbl || '无'; }
function setExternalIp(ip){ $('#extIp').textContent = ip || '未知'; }
function render(nodes){ tbody.innerHTML=''; nodes.forEach(n=>{ const tr=document.createElement('tr'); const checked = (CURRENT && CURRENT.label===n.label) || (SELECTED===n.label);
  tr.innerHTML=`
  <td><input type=radio name=pick value="${n.label}" ${checked?'checked':''}></td>
  <td class=mono>${n.id}</td>
  <td>${n.status}</td>
  <td>${n.city}</td>
  <td><span class=badge>${n.label}</span></td>`; tr.onclick=()=>{ tr.querySelector('input').checked=true; SELECTED=n.label; setSelectedLabel(SELECTED); $('#btn-connect').disabled=false; }; tbody.appendChild(tr); }); $('#count').textContent=nodes.length; }
async function refreshStatus(){ try{ const r=await fetch('/api/status'); const d=await r.json(); CURRENT=d.current||null; if(CURRENT&&CURRENT.label){ setSelectedLabel(CURRENT.label); } if(NODES.length){ render(NODES); } }catch(e){} }
async function fetchIp(){ try{ const r=await fetch('/api/external_ip'); const d=await r.json(); if(d.ok){ setExternalIp(d.ip); } }catch(e){} }
$('#btn-list').onclick=async()=>{ out.textContent='获取中…'; try{ const r=await fetch('/api/list'); const d=await r.json(); if(!d.ok){ out.textContent = '错误: '+(d.error||'ajiasu 不可用'); return;} NODES=d.nodes||[]; render(NODES); out.textContent='已获取节点列表'; }catch(e){ out.textContent='获取失败: '+e; }}
$('#btn-connect').onclick=async()=>{ if(!SELECTED) return; const protocol=$('#protocol').value; out.textContent=`启动连接: ${SELECTED} [${protocol}]...`;
  try{
    // 连接前先清理所有 connect 进程
    await fetch('/api/cleanup', {method:'POST'});
    const r=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:SELECTED,protocol})});
    const d=await r.json(); out.textContent = JSON.stringify(d,null,2); if(d.ok){ CURRENT={label:SELECTED,protocol:protocol,pid:d.pid}; setSelectedLabel(SELECTED); }
  }catch(e){ out.textContent='连接失败: '+e; }
  refreshStatus(); fetchIp(); };
$('#btn-disconnect').onclick=async()=>{ out.textContent='正在断开(清理所有 connect)…'; try{ const r=await fetch('/api/cleanup',{method:'POST'}); const d=await r.json(); out.textContent = JSON.stringify(d,null,2); CURRENT=null; }catch(e){ out.textContent='断开失败: '+e; } };
// 首次加载：默认协议 lwip（双保险）
document.querySelector('#protocol').value='lwip';
// 状态/IP 轮询
refreshStatus(); fetchIp(); setInterval(()=>{ refreshStatus(); fetchIp(); }, 10000);
</script>
"""
    return Response(html, mimetype="text/html; charset=utf-8")

# -------------------------- API --------------------------
@app.get("/api/list")
def api_list():
    ok, msg = _ensure_ajiasu_available(AJIASU_PATH)
    if not ok:
        return jsonify({"ok": False, "error": msg, "nodes": [], "summary": {}})
    proc = run_cmd([AJIASU_PATH, "list"], timeout=120)
    text = proc.stdout.decode("utf-8", errors="replace")
    parsed = parse_list_output(text)
    with _last_nodes_lock:
        global _last_nodes, _last_list_ts
        _last_nodes = parsed["nodes"]
        _last_list_ts = time.time()
    return jsonify({
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "nodes": parsed["nodes"],
        "summary": parsed["summary"],
    })

@app.get("/api/status")
def api_status():
    with _current_conn_lock:
        curr = _current_conn.copy() if _current_conn else None
    if curr and isinstance(curr.get("pid"), int):
        try:
            os.kill(int(curr["pid"]), 0)
            curr["alive"] = True
        except OSError:
            curr["alive"] = False
    return jsonify({"current": curr})

@app.post("/api/disconnect")
def api_disconnect():
    # 按你的要求：即便断开也要保持“始终有一个连接”
    result = kill_all_connects("manual")
    heal = _ensure_one_connection("post_disconnect")
    result["heal"] = heal
    return jsonify(result)

@app.post("/api/cleanup")
def api_cleanup():
    result = kill_all_connects("explicit_cleanup")
    heal = _ensure_one_connection("post_cleanup")
    result["heal"] = heal
    return jsonify(result)

@app.get("/api/external_ip")
def api_external_ip():
    return jsonify(get_external_ip())

@app.post("/api/connect")
def api_connect():
    global _current_conn
    data = request.get_json(silent=True) or {}
    label = (data.get("label") or "").strip()
    protocol = (data.get("protocol") or "lwip\n").strip().lower()  # 默认 lwip
    if not label:
        return jsonify({"ok": False, "error": "label is required"}), 400
    if protocol not in ALLOWED_PROTOCOLS:
        return jsonify({"ok": False, "error": f"protocol must be one of {sorted(ALLOWED_PROTOCOLS)}"}), 400
    with _last_nodes_lock:
        valid_labels = {n["label"] for n in _last_nodes}
    if label not in valid_labels:
        return jsonify({"ok": False, "error": "label not in latest list, refresh first"}), 400

    ok, msg = _ensure_ajiasu_available(AJIASU_PATH)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 500

    with _op_lock:
        # 连接前先杀掉所有 connect 进程
        _ = kill_all_connects("pre_connect")

        try:
            proc = subprocess.Popen(
                [AJIASU_PATH, "connect", label],
                cwd=str(BASE_DIR),
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                if proc.stdin:
                    proc.stdin.write((protocol + "").encode("utf-8", errors="ignore"))
                    proc.stdin.flush()
                    proc.stdin.close()
            except Exception:
                pass
            with _current_conn_lock:
                _current_conn = {"pid": proc.pid, "label": label, "protocol": protocol, "started_at": time.time()}
            # 强制只保留一个 connect（保留刚启动的）
            time.sleep(0.3)
            _enforce_single_connect(prefer_pid=proc.pid)
            return jsonify({"ok": True, "pid": proc.pid, "label": label, "protocol": protocol})
        except FileNotFoundError:
            return jsonify({"ok": False, "error": f"ajiasu not found at {AJIASU_PATH}"}), 500
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

# ------------------------ 自测 -------------------------
TEST_SAMPLE = """
vvn-5871-9238 ok         苏州 #33
vvn-5871-9239 ok         苏州 #34
vvn-5876-9348 ok         上海 #339
vvn-5907-9395 ok         成都 #146
vvn-5908-9394 ok         成都 #144
=====================================================
Web Site: https://www.91ajs.com
Login Result: OK
Membership: 爱加速会员
Expiration: Wed Sep 24 20:08:33 2025
=====================================================
""".strip()


def _compute_paths_for_test(fake_file: Optional[str], env_dir: Optional[str], env_bin: Optional[str]):
    if env_dir:
        base = Path(env_dir)
    elif fake_file is not None:
        base = Path(fake_file).resolve().parent
    else:
        base = Path.cwd()
    ajiasu_bin = env_bin or str(base / "ajiasu")
    return base, ajiasu_bin


def run_selftests() -> Dict[str, Any]:
    results = []

    def t(name, fn):
        try:
            fn(); results.append({"name": name, "passed": True})
        except AssertionError as e:
            results.append({"name": name, "passed": False, "error": str(e)})

    parsed = parse_list_output(TEST_SAMPLE)

    # 旧测试（保持不变）
    def _c1():
        assert len(parsed["nodes"]) == 5
    def _c2():
        n0 = parsed["nodes"][0]
        assert n0["id"] == "vvn-5871-9238" and n0["status"] == "ok" and n0["city"] == "苏州" and n0["num"] == 33 and n0["label"] == "苏州 #33"
    def _c3():
        n_last = parsed["nodes"][-1]
        assert n_last["city"] == "成都" and n_last["num"] == 144
    def _c4():
        s = parsed["summary"]
        assert s.get("website") == "https://www.91ajs.com" and s.get("login_result") == "OK" and s.get("membership") == "爱加速会员" and "2025" in s.get("expiration", "")

    t("parse_count", _c1)
    t("parse_first_node", _c2)
    t("parse_last_node", _c3)
    t("parse_summary", _c4)

    # 新增测试
    def _c5_protocols():
        for p in ["udp","tcp","lwip","proxy"]:
            assert p in ALLOWED_PROTOCOLS
    def _c6_env_overrides():
        base, binp = _compute_paths_for_test(fake_file=None, env_dir="/tmp/aj", env_bin="/opt/ajs")
        assert str(base) == "/tmp/aj" and binp == "/opt/ajs"
    def _c7_cwd_fallback():
        base, binp = _compute_paths_for_test(fake_file=None, env_dir=None, env_bin=None)
        assert base == Path.cwd() and (base / "ajiasu").name == Path(binp).name
    def _c8_missing_binary_error_message():
        ok, msg = _ensure_ajiasu_available("/surely/not/exist/ajiasu")
        assert not ok and ("未找到" in msg or "not found" in msg)
    def _c9_not_executable_message():
        ok, msg = _ensure_ajiasu_available("/")
        assert not ok and ("不可执行" in msg or "not executable" in msg or "未找到" in msg or "not found" in msg)
    def _c10_cmdline_parser():
        assert _is_connect_cmdline("/root/ajiasu connect 厦门 #31")
        assert _is_connect_cmdline("ajiasu connect 温州 #1")
        assert not _is_connect_cmdline("/root/ajiasu list")
        assert not _is_connect_cmdline("bash -lc 'ajiasu connect'")

    t("protocol_set_contains_all", _c5_protocols)
    t("env_override_paths", _c6_env_overrides)
    t("cwd_fallback_paths", _c7_cwd_fallback)
    t("missing_binary_message", _c8_missing_binary_error_message)
    t("not_executable_message_branch", _c9_not_executable_message)
    t("cmdline_parser_correct", _c10_cmdline_parser)

    return {"passed": all(r["passed"] for r in results), "cases": results}

@app.get("/api/selftest")
def api_selftest():
    return jsonify(run_selftests())

# ---------------------------------------------------------------------------
# 自动切换：每隔 24 小时切换到下一节点（基于最后一次 list 的顺序）
# ---------------------------------------------------------------------------

def _refresh_nodes() -> List[Dict[str, Any]]:
    ok, _ = _ensure_ajiasu_available(AJIASU_PATH)
    if not ok:
        return []
    proc = run_cmd([AJIASU_PATH, "list"], timeout=120)
    text = proc.stdout.decode("utf-8", errors="replace")
    parsed = parse_list_output(text)
    with _last_nodes_lock:
        global _last_nodes, _last_list_ts
        _last_nodes = parsed.get("nodes", [])
        _last_list_ts = time.time()
    return _last_nodes

def _choose_next_label() -> Optional[str]:
    nodes = _refresh_nodes() or []
    if not nodes:
        return None
    labels = [n["label"] for n in nodes]
    cur = None
    with _current_conn_lock:
        if _current_conn:
            cur = _current_conn.get("label")
    if cur in labels:
        i = labels.index(cur)
        return labels[(i + 1) % len(labels)]
    return labels[0]

def _autoswitch_once() -> Optional[Dict[str, Any]]:
    label = _choose_next_label()
    if not label:
        print("[autoswitch] skip: no label available")
        return None
    with _op_lock:
        print(f"[autoswitch] switching to {label}…")
        _ = kill_all_connects("autoswitch_pre")
        with _last_nodes_lock:
            valid = {n["label"] for n in _last_nodes}
        if label not in valid:
            print("[autoswitch] abort: label not in latest list")
            return None
        try:
            proc = subprocess.Popen(
                [AJIASU_PATH, "connect", label],
                cwd=str(BASE_DIR),
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                if proc.stdin:
                    proc.stdin.write(("lwip\n").encode("utf-8", errors="ignore"))
                    proc.stdin.flush()
                    proc.stdin.close()
            except Exception:
                pass
            with _current_conn_lock:
                global _current_conn
                _current_conn = {"pid": proc.pid, "label": label, "protocol": "lwip", "started_at": time.time()}
            time.sleep(0.3)
            _enforce_single_connect(prefer_pid=proc.pid)
            print(f"[autoswitch] done: pid={proc.pid}")
            return {"label": label, "pid": proc.pid}
        except Exception as e:
            print(f"[autoswitch] error: {e}")
            return None

def _autoswitch_loop():
    print(f"[autoswitch] enabled interval={AUTOSWITCH_INTERVAL_SEC}s")
    while True:
        try:
            time.sleep(AUTOSWITCH_INTERVAL_SEC)
            _autoswitch_once()
        except Exception as e:
            print(f"[autoswitch] loop error: {e}")
        except Exception:
            # 不中断
            pass

# ---------------------------------------------------------------------------
# 启动服务（含启动前清理）
# ---------------------------------------------------------------------------

def _choose_port(preferred: int) -> int:
    for p in [preferred] + list(range(preferred + 1, preferred + 11)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((APP_HOST, p))
                return p
        except OSError:
            continue
    return preferred


def _start_server():
    # 启动僵尸收割器
    threading.Thread(target=_reaper_loop, daemon=True).start()
    # 启动单实例强制器
    threading.Thread(target=_enforcer_loop, daemon=True).start()
    # 启动自动切换器（每 24 小时）
    if AUTOSWITCH_ENABLED:
        threading.Thread(target=_autoswitch_loop, daemon=True).start()

    # 启动前：清理所有 ajiasu connect 进程
    cleanup = kill_all_connects("startup")
    print(f"* startup cleanup: killed={cleanup['killed']} errors={cleanup['errors']}")
    # 确保启动后始终至少有一个连接
    _ensure_one_connection("startup")

    port = _choose_port(APP_PORT_DEFAULT)
    print(f"* BASE_DIR={BASE_DIR}")
    print(f"* AJIASU_PATH={AJIASU_PATH or 'NOT FOUND'}")
    print(f"* Listening on http://{APP_HOST}:{port}")
    try:
        app.run(host=APP_HOST, port=port, debug=False, use_reloader=False, threaded=True)
    except SystemExit:
        print("! Flask SystemExit(1). 检查端口绑定与 AJIASU_BIN 设置。")
    except SystemExit:
        print("! Flask SystemExit(1). 检查端口绑定与 AJIASU_BIN 设置。")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        print(json.dumps(run_selftests(), ensure_ascii=False, indent=2))
        sys.exit(0)
    _start_server()
