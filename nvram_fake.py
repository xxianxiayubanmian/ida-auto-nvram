# -*- coding: utf-8 -*-
"""
IDA 自动化 NVRAM 提取 + fake libnvram.c 生成脚本

用法：
  1. 在 IDA/IDA64 中打开固件里的目标 ELF/CGI/webserver 二进制并等待自动分析完成。
  2. File -> Script file... 选择本脚本，或命令行：
       ida64 -A -Sida_auto_nvram.py ./goahead
  3. 输出目录默认为：<input_binary_dir>/<input_name>_nvram_auto/

输出：
  - nvram_fake.c          可编译成 LD_PRELOAD 用 fake libnvram
  - nvram.ini             提取/推断出的 key=value
  - nvram_findings.json   结构化证据
  - nvram_report.txt      可读分析报告
  - nvram_all_kv.ini      二进制内所有疑似 key=value，低置信度参考

设计目标：
  - 仅依赖 IDAPython 静态分析，不要求 Hex-Rays。
  - 自动适配常见路由固件：MIPS/ARM/AArch64/x86/PPC。
  - 自动识别 nvram_get/nvram_bufget/nvram_set/nvram_getall、acosNvramConfig_*、
    bcm_nvram_*、tcapi_get/set、uci_get/set、xmldbc_get/set 等常见 NVRAM/配置 API。
  - 通过 API 调用点反向追踪参数寄存器/栈参数，提取 NVRAM key/value。
  - 同时解析字符串里的 shell 命令：nvram_get 2860 lan_ipaddr、nvram get key、
    nvram set key=value 等。

兼容性：
  - 主要使用用户指定的模块：idautils, ida_segment, ida_bytes, idaapi, os。
  - 额外 IDA 模块均为可选导入；缺失时降级。
"""
from __future__ import print_function

import os
import re
import json
import time
import codecs

import idautils
import ida_segment
import ida_bytes
import idaapi

try:
    import idc
except Exception:
    idc = None

try:
    import ida_funcs
except Exception:
    ida_funcs = None

try:
    import ida_name
except Exception:
    ida_name = None

try:
    import ida_nalt
except Exception:
    ida_nalt = None

try:
    import ida_auto
except Exception:
    ida_auto = None


# --------------------------- 可调配置 ---------------------------

BACKTRACK_INSNS = 90
MIN_OUTPUT_CONFIDENCE = 35
INCLUDE_LOW_CONFIDENCE_KV_IN_MAIN_INI = False
MAX_STRING_LEN = 4096
MAX_KV_VALUE_LEN = 512

# 遇到这些 API 时会主动反向追踪参数。
API_EXACT = {
    # Broadcom / common
    "nvram_get": "get",
    "nvram_safe_get": "get",
    "nvram_bufget": "get",
    "nvram_nget": "get",
    "nvram_default_get": "get",
    "bcm_nvram_get": "get",
    "wlcsm_nvram_get": "get",
    "nvram_set": "set",
    "nvram_bufset": "set",
    "nvram_unset": "unset",
    "nvram_commit": "misc",
    "nvram_init": "misc",
    "nvram_getall": "getall",
    "nvram_match": "match",
    "nvram_invmatch": "match",
    # Netgear / acos
    "acosnvramconfig_get": "get",
    "acosnvramconfig_set": "set",
    "acosnvramconfig_match": "match",
    "acosnvramconfig_invmatch": "match",
    # TrendMicro/other wrappers
    "dni_nvram_get": "get",
    "dni_nvram_set": "set",
    "envram_get": "get",
    "envram_set": "set",
    # OpenWrt/UCI-like wrappers sometimes used by vendors
    "uci_get": "get",
    "uci_set": "set",
    "uci_safe_get": "get",
    # Realtek/Ralink/Trendchip
    "tcapi_get": "get",
    "tcapi_set": "set",
    "tcapi_commit": "misc",
    "tcapi_save": "misc",
    "cfg_get": "get",
    "cfg_set": "set",
    "config_get": "get",
    "config_set": "set",
    # D-Link / XML DB style
    "xmldbc_get": "get",
    "xmldbc_set": "set",
    "query": "get",
    "set": "set",
}

# 对已发现 key 进行值推断；仅在 key 已被证据发现时使用。
BUILTIN_DEFAULTS = {
    "lan_ipaddr": "192.168.10.200",
    "lan_ip": "192.168.10.200",
    "lan_netmask": "255.255.255.0",
    "lan_gateway": "192.168.10.200",
    "dhcp_start": "192.168.0.100",
    "dhcp_end": "192.168.0.200",
    "wanConnectionMode": "DHCP",
    "wan_connection_mode": "DHCP",
    "wan_proto": "dhcp",
    "wan_mtu": "1500",
    "wan_speed": "0",
    "Login": "admin",
    "login": "admin",
    "username": "admin",
    "user": "admin",
    "http_username": "admin",
    "admin_username": "admin",
    "Password": "admin",
    "password": "admin",
    "passwd": "admin",
    "http_passwd": "admin",
    "http_password": "admin",
    "admin_password": "admin",
    "BssidNum": "1",
    "WdsEnable": "0",
    "OperationMode": "1",
    "TZ": "UCT_0",
    "Language": "en",
    "natEnabled": "1",
    "telnetEnabled": "1",
    "AuthMode": "OPEN",
}


# --------------------------- 兼容工具函数 ---------------------------

BADADDR = getattr(idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)

try:
    text_type = unicode  # noqa: F821  # Python 2 under old IDA
except NameError:
    text_type = str


def log(msg):
    print("[auto-nvram] {0}".format(msg))


def to_text(x):
    if x is None:
        return None
    if isinstance(x, text_type):
        return x
    try:
        if isinstance(x, bytearray):
            x = bytes(x)
        if isinstance(x, bytes):
            for enc in ("utf-8", "latin-1"):
                try:
                    return x.decode(enc, "ignore")
                except Exception:
                    pass
    except Exception:
        pass
    try:
        return str(x)
    except Exception:
        return repr(x)


def write_text(path, data):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with codecs.open(path, "w", "utf-8") as fp:
        fp.write(data)


def json_dump(path, obj):
    write_text(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def get_inf_procname():
    try:
        inf = idaapi.get_inf_structure()
        for attr in ("procName", "procname", "proc_name"):
            if hasattr(inf, attr):
                v = getattr(inf, attr)
                if callable(v):
                    v = v()
                if v:
                    return to_text(v).lower()
    except Exception:
        pass
    try:
        if idc and hasattr(idc, "get_inf_attr") and hasattr(idc, "INF_PROCNAME"):
            return to_text(idc.get_inf_attr(idc.INF_PROCNAME)).lower()
    except Exception:
        pass
    return ""


def get_input_path():
    for f in (
        lambda: idaapi.get_input_file_path(),
        lambda: idc.get_input_file_path() if idc else None,
    ):
        try:
            v = f()
            if v:
                return to_text(v)
        except Exception:
            pass
    try:
        name = idaapi.get_root_filename()
    except Exception:
        name = "ida_input"
    return os.path.abspath(name)


def get_root_filename():
    try:
        return to_text(idaapi.get_root_filename())
    except Exception:
        p = get_input_path()
        return os.path.basename(p)


def get_func(ea):
    if ida_funcs:
        try:
            return ida_funcs.get_func(ea)
        except Exception:
            pass
    try:
        return idaapi.get_func(ea)
    except Exception:
        return None


def get_func_name(ea):
    try:
        if idc:
            n = idc.get_func_name(ea)
            if n:
                return to_text(n)
    except Exception:
        pass
    f = get_func(ea)
    if f:
        try:
            if idc:
                return to_text(idc.get_func_name(f.start_ea))
        except Exception:
            pass
    return ""


def get_name(ea):
    try:
        if ida_name:
            n = ida_name.get_name(ea)
            if n:
                return to_text(n)
    except Exception:
        pass
    try:
        if idc:
            n = idc.get_name(ea)
            if n:
                return to_text(n)
    except Exception:
        pass
    return ""


def is_code_ea(ea):
    try:
        return ida_bytes.is_code(ida_bytes.get_full_flags(ea))
    except Exception:
        pass
    try:
        if idc:
            return idc.is_code(idc.get_full_flags(ea))
    except Exception:
        pass
    return False


def next_head(ea, maxea):
    try:
        if idc:
            return idc.next_head(ea, maxea)
    except Exception:
        pass
    try:
        return idaapi.next_head(ea, maxea)
    except Exception:
        return BADADDR


def prev_head(ea, minea):
    try:
        if idc:
            return idc.prev_head(ea, minea)
    except Exception:
        pass
    try:
        return idaapi.prev_head(ea, minea)
    except Exception:
        return BADADDR


def print_operand(ea, n):
    try:
        if idc:
            return to_text(idc.print_operand(ea, n))
    except Exception:
        pass
    try:
        return to_text(idaapi.print_operand(ea, n))
    except Exception:
        return ""


def print_mnem(ea):
    try:
        if idc:
            return to_text(idc.print_insn_mnem(ea)).lower()
    except Exception:
        pass
    try:
        return to_text(idaapi.print_insn_mnem(ea)).lower()
    except Exception:
        return ""


def operand_value(ea, n):
    try:
        if idc:
            return idc.get_operand_value(ea, n)
    except Exception:
        pass
    return BADADDR


def seg_name(ea):
    try:
        if idc:
            return to_text(idc.get_segm_name(ea))
    except Exception:
        pass
    try:
        s = ida_segment.getseg(ea)
        if not s:
            return ""
        return to_text(ida_segment.get_segm_name(s))
    except Exception:
        return ""


def is_mapped(ea):
    try:
        return ida_segment.getseg(ea) is not None
    except Exception:
        return False


def ea_hex(ea):
    try:
        if ea is None or ea == BADADDR:
            return ""
        return "0x{0:x}".format(int(ea))
    except Exception:
        return str(ea)


def clean_str(s, max_len=MAX_STRING_LEN):
    s = to_text(s)
    if s is None:
        return None
    s = s.replace("\x00", "")
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    if len(s) > max_len:
        s = s[:max_len]
    return s


def c_escape(s):
    s = to_text(s) or ""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\"":
            out.append("\\\"")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 32 <= o <= 126:
            out.append(ch)
        else:
            out.append("\\x{0:02x}".format(o & 0xff))
    return "".join(out)


def ini_escape_value(s):
    s = to_text(s) or ""
    s = s.replace("\x00", "")
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    return s


# --------------------------- 字符串收集 ---------------------------

STRING_BY_EA = {}
ALL_STRINGS = []


def try_get_strlit(ea):
    if ea is None or ea == BADADDR or not is_mapped(ea):
        return None
    if ea in STRING_BY_EA:
        return STRING_BY_EA[ea]
    raw = None
    try:
        if idc and hasattr(idc, "get_strlit_contents"):
            raw = idc.get_strlit_contents(ea, -1, 0)
    except Exception:
        raw = None
    if raw is None:
        try:
            raw = ida_bytes.get_strlit_contents(ea, -1, 0)
        except Exception:
            raw = None
    s = clean_str(raw)
    if s:
        # 粗略排除非文本
        printable = 0
        for ch in s:
            if 32 <= ord(ch) <= 126 or ch in "\t\\r\\n":
                printable += 1
        if float(printable) / max(1, len(s)) >= 0.80:
            STRING_BY_EA[ea] = s
            return s
    return None


def collect_strings():
    global STRING_BY_EA, ALL_STRINGS
    STRING_BY_EA = {}
    ALL_STRINGS = []
    ss = idautils.Strings()
    try:
        if ida_nalt:
            strtypes = [ida_nalt.STRTYPE_C]
            try:
                strtypes.append(ida_nalt.STRTYPE_C_16)
            except Exception:
                pass
            ss.setup(strtypes=strtypes, minlen=1, only_7bit=True)
        else:
            ss.setup(minlen=1)
    except Exception:
        try:
            ss.setup(minlen=1)
        except Exception:
            pass
    for x in ss:
        try:
            ea = int(x.ea)
        except Exception:
            continue
        s = clean_str(str(x))
        if not s:
            continue
        STRING_BY_EA[ea] = s
        ALL_STRINGS.append({"ea": ea, "s": s, "len": len(s), "seg": seg_name(ea)})
    log("collected {0} strings".format(len(ALL_STRINGS)))


def data_ref_strings_from_insn(ea):
    out = []
    seen = set()
    try:
        refs = list(idautils.DataRefsFrom(ea))
    except Exception:
        refs = []
    for r in refs:
        if r in seen:
            continue
        seen.add(r)
        s = try_get_strlit(r)
        if s:
            out.append((r, s))
    # 某些架构/IDA 版本不会建立 DataRef，补充检查 operand immediate。
    for i in range(0, 6):
        try:
            v = operand_value(ea, i)
        except Exception:
            continue
        if not v or v == BADADDR or v in seen:
            continue
        if not is_mapped(v):
            continue
        s = try_get_strlit(v)
        if s:
            seen.add(v)
            out.append((v, s))
    return out


# --------------------------- key/value 判定 ---------------------------

KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,95}$")
KV_RE_TEXT = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.:-]{0,95})=(.{0,%d})$" % MAX_KV_VALUE_LEN)

COMMON_KEY_PREFIXES = (
    "lan_", "wan_", "wl", "wifi", "wlan", "ppp", "pppoe", "dhcp", "dns",
    "http_", "https_", "admin", "user", "login", "pass", "passwd", "password",
    "nat", "upnp", "dmz", "qos", "ddns", "vpn", "pptp", "l2tp", "telnet",
    "ssh", "remote", "firewall", "filter", "mac", "ssid", "wpa", "wep",
    "wps", "auth", "radio", "channel", "bssid", "operation", "language",
)

COMMON_KEY_SUBSTRINGS = (
    "ipaddr", "netmask", "gateway", "mtu", "mac", "ssid", "password",
    "passwd", "psk", "wep", "wpa", "enable", "enabled", "mode", "proto",
    "dns", "dhcp", "login", "user", "admin", "timezone", "language",
)

KEY_BLACKLIST = set([
    "GET", "POST", "HEAD", "HTTP", "HTTPS", "html", "body", "script",
    "text", "plain", "admin",  # 单独 admin 更像值；admin_xxx 会保留
    "root", "true", "false", "null", "name", "method", "group", "prot",
    "disable", "enable", "r", "w", "rb", "wb", "GET", "PUT", "DELETE",
])


def is_key_candidate(s, strict=False):
    s = to_text(s)
    if not s:
        return False
    s = s.strip()
    if len(s) < 2 or len(s) > 96:
        # TZ 是少数常见短 key。
        if s != "TZ":
            return False
    if s in KEY_BLACKLIST:
        return False
    if not KEY_RE.match(s):
        return False
    # 排除明显 IP/MAC/纯数字/扩展名/格式值
    if re.match(r"^\d+$", s):
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
        return False
    if re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s):
        return False
    if s.startswith(".") or s.endswith(".so") or s.endswith(".html") or s.endswith(".asp"):
        return False
    if strict and not is_nvramish_key(s):
        return False
    return True


def is_nvramish_key(k):
    lk = (to_text(k) or "").lower()
    if lk == "tz":
        return True
    for p in COMMON_KEY_PREFIXES:
        if lk.startswith(p):
            return True
    for sub in COMMON_KEY_SUBSTRINGS:
        if sub in lk:
            return True
    if "_" in lk:
        return True
    return False


def is_sane_value(v):
    if v is None:
        return False
    v = to_text(v)
    if len(v) > MAX_KV_VALUE_LEN:
        return False
    bad = 0
    for ch in v:
        o = ord(ch)
        if o == 0:
            bad += 1
        elif o < 9:
            bad += 1
    return bad == 0



def forced_default_value(k):
    """Project policy: credential-like keys always admin; LAN IP keys always 192.168.10.200."""
    lk = (to_text(k) or "").strip().lower()
    if not lk:
        return None
    cred_terms = (
        "login", "password", "passwd", "username", "user_name",
        "admin_password", "admin_pass", "pwd", "passphrase"
    )
    if lk == "user" or lk.endswith("_user") or lk.endswith("user"):
        return "admin"
    for term in cred_terms:
        if term in lk:
            return "admin"
    if lk in ("lan_ipaddr", "lan_ip", "lan_ip_addr", "lanip", "lan_ipaddress"):
        return "192.168.10.200"
    if lk.startswith("lan_") and ("ipaddr" in lk or lk.endswith("_ip") or lk.endswith("ip")):
        return "192.168.10.200"
    return None

def heuristic_default(k):
    forced = forced_default_value(k)
    if forced is not None:
        return forced
    if k in BUILTIN_DEFAULTS:
        return BUILTIN_DEFAULTS[k]
    lk = k.lower()
    # case-insensitive builtin
    for bk, bv in BUILTIN_DEFAULTS.items():
        if bk.lower() == lk:
            return bv
    if "netmask" in lk or lk.endswith("_mask"):
        return "255.255.255.0"
    if "ipaddr" in lk or lk.endswith("_ip") or lk.endswith("ip"):
        if "wan" in lk:
            return "0.0.0.0"
        if "lan" in lk:
            return "192.168.10.200"
        return "192.168.10.200"
    if "gateway" in lk or lk.endswith("_gw"):
        if "lan" in lk:
            return "192.168.10.200"
        return "192.168.10.200"
    if "dns" in lk:
        return "8.8.8.8"
    if "mtu" in lk:
        return "1500"
    if "mac" in lk or "bssid" in lk:
        return "00:11:22:33:44:55"
    if "ssid" in lk:
        return "test"
    if "password" in lk or "passwd" in lk or lk.endswith("pass") or "psk" in lk:
        return "admin"
    if "login" in lk or "username" in lk or lk.endswith("user"):
        return "admin"
    if "connectionmode" in lk or lk.endswith("_proto") or "wan_proto" in lk:
        return "DHCP"
    if "language" in lk:
        return "en"
    if lk in ("tz", "timezone"):
        return "UCT_0"
    if "enable" in lk or "enabled" in lk:
        if "nat" in lk or "telnet" in lk:
            return "1"
        return "0"
    if "mode" in lk or "num" in lk or "count" in lk or "timeout" in lk:
        return "0"
    return ""


# --------------------------- API 识别 ---------------------------

def normalize_api_name(name):
    n = to_text(name) or ""
    n = n.strip()
    n = n.split("@")[0]
    for p in ("j_", "__imp_", "imp_", "."):
        if n.startswith(p):
            n = n[len(p):]
    # IDA/MIPS 常出现 nvram_get_ptr / _nvram_get
    if n.startswith("_"):
        n = n[1:]
    if n.endswith("_ptr"):
        n = n[:-4]
    if n.endswith("_plt"):
        n = n[:-4]
    n = n.replace(".", "_")
    return n.lower()


def classify_api(name):
    n = normalize_api_name(name)
    if n in API_EXACT:
        return API_EXACT[n]
    # 泛化：名字里带 nvram/cfg/config/uci/tcapi/xmldbc 且有 get/set。
    family = (
        "nvram" in n or "envram" in n or n.startswith("cfg_") or
        n.startswith("config_") or n.startswith("uci_") or n.startswith("tcapi_") or
        n.startswith("xmldbc_") or "acosnvramconfig" in n
    )
    if not family:
        return None
    if "getall" in n:
        return "getall"
    if "safe_get" in n or "bufget" in n or n.endswith("_get") or n.endswith("get"):
        return "get"
    if "bufset" in n or n.endswith("_set") or n.endswith("set"):
        return "set"
    if "unset" in n:
        return "unset"
    if "match" in n:
        return "match"
    if "commit" in n or "init" in n or "save" in n:
        return "misc"
    return None


def collect_api_symbols():
    apis = {}

    def add_api(ea, name, via):
        kind = classify_api(name)
        if not kind:
            return
        if ea is None or ea == BADADDR:
            return
        old = apis.get(int(ea))
        if old:
            old["names"].add(name)
            old["via"].add(via)
        else:
            apis[int(ea)] = {
                "ea": int(ea),
                "name": name,
                "norm": normalize_api_name(name),
                "kind": kind,
                "names": set([name]),
                "via": set([via]),
            }

    # 普通命名符号
    try:
        for ea, name in idautils.Names():
            add_api(ea, to_text(name), "Names")
    except Exception:
        pass

    # Import table
    if ida_nalt:
        try:
            qty = ida_nalt.get_import_module_qty()
            for i in range(qty):
                def cb(ea, name, ord_):
                    add_api(ea, to_text(name), "Imports")
                    return True
                ida_nalt.enum_import_names(i, cb)
        except Exception:
            pass

    log("found {0} NVRAM/config API symbols".format(len(apis)))
    return apis


CALL_MNEMS = set([
    "call", "calls", "bl", "blr", "blx", "jal", "jalr", "bal", "bsr",
    "jsr", "callr", "brasl",
])


def find_call_sites_for_api(api_ea):
    out = []
    seen = set()

    def resolve_call_ea(ref_ea):
        """把 import/GOT 加载指令归一化到后面的真实 call/jalr/bl 指令。"""
        if ref_ea is None or ref_ea == BADADDR:
            return ref_ea
        ref_ea = int(ref_ea)
        if print_mnem(ref_ea) in CALL_MNEMS:
            return ref_ea
        f = get_func(ref_ea)
        end = int(f.end_ea) if f else ref_ea + 0x80
        ea = ref_ea
        for _ in range(0, 24):
            ea = next_head(ea, end)
            if ea == BADADDR or ea >= end:
                break
            m = print_mnem(ea)
            if m in CALL_MNEMS:
                return int(ea)
            # 遇到明显跳转/返回，说明这条 xref 不属于直接调用准备区。
            if m in ("j", "jr", "b", "bra", "ret", "retn", "return") or m.startswith("b"):
                break
        return ref_ea

    def add(ea, why):
        if ea is None or ea == BADADDR:
            return
        ea = int(resolve_call_ea(ea))
        if ea in seen:
            return
        if is_code_ea(ea):
            seen.add(ea)
            out.append({"ea": ea, "why": why})

    try:
        for r in idautils.CodeRefsTo(api_ea, 0):
            add(r, "CodeRefsTo0")
        for r in idautils.CodeRefsTo(api_ea, 1):
            add(r, "CodeRefsTo1")
    except Exception:
        pass

    try:
        for xr in idautils.XrefsTo(api_ea, 0):
            frm = int(xr.frm)
            if is_code_ea(frm):
                add(frm, "XrefsTo-code")
            else:
                # import/GOT 指针的二级 xref
                try:
                    for xr2 in idautils.XrefsTo(frm, 0):
                        add(int(xr2.frm), "XrefsTo-data")
                except Exception:
                    pass
    except Exception:
        pass

    # 某些 IDA 不把间接 jalr/call 建成到 import 的 code ref；
    # 这里不全量扫所有 call，避免误报，后续同函数字符串策略补充。
    return out


# --------------------------- 参数反向追踪 ---------------------------

def norm_reg_token(s):
    s = (to_text(s) or "").lower().strip()
    s = s.replace("$", "")
    s = s.replace("{", "").replace("}", "")
    s = s.replace("[", "").replace("]", "")
    s = s.replace("(", "").replace(")", "")
    s = s.replace(",", " ")
    s = s.split()
    if not s:
        return ""
    return s[0]


def operand_mentions(op, aliases):
    opn = norm_reg_token(op)
    if opn in aliases:
        return True
    # print_operand 对 [r0,#4] 等可能保留完整文本，做一次宽松匹配。
    low = (to_text(op) or "").lower().replace("$", "")
    for a in aliases:
        if re.search(r"(^|[^a-z0-9_]){0}([^a-z0-9_]|$)".format(re.escape(a)), low):
            return True
    return False


def get_arg_reg_aliases():
    p = get_inf_procname()
    if "mips" in p:
        return [
            set(["a0", "r4"]),
            set(["a1", "r5"]),
            set(["a2", "r6"]),
            set(["a3", "r7"]),
        ]
    if "arm" in p and "64" not in p and "aarch64" not in p:
        return [
            set(["r0"]),
            set(["r1"]),
            set(["r2"]),
            set(["r3"]),
        ]
    if "arm64" in p or "aarch64" in p:
        return [
            set(["x0", "w0"]),
            set(["x1", "w1"]),
            set(["x2", "w2"]),
            set(["x3", "w3"]),
            set(["x4", "w4"]),
            set(["x5", "w5"]),
        ]
    if "ppc" in p or "powerpc" in p:
        return [
            set(["r3"]),
            set(["r4"]),
            set(["r5"]),
            set(["r6"]),
            set(["r7"]),
        ]
    if "386" in p or "metapc" in p or "x86" in p:
        # 同时兼容 SysV x64 与 Win64；x86 主要依赖 push 栈参数。
        return [
            set(["rdi", "edi", "di", "rcx", "ecx", "cx"]),
            set(["rsi", "esi", "si", "rdx", "edx", "dx"]),
            set(["rdx", "edx", "dx", "r8", "r8d"]),
            set(["rcx", "ecx", "cx", "r9", "r9d"]),
        ]
    # 泛化兜底
    return [
        set(["a0", "r0", "x0", "w0", "rdi", "rcx"]),
        set(["a1", "r1", "x1", "w1", "rsi", "rdx"]),
        set(["a2", "r2", "x2", "w2", "rdx", "r8"]),
        set(["a3", "r3", "x3", "w3", "rcx", "r9"]),
    ]


def imm_from_operand_text(op):
    op = (to_text(op) or "").strip()
    if not op:
        return None
    # 去掉 #、$、h 后缀等常见格式
    op = op.replace("#", "").replace("$", "")
    if op.endswith("h") and re.match(r"^[0-9a-fA-F]+h$", op):
        try:
            return int(op[:-1], 16)
        except Exception:
            return None
    try:
        if op.lower().startswith("0x"):
            return int(op, 16)
        if re.match(r"^-?\d+$", op):
            return int(op, 10)
    except Exception:
        return None
    return None


def extract_call_args(call_ea):
    """
    返回：
      {
        "args": {idx: {"kind":"str"/"imm", "value":..., "ea":...}},
        "near_strings": [{"ea":..., "string":...}, ...],
      }
    """
    f = get_func(call_ea)
    if f:
        start = int(f.start_ea)
    else:
        start = max(0, int(call_ea) - 0x400)

    arg_aliases = get_arg_reg_aliases()
    tracked = {}
    for i, aliases in enumerate(arg_aliases):
        tracked[i] = set(aliases)

    args = {}
    near = []
    push_args = []

    ea = prev_head(call_ea, start)
    count = 0
    while ea != BADADDR and ea >= start and count < BACKTRACK_INSNS:
        count += 1
        mnem = print_mnem(ea)
        op0 = print_operand(ea, 0)
        op1 = print_operand(ea, 1)
        dstrs = data_ref_strings_from_insn(ea)
        for sea, s in dstrs:
            near.append({"ea": sea, "string": s, "insn": ea})

        # x86/cdecl 栈参数：从 call 往前遇到的第一个 push 是 arg0。
        if mnem.startswith("push"):
            if dstrs:
                push_args.append({"kind": "str", "value": dstrs[0][1], "ea": dstrs[0][0], "insn": ea})
            else:
                imm = imm_from_operand_text(op0)
                if imm is not None and abs(imm) < 0x100000:
                    push_args.append({"kind": "imm", "value": str(imm), "ea": ea, "insn": ea})

        # 寄存器参数：如果本指令写目标参数寄存器，并引用字符串，则认为装载了参数。
        for idx, aliases in tracked.items():
            if idx in args:
                continue
            if operand_mentions(op0, aliases):
                if dstrs:
                    args[idx] = {"kind": "str", "value": dstrs[0][1], "ea": dstrs[0][0], "insn": ea}
                    continue
                # li/mov reg, imm
                imm = imm_from_operand_text(op1)
                if imm is not None and abs(imm) < 0x100000:
                    args[idx] = {"kind": "imm", "value": str(imm), "ea": ea, "insn": ea}
                    continue
                # move reg, other_reg：反向追踪 other_reg。
                src = norm_reg_token(op1)
                if src and re.match(r"^[a-z][a-z0-9]*$", src):
                    tracked[idx].add(src)

        # 到上一处调用通常意味着越过了当前调用参数准备区，停止。
        if count > 4 and mnem in CALL_MNEMS:
            break
        ea = prev_head(ea, start)

    # push 参数只填充还没识别到的寄存器参数。
    for i, v in enumerate(push_args):
        if i not in args:
            args[i] = v

    # near 去重，保留顺序
    seen = set()
    near2 = []
    for item in near:
        key = (item.get("ea"), item.get("string"))
        if key in seen:
            continue
        seen.add(key)
        near2.append(item)
    return {"args": args, "near_strings": near2}


# --------------------------- 发现数据库 ---------------------------

class Findings(object):
    def __init__(self):
        self.keys = {}
        self.all_kv = {}
        self.api_symbols = []
        self.api_calls = []
        self.shell_commands = []
        self.stats = {}

    def add_key(self, key, value=None, source="", ea=None, api="", confidence=50, note=""):
        key = to_text(key)
        if key is None:
            return False
        key = key.strip()
        if not is_key_candidate(key):
            return False
        if value is not None:
            value = clean_str(value, MAX_KV_VALUE_LEN)
            if not is_sane_value(value):
                value = None
        ent = self.keys.get(key)
        if not ent:
            ent = {
                "key": key,
                "score": 0,
                "values": [],
                "evidence": [],
            }
            self.keys[key] = ent
        ent["score"] = max(ent["score"], int(confidence))
        ev = {
            "source": source,
            "ea": ea_hex(ea),
            "api": api or "",
            "confidence": int(confidence),
            "note": note or "",
        }
        if value is not None:
            ev["value"] = value
            ent["values"].append({
                "value": value,
                "confidence": int(confidence),
                "source": source,
                "ea": ea_hex(ea),
            })
        ent["evidence"].append(ev)
        return True

    def add_all_kv(self, key, value, source, ea=None, confidence=20):
        if not key:
            return
        key = key.strip()
        if not is_key_candidate(key):
            return
        if value is None:
            value = ""
        value = clean_str(value, MAX_KV_VALUE_LEN)
        if not is_sane_value(value):
            return
        old = self.all_kv.get(key)
        if not old or confidence > old.get("confidence", 0):
            self.all_kv[key] = {
                "key": key,
                "value": value,
                "source": source,
                "ea": ea_hex(ea),
                "confidence": int(confidence),
            }
        # 对 nvramish 的 key 或已发现 key，可作为低置信度值。
        if is_nvramish_key(key):
            self.add_key(key, value, source, ea, "", max(confidence, 30), "key=value blob")

    def best_value(self, key):
        forced = forced_default_value(key)
        if forced is not None:
            return forced, "forced-policy"
        ent = self.keys[key]
        best = None
        for item in ent.get("values", []):
            if item.get("value") is None:
                continue
            if best is None or item.get("confidence", 0) > best.get("confidence", 0):
                best = item
        if best and best.get("value") is not None:
            return best.get("value"), best.get("source", "")
        return heuristic_default(key), "heuristic"

    def output_keys(self):
        out = []
        for k, ent in self.keys.items():
            score = ent.get("score", 0)
            if score >= MIN_OUTPUT_CONFIDENCE:
                out.append(k)
                continue
            if INCLUDE_LOW_CONFIDENCE_KV_IN_MAIN_INI and is_nvramish_key(k):
                out.append(k)
        out.sort(key=lambda x: x.lower())
        return out

    def as_jsonable(self):
        keys = {}
        for k in sorted(self.keys.keys(), key=lambda x: x.lower()):
            ent = self.keys[k]
            val, val_src = self.best_value(k)
            keys[k] = {
                "score": ent.get("score", 0),
                "chosen_value": val,
                "chosen_value_source": val_src,
                "values": ent.get("values", []),
                "evidence": ent.get("evidence", []),
            }
        return {
            "stats": self.stats,
            "keys": keys,
            "all_kv": self.all_kv,
            "api_symbols": self.api_symbols,
            "api_calls": self.api_calls,
            "shell_commands": self.shell_commands,
        }


# --------------------------- 主分析逻辑 ---------------------------

def process_api_calls(db, apis):
    funcs_with_api = set()
    total_calls = 0

    for ea, api in apis.items():
        api_rec = {
            "ea": ea_hex(ea),
            "name": api.get("name", ""),
            "norm": api.get("norm", ""),
            "kind": api.get("kind", ""),
            "names": sorted(list(api.get("names", []))),
            "via": sorted(list(api.get("via", []))),
        }
        db.api_symbols.append(api_rec)

        callsites = find_call_sites_for_api(ea)
        for cs in callsites:
            call_ea = cs["ea"]
            total_calls += 1
            f = get_func(call_ea)
            if f:
                funcs_with_api.add(int(f.start_ea))
            arginfo = extract_call_args(call_ea)
            args = arginfo["args"]
            kind = api.get("kind", "")
            aname = api.get("norm", api.get("name", ""))

            rec_args = {}
            for idx, val in args.items():
                rec_args[str(idx)] = {
                    "kind": val.get("kind"),
                    "value": val.get("value"),
                    "ea": ea_hex(val.get("ea")),
                    "insn": ea_hex(val.get("insn")),
                }
            db.api_calls.append({
                "call_ea": ea_hex(call_ea),
                "func": get_func_name(call_ea),
                "api": aname,
                "kind": kind,
                "xref": cs.get("why", ""),
                "args": rec_args,
                "near_strings": [
                    {"ea": ea_hex(x.get("ea")), "s": x.get("string"), "insn": ea_hex(x.get("insn"))}
                    for x in arginfo.get("near_strings", [])[:20]
                ],
            })

            def arg_str(i):
                v = args.get(i)
                if v and v.get("kind") == "str":
                    return v.get("value")
                return None

            if kind == "get":
                # Broadcom: nvram_get(key) -> arg0
                # Ralink/D-Link: nvram_get(index, key) -> arg1
                added = False
                for idx, conf in ((0, 80), (1, 85), (2, 65)):
                    s = arg_str(idx)
                    if s and is_key_candidate(s):
                        note = "api arg{0}".format(idx)
                        if db.add_key(s, None, "api-get-arg{0}".format(idx), call_ea, aname, conf, note):
                            added = True
                if not added:
                    for item in arginfo.get("near_strings", []):
                        s = item.get("string")
                        if is_key_candidate(s, strict=True):
                            db.add_key(s, None, "api-get-near-string", item.get("ea"), aname, 45, "near call {0}".format(ea_hex(call_ea)))

            elif kind == "set":
                # Broadcom: nvram_set(key, value) -> arg0,arg1
                # Ralink/D-Link: nvram_set(index, key, value) -> arg1,arg2
                pairs = ((0, 1, 82), (1, 2, 87), (0, 2, 60))
                added = False
                for kidx, vidx, conf in pairs:
                    k = arg_str(kidx)
                    v = arg_str(vidx)
                    if k and is_key_candidate(k):
                        db.add_key(k, v, "api-set-arg{0}".format(kidx), call_ea, aname, conf, "value arg{0}".format(vidx))
                        added = True
                if not added:
                    for item in arginfo.get("near_strings", []):
                        s = item.get("string")
                        if is_key_candidate(s, strict=True):
                            db.add_key(s, None, "api-set-near-string", item.get("ea"), aname, 45, "near call {0}".format(ea_hex(call_ea)))

            elif kind in ("match", "unset"):
                for idx, conf in ((0, 70), (1, 75)):
                    s = arg_str(idx)
                    if s and is_key_candidate(s):
                        db.add_key(s, None, "api-{0}-arg{1}".format(kind, idx), call_ea, aname, conf, "")

            elif kind == "getall":
                # getall 本身不提供 key，但说明程序依赖 NVRAM。
                pass

    # 兜底：包含 nvram/config API 调用的函数中，所有 nvramish 字符串作为低置信度 key。
    for fs in sorted(funcs_with_api):
        f = get_func(fs)
        if not f:
            continue
        heads = []
        try:
            heads = list(idautils.Heads(int(f.start_ea), int(f.end_ea)))
        except Exception:
            continue
        for h in heads:
            for sea, s in data_ref_strings_from_insn(h):
                if is_key_candidate(s, strict=True):
                    db.add_key(s, None, "same-func-with-nvram-api", sea, "", 35, get_func_name(fs))

    log("processed {0} API callsites, {1} functions with API".format(total_calls, len(funcs_with_api)))


SHELL_PATTERNS = [
    # nvram_get 2860 lan_ipaddr / nvram_get lan_ipaddr
    re.compile(r"(?:^|[;&|`$() \t])nvram_get\s+(?:(?:\d+|2860|rtdev|wifi|wl|wlan|ralink)\s+)?([A-Za-z0-9_][A-Za-z0-9_.:-]{0,95})"),
    # nvram get foo
    re.compile(r"(?:^|[;&|`$() \t])nvram\s+get\s+([A-Za-z0-9_][A-Za-z0-9_.:-]{0,95})"),
    # nvram set foo=bar
    re.compile(r"(?:^|[;&|`$() \t])nvram\s+set\s+([A-Za-z0-9_][A-Za-z0-9_.:-]{0,95})=([^;&|`$() \t]+)"),
    # flash get foo / flash set foo bar，部分 Realtek 固件
    re.compile(r"(?:^|[;&|`$() \t])flash\s+get\s+([A-Za-z0-9_][A-Za-z0-9_.:-]{0,95})"),
]


def process_shell_and_text_strings(db):
    shell_hits = 0
    kv_hits = 0

    for item in ALL_STRINGS:
        ea = item["ea"]
        s = item["s"]

        for pat in SHELL_PATTERNS:
            for m in pat.finditer(s):
                key = m.group(1)
                value = None
                if len(m.groups()) >= 2:
                    value = m.group(2)
                if is_key_candidate(key):
                    db.add_key(key, value, "shell-command", ea, "", 88, s[:180])
                    db.shell_commands.append({"ea": ea_hex(ea), "string": s, "key": key, "value": value or ""})
                    shell_hits += 1

        # 单条 key=value 字符串
        m = KV_RE_TEXT.match(s)
        if m:
            k, v = m.group(1), m.group(2)
            db.add_all_kv(k, v, "string-kv", ea, 28 if is_nvramish_key(k) else 20)
            kv_hits += 1

        # 多行配置片段
        if "\\n" in s or "\n" in s:
            lines = s.replace("\\n", "\n").splitlines()
            for line in lines:
                m = KV_RE_TEXT.match(line.strip())
                if m:
                    k, v = m.group(1), m.group(2)
                    db.add_all_kv(k, v, "multiline-kv", ea, 30 if is_nvramish_key(k) else 20)
                    kv_hits += 1

    log("processed shell strings: {0} hits, key=value strings: {1} hits".format(shell_hits, kv_hits))


def get_segment_bytes(seg):
    start = int(seg.start_ea)
    end = int(seg.end_ea)
    size = end - start
    if size <= 0 or size > 32 * 1024 * 1024:
        return None
    try:
        return ida_bytes.get_bytes(start, size)
    except Exception:
        try:
            if idc:
                return idc.get_bytes(start, size)
        except Exception:
            return None
    return None


def process_raw_key_value_blobs(db):
    # NUL 分隔 key=value blob，例如 default nvram table。
    # 为避免 .text 里的误报，只扫 DATA/RODATA/BSS-like 之外有初始化字节的段。
    try:
        pattern = re.compile(br"([A-Za-z0-9_][A-Za-z0-9_.:-]{1,95})=([ -~]{0,%d})\x00" % MAX_KV_VALUE_LEN)
    except Exception:
        pattern = None
    if pattern is None:
        return
    hits = 0
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if not seg:
            continue
        sname = seg_name(seg_start).lower()
        if any(x in sname for x in (".text", "text", "code")):
            continue
        data = get_segment_bytes(seg)
        if not data:
            continue
        if not isinstance(data, bytes):
            try:
                data = bytes(bytearray(data))
            except Exception:
                continue
        for m in pattern.finditer(data):
            try:
                k = m.group(1).decode("latin-1", "ignore")
                v = m.group(2).decode("latin-1", "ignore")
            except Exception:
                continue
            ea = int(seg.start_ea) + m.start(1)
            conf = 35 if is_nvramish_key(k) else 18
            db.add_all_kv(k, v, "raw-kv-blob", ea, conf)
            hits += 1
    log("processed raw key=value blobs: {0} hits".format(hits))


def process_nvramish_strings_as_last_resort(db):
    """
    如果 API xref 不完整，仍然把非常像 NVRAM key 的裸字符串纳入候选。
    置信度较低，只有 nvramish key 会进入主 ini。
    """
    hits = 0
    for item in ALL_STRINGS:
        ea = item["ea"]
        s = item["s"]
        if is_key_candidate(s, strict=True):
            conf = 38 if "_" in s or s == "TZ" else 30
            if db.add_key(s, None, "nvramish-string-last-resort", ea, "", conf, "bare string heuristic"):
                hits += 1
    log("processed nvramish bare strings: {0} hits".format(hits))


# --------------------------- 输出生成 ---------------------------

def generate_ini(db, keys):
    lines = ["[config]"]
    for k in keys:
        v, _src = db.best_value(k)
        lines.append("{0}={1}".format(k, ini_escape_value(v)))
    lines.append("")
    return "\n".join(lines)


def generate_all_kv_ini(db):
    lines = ["[all_kv_low_confidence]"]
    for k in sorted(db.all_kv.keys(), key=lambda x: x.lower()):
        item = db.all_kv[k]
        lines.append("; source={0} ea={1} confidence={2}".format(item.get("source", ""), item.get("ea", ""), item.get("confidence", "")))
        lines.append("{0}={1}".format(k, ini_escape_value(item.get("value", ""))))
    lines.append("")
    return "\n".join(lines)


def generate_c(db, keys):
    rows = []
    for k in keys:
        v, src = db.best_value(k)
        rows.append('    { "%s", "%s", "%s" },' % (c_escape(k), c_escape(v), c_escape(src)))
    if not rows:
        rows.append('    { "lan_ipaddr", "192.168.10.200", "fallback" },')
        rows.append('    { "lan_netmask", "255.255.255.0", "fallback" },')

    template = r'''/*
 * Auto-generated by ida_auto_nvram.py at __TIME__.
 *
 * Build examples:
 *   mipsel-linux-uclibc-gcc -shared -fPIC -O2 -o libnvram.so.0 nvram_fake.c
 *   arm-linux-gnueabi-gcc    -shared -fPIC -O2 -o libnvram.so.0 nvram_fake.c
 *   gcc                      -shared -fPIC -O2 -o libnvram.so.0 nvram_fake.c
 *
 * Runtime:
 *   export NVRAM_FAKE_INI=/path/to/nvram.ini
 *   LD_PRELOAD=./libnvram.so.0 ./goahead
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>

#ifndef NVRAM_FAKE_GETALL_MAX
#define NVRAM_FAKE_GETALL_MAX 32768
#endif

typedef struct {
    const char *key;
    const char *value;
    const char *source;
} nvram_kv_t;

static nvram_kv_t static_kv[] = {
__ROWS__
    { NULL, NULL, NULL }
};

typedef struct dyn_kv {
    char *key;
    char *value;
    struct dyn_kv *next;
} dyn_kv_t;

static dyn_kv_t *dyn_head = NULL;

static int looks_like_index_arg(const void *p)
{
    uintptr_t x = (uintptr_t)p;
    return x < 4096U;
}

static char *xstrdup0(const char *s)
{
    if (!s) s = "";
    char *p = strdup(s);
    if (!p) {
        fprintf(stderr, "[nvram_fake] strdup failed\n");
        abort();
    }
    return p;
}

static void trim_inplace(char *s)
{
    char *p;
    if (!s) return;
    while (*s && isspace((unsigned char)*s)) {
        memmove(s, s + 1, strlen(s));
    }
    p = s + strlen(s);
    while (p > s && isspace((unsigned char)p[-1])) {
        *--p = 0;
    }
}

static const char *lookup_static(const char *key)
{
    int i;
    if (!key) return NULL;
    for (i = 0; static_kv[i].key; i++) {
        if (strcmp(static_kv[i].key, key) == 0) {
            return static_kv[i].value ? static_kv[i].value : "";
        }
    }
    return NULL;
}

static const char *lookup_dyn(const char *key)
{
    dyn_kv_t *p;
    if (!key) return NULL;
    for (p = dyn_head; p; p = p->next) {
        if (strcmp(p->key, key) == 0) {
            return p->value ? p->value : "";
        }
    }
    return NULL;
}

static const char *lookup_nvram_value(const char *key)
{
    const char *v;
    if (!key) return NULL;
    v = lookup_dyn(key);
    if (v) return v;
    v = lookup_static(key);
    if (v) return v;
    return "";
}

static void set_dyn(const char *key, const char *value)
{
    dyn_kv_t *p;
    if (!key || !*key) return;
    if (!value) value = "";
    for (p = dyn_head; p; p = p->next) {
        if (strcmp(p->key, key) == 0) {
            free(p->value);
            p->value = xstrdup0(value);
            return;
        }
    }
    p = (dyn_kv_t *)calloc(1, sizeof(*p));
    if (!p) return;
    p->key = xstrdup0(key);
    p->value = xstrdup0(value);
    p->next = dyn_head;
    dyn_head = p;
}

static void load_ini_file(const char *path)
{
    FILE *fp;
    char line[2048];
    if (!path || !*path) return;
    fp = fopen(path, "r");
    if (!fp) return;
    while (fgets(line, sizeof(line), fp)) {
        char *eq;
        trim_inplace(line);
        if (!line[0] || line[0] == '#' || line[0] == ';' || line[0] == '[') continue;
        eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = 0;
        trim_inplace(line);
        trim_inplace(eq);
        if (line[0]) set_dyn(line, eq);
    }
    fclose(fp);
}

__attribute__((constructor))
static void nvram_fake_ctor(void)
{
    const char *ini = getenv("NVRAM_FAKE_INI");
    if (ini && *ini) load_ini_file(ini);
    load_ini_file("./nvram.ini");
    fprintf(stderr, "[nvram_fake] loaded; override with NVRAM_FAKE_INI=/path/nvram.ini\n");
}

static const char *extract_get_key(void *arg0, va_list *ap)
{
    /*
     * Ralink/D-Link style often calls nvram_get(0, "key"), so arg0 == NULL
     * is a valid index argument and must still consume the next vararg.
     */
    if (looks_like_index_arg(arg0)) {
        return va_arg(*ap, const char *);
    }
    return (const char *)arg0;
}

static void extract_set_args(void *arg0, va_list *ap, const char **key, const char **value)
{
    *key = NULL;
    *value = NULL;
    /* arg0 == 0 may be a valid index: nvram_set(0, key, value). */
    if (looks_like_index_arg(arg0)) {
        *key = va_arg(*ap, const char *);
        *value = va_arg(*ap, const char *);
    } else {
        *key = (const char *)arg0;
        *value = va_arg(*ap, const char *);
    }
}

#define DEFINE_NVRAM_GETTER(fn, null_on_missing)                 \
char *fn(void *arg0, ...)                                        \
{                                                                \
    va_list ap;                                                  \
    const char *key;                                             \
    const char *value;                                           \
    va_start(ap, arg0);                                          \
    key = extract_get_key(arg0, &ap);                             \
    va_end(ap);                                                  \
    value = lookup_nvram_value(key);                              \
    fprintf(stderr, "[nvram_fake] %s(%s) -> %s\n", #fn,           \
            key ? key : "(null)", value ? value : "(null)");    \
    if (!value && (null_on_missing)) return NULL;                 \
    return xstrdup0(value ? value : "");                         \
}

DEFINE_NVRAM_GETTER(nvram_get, 1)
DEFINE_NVRAM_GETTER(nvram_bufget, 1)
DEFINE_NVRAM_GETTER(nvram_safe_get, 0)
DEFINE_NVRAM_GETTER(bcm_nvram_get, 1)
DEFINE_NVRAM_GETTER(wlcsm_nvram_get, 1)
DEFINE_NVRAM_GETTER(dni_nvram_get, 1)
DEFINE_NVRAM_GETTER(envram_get, 1)
DEFINE_NVRAM_GETTER(acosNvramConfig_get, 1)
DEFINE_NVRAM_GETTER(uci_get, 1)
DEFINE_NVRAM_GETTER(cfg_get, 1)
DEFINE_NVRAM_GETTER(config_get, 1)
DEFINE_NVRAM_GETTER(xmldbc_get, 1)

#define DEFINE_NVRAM_SETTER(fn)                                  \
int fn(void *arg0, ...)                                           \
{                                                                \
    va_list ap;                                                  \
    const char *key, *value;                                     \
    va_start(ap, arg0);                                          \
    extract_set_args(arg0, &ap, &key, &value);                    \
    va_end(ap);                                                  \
    fprintf(stderr, "[nvram_fake] %s(%s,%s)\n", #fn,              \
            key ? key : "(null)", value ? value : "(null)");    \
    if (key) set_dyn(key, value ? value : "");                   \
    return 0;                                                    \
}

DEFINE_NVRAM_SETTER(nvram_set)
DEFINE_NVRAM_SETTER(nvram_bufset)
DEFINE_NVRAM_SETTER(bcm_nvram_set)
DEFINE_NVRAM_SETTER(dni_nvram_set)
DEFINE_NVRAM_SETTER(envram_set)
DEFINE_NVRAM_SETTER(acosNvramConfig_set)
DEFINE_NVRAM_SETTER(uci_set)
DEFINE_NVRAM_SETTER(cfg_set)
DEFINE_NVRAM_SETTER(config_set)
DEFINE_NVRAM_SETTER(xmldbc_set)

int nvram_unset(void *arg0, ...)
{
    va_list ap;
    const char *key;
    va_start(ap, arg0);
    key = extract_get_key(arg0, &ap);
    va_end(ap);
    fprintf(stderr, "[nvram_fake] nvram_unset(%s)\n", key ? key : "(null)");
    if (key) set_dyn(key, "");
    return 0;
}

int nvram_getall(void *arg0, ...)
{
    va_list ap;
    char *buf = NULL;
    int count = NVRAM_FAKE_GETALL_MAX;
    char *p;
    int left;
    int i;
    dyn_kv_t *d;

    va_start(ap, arg0);
    if (looks_like_index_arg(arg0)) {
        buf = va_arg(ap, char *);
        /* Ralink-style nvram_getall(index, buf) often has no length arg. */
        count = NVRAM_FAKE_GETALL_MAX;
    } else {
        buf = (char *)arg0;
        count = va_arg(ap, int);
        if (count <= 0 || count > NVRAM_FAKE_GETALL_MAX) count = NVRAM_FAKE_GETALL_MAX;
    }
    va_end(ap);
    if (!buf || count <= 2) return -1;

    p = buf;
    left = count;
#define APPEND_KV(k, v) do {                                      \
        int n;                                                     \
        if (!(k)) break;                                           \
        n = snprintf(p, left, "%s=%s", (k), (v) ? (v) : "");      \
        if (n < 0 || n + 2 >= left) goto done;                     \
        p += n + 1;                                                \
        left -= n + 1;                                             \
    } while (0)

    for (i = 0; static_kv[i].key; i++) APPEND_KV(static_kv[i].key, lookup_nvram_value(static_kv[i].key));
    for (d = dyn_head; d; d = d->next) APPEND_KV(d->key, d->value);
done:
    if (left > 0) *p++ = '\0';
    fprintf(stderr, "[nvram_fake] nvram_getall -> %ld bytes\n", (long)(p - buf));
    return 0;
}

int nvram_match(void *arg0, ...)
{
    va_list ap;
    const char *key, *expect, *got;
    va_start(ap, arg0);
    if (looks_like_index_arg(arg0)) {
        key = va_arg(ap, const char *);
        expect = va_arg(ap, const char *);
    } else {
        key = (const char *)arg0;
        expect = va_arg(ap, const char *);
    }
    va_end(ap);
    got = lookup_nvram_value(key);
    return (got && expect && strcmp(got, expect) == 0) ? 1 : 0;
}

int nvram_invmatch(void *arg0, ...)
{
    va_list ap;
    const char *key, *expect, *got;
    va_start(ap, arg0);
    if (looks_like_index_arg(arg0)) {
        key = va_arg(ap, const char *);
        expect = va_arg(ap, const char *);
    } else {
        key = (const char *)arg0;
        expect = va_arg(ap, const char *);
    }
    va_end(ap);
    got = lookup_nvram_value(key);
    return (got && expect && strcmp(got, expect) == 0) ? 0 : 1;
}

int acosNvramConfig_match(void *arg0, ...)
{
    va_list ap;
    const char *key, *expect, *got;
    va_start(ap, arg0);
    key = (const char *)arg0;
    expect = va_arg(ap, const char *);
    va_end(ap);
    got = lookup_nvram_value(key);
    return (got && expect && strcmp(got, expect) == 0) ? 1 : 0;
}

int acosNvramConfig_invmatch(void *arg0, ...)
{
    va_list ap;
    const char *key, *expect, *got;
    va_start(ap, arg0);
    key = (const char *)arg0;
    expect = va_arg(ap, const char *);
    va_end(ap);
    got = lookup_nvram_value(key);
    return (got && expect && strcmp(got, expect) == 0) ? 0 : 1;
}

int nvram_commit()
{
    fprintf(stderr, "[nvram_fake] nvram_commit()\n");
    return 0;
}

int nvram_init()
{
    fprintf(stderr, "[nvram_fake] nvram_init()\n");
    return 0;
}

int tcapi_get(const char *node, const char *key, char *buf)
{
    const char *v = lookup_nvram_value(key ? key : node);
    fprintf(stderr, "[nvram_fake] tcapi_get(%s,%s) -> %s\n",
            node ? node : "(null)", key ? key : "(null)", v ? v : "");
    if (buf) strcpy(buf, v ? v : "");
    return 0;
}

int tcapi_set(const char *node, const char *key, const char *value)
{
    fprintf(stderr, "[nvram_fake] tcapi_set(%s,%s,%s)\n",
            node ? node : "(null)", key ? key : "(null)", value ? value : "(null)");
    if (key) set_dyn(key, value ? value : "");
    return 0;
}

int tcapi_commit()
{
    fprintf(stderr, "[nvram_fake] tcapi_commit()\n");
    return 0;
}
'''
    return template.replace("__TIME__", time.strftime("%Y-%m-%d %H:%M:%S")).replace("__ROWS__", "\n".join(rows))


def generate_report(db, keys, out_dir):
    lines = []
    lines.append("IDA Auto NVRAM Report")
    lines.append("=" * 80)
    lines.append("input      : {0}".format(get_input_path()))
    lines.append("processor  : {0}".format(get_inf_procname()))
    lines.append("output_dir : {0}".format(out_dir))
    lines.append("time       : {0}".format(time.strftime("%Y-%m-%d %H:%M:%S")))
    lines.append("")
    lines.append("[stats]")
    for k in sorted(db.stats.keys()):
        lines.append("  {0}: {1}".format(k, db.stats[k]))
    lines.append("")
    lines.append("[api symbols]")
    for a in db.api_symbols:
        lines.append("  {ea} {kind:6s} {norm} names={names}".format(
            ea=a.get("ea", ""), kind=a.get("kind", ""), norm=a.get("norm", ""), names=",".join(a.get("names", []))))
    lines.append("")
    lines.append("[selected nvram keys]")
    for k in keys:
        ent = db.keys[k]
        v, src = db.best_value(k)
        lines.append("  {0}={1}    score={2} value_source={3}".format(k, v, ent.get("score", 0), src))
        for ev in ent.get("evidence", [])[:5]:
            lines.append("      - {source} conf={confidence} ea={ea} api={api} {note}".format(**ev))
        if len(ent.get("evidence", [])) > 5:
            lines.append("      - ... {0} more".format(len(ent.get("evidence", [])) - 5))
    lines.append("")
    lines.append("[shell commands]")
    for c in db.shell_commands[:200]:
        lines.append("  {0}: {1}".format(c.get("ea", ""), c.get("string", "")))
    if len(db.shell_commands) > 200:
        lines.append("  ... {0} more".format(len(db.shell_commands) - 200))
    lines.append("")
    lines.append("[api calls]")
    for c in db.api_calls[:300]:
        lines.append("  {call_ea} {func} -> {api} args={args}".format(
            call_ea=c.get("call_ea", ""), func=c.get("func", ""), api=c.get("api", ""), args=c.get("args", {})))
    if len(db.api_calls) > 300:
        lines.append("  ... {0} more".format(len(db.api_calls) - 300))
    lines.append("")
    return "\n".join(lines)


def main():
    if ida_auto:
        try:
            ida_auto.auto_wait()
        except Exception:
            pass

    input_path = get_input_path()
    root = get_root_filename() or "ida_input"
    base_dir = os.path.dirname(input_path) or os.getcwd()
    out_dir = os.path.join(base_dir, "{0}_nvram_auto".format(os.path.splitext(os.path.basename(root))[0]))
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    collect_strings()
    apis = collect_api_symbols()

    db = Findings()
    db.stats["input"] = input_path
    db.stats["processor"] = get_inf_procname()
    db.stats["strings"] = len(ALL_STRINGS)
    db.stats["api_symbols"] = len(apis)

    process_api_calls(db, apis)
    process_shell_and_text_strings(db)
    process_raw_key_value_blobs(db)
    process_nvramish_strings_as_last_resort(db)

    keys = db.output_keys()
    db.stats["selected_keys"] = len(keys)
    db.stats["all_candidate_keys"] = len(db.keys)
    db.stats["all_kv"] = len(db.all_kv)
    db.stats["api_calls"] = len(db.api_calls)
    db.stats["shell_commands"] = len(db.shell_commands)

    ini_data = generate_ini(db, keys)
    c_data = generate_c(db, keys)
    write_text(os.path.join(out_dir, "nvram.ini"), ini_data)
    write_text(os.path.join(out_dir, "nvram_all_kv.ini"), generate_all_kv_ini(db))
    write_text(os.path.join(out_dir, "nvram_fake.c"), c_data)
    # Compatibility with older GetNvramIni.py workflow: also place nvram.ini/nvram_fake.c next to input binary.
    write_text(os.path.join(base_dir, "nvram.ini"), ini_data)
    write_text(os.path.join(base_dir, "nvram_fake.c"), c_data)
    write_text(os.path.join(out_dir, "nvram_report.txt"), generate_report(db, keys, out_dir))
    json_dump(os.path.join(out_dir, "nvram_findings.json"), db.as_jsonable())

    log("done")
    log("selected keys: {0}, all candidates: {1}, all key=value: {2}".format(len(keys), len(db.keys), len(db.all_kv)))
    log("output dir: {0}".format(out_dir))
    return out_dir


if __name__ == "__main__":
    main()


# --------------------------- IDA Plugin Entry ---------------------------

class NvramFakePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Auto extract NVRAM keys and generate nvram.ini/nvram_fake.c"
    help = "Auto extract NVRAM keys from firmware binary"
    wanted_name = "nvram_fake"
    wanted_hotkey = ""

    def init(self):
        idaapi.msg("[nvram_fake] plugin initialized\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("[nvram_fake] running...\n")
        try:
            out_dir = main()
            idaapi.msg("[nvram_fake] success. output dir: %s\n" % out_dir)
            try:
                idaapi.info("nvram_fake finished.\nOutput dir:\n%s" % out_dir)
            except Exception:
                pass
        except Exception as e:
            import traceback
            idaapi.msg("[nvram_fake] failed: %s\n" % e)
            idaapi.msg(traceback.format_exc() + "\n")
            try:
                idaapi.warning("nvram_fake failed:\n%s" % e)
            except Exception:
                pass

    def term(self):
        idaapi.msg("[nvram_fake] plugin terminated\n")


def PLUGIN_ENTRY():
    return NvramFakePlugin()
