#!/usr/bin/env python3
"""多源融合 + 深度去重的 honk geosite.dat / geoip.dat 构建器。

融合数据源：
  1. MetaCubeX/meta-rules-dat（基础 geosite.dat / geoip.dat，亦为 Surfing 全部 .mrs 的上游）
  2. blackmatrix7/ios_rule_script（rule/Clash 完整 *_Classical.yaml / *_Domain.yaml / *_IP.yaml）
  3. GitMetaio/Surfing（AWAvenue-Ads-Rule、自定义放行/IMS 规则、WebRTC.list）
  4. Hackl0us/GeoIP2-CN（CN-ip-cidr.txt IPv4）
  5. ispip.clang.cn/all_cn_ipv6.txt（大陆运营商 IPv6）
  6. X-Shelby/geoip（cn_v4.txt + cn_v6.txt）
  7. IPinfo Lite 免费国家数据库（ipinfo_lite.csv.gz，按 country_code == CN 提取 IPv4+IPv6）

去重与冲突消解：
  - 域名：规范化 + 精确去重 + 反转标签 Trie 后缀覆盖消除（母域覆盖子域与同域 full）
         + Rust regex 兼容性过滤（剔除 PCRE 环视/反向引用）
         + 跨类冲突扣减（放行白名单从广告剔除；海外核心域名从大陆直连剔除；
           大陆镜像与已分类专属域从海外兜底剔除）
  - IP：过滤保留/私网/假 IP（公共集合）+ ipaddress.collapse_addresses 超网聚合去重
        + 海外核心服务 IP 与大陆 CN IP 冲突检查与剔除
"""

from __future__ import annotations

import argparse
import csv
import datetime
import gzip
import hashlib
import ipaddress
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pbmini as pb  # noqa: E402

# honk crates/honk-core/src/routing/geo.rs 编码：
#   0 = Keyword, 1 = Regex, 2 = Domain(后缀), 3 = Full(完整域名)
T_KEYWORD, T_REGEX, T_DOMAIN, T_FULL = 0, 1, 2, 3

# Rust regex crate 不支持环视和反向引用
PCRE_UNSUPPORTED_RE = re.compile(r"\(\?[<!=]|\\[1-9]")
DOMAIN_VALID_RE = re.compile(r"^[a-z0-9._-]+$")

# 公共集合需剔除的特殊网段（除了标准 is_private 等之外额外显式排除 CGNAT / FakeIP）
EXTRA_NON_PUBLIC_V4 = [
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("198.18.0.0/15"),
]


# ── Protobuf 读写 ────────────────────────────────────────────────────────


def read_geosite(path: Path) -> dict[str, list[tuple[int, str, list[bytes]]]]:
    data = path.read_bytes()
    out: dict[str, list[tuple[int, str, list[bytes]]]] = {}
    for f, w, v in pb.iter_fields(data):
        if f != 1 or w != 2:
            continue
        code = None
        entries = []
        for f2, w2, v2 in pb.iter_fields(v):
            if f2 == 1:
                code = pb.decode_utf8(v2)
            elif f2 == 2:
                t, val = T_DOMAIN, None
                attrs = []
                for f3, w3, v3 in pb.iter_fields(v2):
                    if f3 == 1:
                        t = v3
                    elif f3 == 2:
                        val = pb.decode_utf8(v3)
                    elif f3 == 3:
                        attrs.append(v3)
                if val is not None:
                    entries.append((t, val, attrs))
        if code:
            out[code] = entries
    return out


def write_geosite(path: Path, mapping: dict[str, list[tuple[int, str, list[bytes]]]]) -> None:
    parts = []
    for code, entries in mapping.items():
        dom_parts = []
        for t, val, attrs in entries:
            inner = pb.field_varint(1, t) + pb.field_bytes(2, val)
            for a in attrs:
                inner += pb.field_bytes(3, a)
            dom_parts.append(pb.field_bytes(2, inner))
        site = pb.field_bytes(1, code) + b"".join(dom_parts)
        parts.append(pb.field_bytes(1, site))
    path.write_bytes(b"".join(parts))


def read_geoip(path: Path) -> dict[str, list[tuple[bytes, int]]]:
    data = path.read_bytes()
    out: dict[str, list[tuple[bytes, int]]] = {}
    for f, w, v in pb.iter_fields(data):
        if f != 1 or w != 2:
            continue
        code = None
        cidrs = []
        for f2, w2, v2 in pb.iter_fields(v):
            if f2 == 1:
                code = pb.decode_utf8(v2)
            elif f2 == 2:
                ip = pref = None
                for f3, w3, v3 in pb.iter_fields(v2):
                    if f3 == 1:
                        ip = v3
                    elif f3 == 2:
                        pref = v3
                if ip is not None and pref is not None:
                    cidrs.append((ip, pref))
        if code:
            out[code] = cidrs
    return out


def write_geoip(path: Path, mapping: dict[str, list[tuple[bytes, int]]]) -> None:
    parts = []
    for code, cidrs in mapping.items():
        cidr_parts = []
        for ip, pref in cidrs:
            cidr_parts.append(pb.field_bytes(2, pb.field_bytes(1, ip) + pb.field_varint(2, pref)))
        entry = pb.field_bytes(1, code) + b"".join(cidr_parts)
        parts.append(pb.field_bytes(1, entry))
    path.write_bytes(b"".join(parts))


def parse_attr_keys(attrs: list[bytes]) -> set[str]:
    keys = set()
    for a in attrs:
        for f, w, v in pb.iter_fields(a):
            if f == 1 and w == 2:
                keys.add(pb.decode_utf8(v).lower())
    return keys


# ── 文本规则解析（支持 Clash Classical / Clash Domain / .list / 纯 CIDR）──


def clean_regex(pattern: str) -> str | None:
    s = pattern.strip()
    if not s or PCRE_UNSUPPORTED_RE.search(s):
        return None
    try:
        re.compile(s)
    except re.error:
        return None
    return s


def parse_rule_text(text: str, default_behavior: str = "auto") -> tuple[list[tuple[int, str]], list[str]]:
    """返回 (domains: list[(type, value)], cidrs: list[str])。"""
    domains: list[tuple[int, str]] = []
    cidrs: list[str] = []

    lines = text.splitlines()
    has_payload = any(l.strip().startswith("payload:") for l in lines[:80])
    in_payload = not has_payload

    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if has_payload:
            if s.startswith("payload:"):
                in_payload = True
                continue
            if not in_payload:
                continue
            if s.startswith("- "):
                s = s[2:].strip()
            else:
                if not s.startswith("#"):
                    in_payload = False
                continue
        elif s.startswith("- "):
            s = s[2:].strip()

        # 去掉行尾注释
        if " #" in s:
            s = s[: s.index(" #")].strip()
        # 去掉外层单/双引号
        if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
            s = s[1:-1].strip()
        if not s:
            continue

        # 1) Clash Classical 规则：KIND,VALUE[,no-resolve]
        if "," in s:
            kind, rest = s.split(",", 1)
            kind_u = kind.strip().upper()
            val = rest.split(",", 1)[0].strip().strip("'\"")
            if kind_u == "DOMAIN":
                v = val.lower().rstrip(".")
                if v and DOMAIN_VALID_RE.match(v):
                    domains.append((T_FULL, v))
            elif kind_u == "DOMAIN-SUFFIX":
                v = val.lower().lstrip("+.").rstrip(".")
                if v and DOMAIN_VALID_RE.match(v):
                    domains.append((T_DOMAIN, v))
            elif kind_u == "DOMAIN-KEYWORD":
                v = val.lower()
                if v:
                    domains.append((T_KEYWORD, v))
            elif kind_u == "DOMAIN-REGEX":
                rx = clean_regex(val)
                if rx:
                    domains.append((T_REGEX, rx))
            elif kind_u in ("IP-CIDR", "IP-CIDR6"):
                if val:
                    cidrs.append(val)
            continue

        # 2) 纯 IP / CIDR 行
        if "/" in s or ":" in s:
            try:
                ipaddress.ip_network(s, strict=False)
                cidrs.append(s)
                continue
            except ValueError:
                pass

        # 3) Clash behavior: domain 行（'+.foo.com' / '.foo.com' / '*.foo.com' / 'foo.com'）
        if default_behavior in ("auto", "domain"):
            v = s.lower().rstrip(".")
            if v.startswith("+.") or v.startswith("*.") or v.startswith("."):
                sub = v.lstrip("+*.")
                if sub and DOMAIN_VALID_RE.match(sub):
                    domains.append((T_DOMAIN, sub))
            elif DOMAIN_VALID_RE.match(v) and "." in v:
                domains.append((T_FULL, v))

    return domains, cidrs


def load_bm7_category(clash_dir: Path, rel_path: str) -> tuple[list[tuple[int, str]], list[str]]:
    """读取 blackmatrix7/ios_rule_script 分类的完整规则集。"""
    cat_dir = clash_dir / rel_path
    if not cat_dir.is_dir():
        raise FileNotFoundError(f"bm7 category dir missing: {cat_dir}")
    name = cat_dir.name

    # 优先完整 Classical 文件（涵盖全部域名 + 关键字 + 正则 + IP）
    classical = cat_dir / f"{name}_Classical.yaml"
    if classical.is_file():
        return parse_rule_text(classical.read_text(encoding="utf-8", errors="replace"), "classical")

    # 其次合并 Domain + IP 文件（如 ChinaIPs 等仅拆分的目录）
    dom_f = cat_dir / f"{name}_Domain.yaml"
    ip_f = cat_dir / f"{name}_IP.yaml"
    if dom_f.is_file() or ip_f.is_file():
        doms: list[tuple[int, str]] = []
        cidrs: list[str] = []
        if dom_f.is_file():
            d, c = parse_rule_text(dom_f.read_text(encoding="utf-8", errors="replace"), "domain")
            doms.extend(d)
            cidrs.extend(c)
        if ip_f.is_file():
            d, c = parse_rule_text(ip_f.read_text(encoding="utf-8", errors="replace"), "auto")
            doms.extend(d)
            cidrs.extend(c)
        return doms, cidrs

    # 普通小分类（<Name>.yaml 即完整文件）
    plain = cat_dir / f"{name}.yaml"
    if plain.is_file():
        return parse_rule_text(plain.read_text(encoding="utf-8", errors="replace"), "classical")

    lst = cat_dir / f"{name}.list"
    if lst.is_file():
        return parse_rule_text(lst.read_text(encoding="utf-8", errors="replace"), "classical")

    return [], []


def load_mcx_site(
    mcx_sites: dict[str, list[tuple[int, str, list[bytes]]]],
    spec: str,
) -> list[tuple[int, str]]:
    """从 MetaCubeX geosite 提取条目，支持 'code' 或 'code@attr'。"""
    if "@" in spec:
        code_raw, attr = spec.split("@", 1)
        attr = attr.lower()
    else:
        code_raw, attr = spec, None

    entries = mcx_sites.get(code_raw.upper()) or mcx_sites.get(code_raw.lower()) or mcx_sites.get(code_raw)
    if not entries:
        return []
    out: list[tuple[int, str]] = []
    for t, val, attrs in entries:
        if attr is not None and attr not in parse_attr_keys(attrs):
            continue
        if t == T_REGEX:
            rx = clean_regex(val)
            if rx:
                out.append((T_REGEX, rx))
        elif t == T_KEYWORD:
            v = val.strip().lower()
            if v:
                out.append((T_KEYWORD, v))
        elif t in (T_DOMAIN, T_FULL):
            v = val.strip().lower().lstrip("+.").rstrip(".")
            if v and DOMAIN_VALID_RE.match(v):
                out.append((t, v))
    return out


def load_mcx_ip(mcx_ips: dict[str, list[tuple[bytes, int]]], code: str) -> list[str]:
    entries = mcx_ips.get(code.upper()) or mcx_ips.get(code.lower()) or mcx_ips.get(code) or []
    out = []
    for raw, pref in entries:
        try:
            out.append(str(ipaddress.ip_network((raw, pref), strict=False)))
        except ValueError:
            pass
    return out


# ── 域名深度去重（精确去重 + 反转标签 Trie 后缀覆盖消除）────────────────


class SuffixTrie:
    __slots__ = ("root",)

    def __init__(self) -> None:
        self.root: dict = {}

    def insert(self, domain: str) -> None:
        node = self.root
        for label in reversed(domain.split(".")):
            nxt = node.get(label)
            if nxt is None:
                nxt = {}
                node[label] = nxt
            node = nxt
        node[""] = True

    def covered_by(self, domain: str, strict_parent: bool = False) -> bool:
        """判断 domain 是否被已有后缀覆盖。strict_parent=True 时仅检查严格父域。"""
        labels = domain.split(".")
        node = self.root
        n = len(labels)
        for idx, label in enumerate(reversed(labels)):
            node = node.get(label)
            if node is None:
                return False
            if "" in node:
                if not strict_parent or idx < n - 1:
                    return True
        return False


def build_trie_from_entries(entries: list[tuple[int, str]]) -> SuffixTrie:
    trie = SuffixTrie()
    for t, v in entries:
        if t == T_DOMAIN:
            trie.insert(v)
    return trie


def dedup_domains(
    raw_items: list[tuple[int, str]],
    exclude_domains: set[tuple[int, str]] | None = None,
    exclude_trie: SuffixTrie | None = None,
) -> tuple[list[tuple[int, str]], dict[str, int]]:
    """对域名集合执行精确去重 + Trie 后缀覆盖去重 + 可选冲突扣减。"""
    stats = {"raw": len(raw_items), "exact": 0, "excluded": 0, "subsumed": 0, "final": 0}

    # 1. 精确去重
    unique: set[tuple[int, str]] = set()
    for t, v in raw_items:
        v = v.strip().lower()
        if not v:
            continue
        if t in (T_DOMAIN, T_FULL):
            v = v.lstrip("+.").rstrip(".")
            if not v or not DOMAIN_VALID_RE.match(v):
                continue
        elif t == T_REGEX:
            rx = clean_regex(v)
            if not rx:
                continue
            v = rx
        unique.add((t, v))
    stats["exact"] = len(unique)

    # 2. 冲突/已有覆盖扣减
    filtered: set[tuple[int, str]] = set()
    for t, v in unique:
        if exclude_domains and (t, v) in exclude_domains:
            stats["excluded"] += 1
            continue
        if exclude_trie and t in (T_DOMAIN, T_FULL) and exclude_trie.covered_by(v, strict_parent=False):
            stats["excluded"] += 1
            continue
        filtered.add((t, v))

    # 3. 组内后缀 Trie 覆盖去重（短后缀优先插入）
    dom_suffixes = sorted((v for t, v in filtered if t == T_DOMAIN), key=lambda d: (d.count("."), len(d), d))
    trie = SuffixTrie()
    kept_domains: list[str] = []
    for d in dom_suffixes:
        if trie.covered_by(d, strict_parent=True):
            stats["subsumed"] += 1
            continue
        trie.insert(d)
        kept_domains.append(d)

    out: list[tuple[int, str]] = [(T_DOMAIN, d) for d in kept_domains]
    for t, v in sorted(filtered):
        if t == T_DOMAIN:
            continue
        if t == T_FULL and trie.covered_by(v, strict_parent=False):
            stats["subsumed"] += 1
            continue
        out.append((t, v))

    stats["final"] = len(out)
    return out, stats


# ── IP/CIDR 去重与超网聚合 ──────────────────────────────────────────────


def is_public_net(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if (
        net.is_private
        or net.is_loopback
        or net.is_link_local
        or net.is_multicast
        or net.is_unspecified
        or net.is_reserved
    ):
        return False
    if net.version == 4:
        for bad in EXTRA_NON_PUBLIC_V4:
            if net.overlaps(bad):
                return False
    return True


def subtract_networks(
    base_nets: list[ipaddress.IPv4Network] | list[ipaddress.IPv6Network],
    excl_nets: list[ipaddress.IPv4Network] | list[ipaddress.IPv6Network],
) -> tuple[list, int]:
    """O(N+M) 排序双指针区间差集，从已聚合的 base_nets 中精确扣减 excl_nets 重叠部分。"""
    if not base_nets or not excl_nets:
        return base_nets, 0
    cls = ipaddress.IPv4Address if base_nets[0].version == 4 else ipaddress.IPv6Address
    ex_intervals = [(int(e.network_address), int(e.broadcast_address)) for e in excl_nets]
    ex_intervals.sort()
    j = 0
    m = len(ex_intervals)
    out = []
    hits = 0
    for net in base_nets:
        a, b = int(net.network_address), int(net.broadcast_address)
        while j < m and ex_intervals[j][1] < a:
            j += 1
        k = j
        cur = a
        had_hit = False
        while k < m and ex_intervals[k][0] <= b:
            ea, eb = ex_intervals[k]
            had_hit = True
            if ea > cur:
                out.extend(ipaddress.summarize_address_range(cls(cur), cls(ea - 1)))
            if eb + 1 > cur:
                cur = eb + 1
            if cur > b:
                break
            k += 1
        if had_hit:
            hits += 1
            if cur <= b:
                out.extend(ipaddress.summarize_address_range(cls(cur), cls(b)))
        else:
            out.append(net)
    return list(ipaddress.collapse_addresses(out)) if out else [], hits


def collapse_cidrs(
    raw_cidrs: list[str],
    public_only: bool = True,
    exclude_v4: list[ipaddress.IPv4Network] | None = None,
    exclude_v6: list[ipaddress.IPv6Network] | None = None,
) -> tuple[list[tuple[bytes, int]], list[ipaddress.IPv4Network], list[ipaddress.IPv6Network], dict[str, int]]:
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    dropped = 0
    for s in raw_cidrs:
        try:
            n = ipaddress.ip_network(s.strip(), strict=False)
        except ValueError:
            dropped += 1
            continue
        if public_only and not is_public_net(n):
            dropped += 1
            continue
        if n.version == 4:
            v4.append(n)
        else:
            v6.append(n)

    raw_v4, raw_v6 = len(v4), len(v6)
    col_v4 = list(ipaddress.collapse_addresses(v4)) if v4 else []
    col_v6 = list(ipaddress.collapse_addresses(v6)) if v6 else []

    ex_hits = 0
    if exclude_v4 and col_v4:
        col_v4, h4 = subtract_networks(col_v4, exclude_v4)
        ex_hits += h4
    if exclude_v6 and col_v6:
        col_v6, h6 = subtract_networks(col_v6, exclude_v6)
        ex_hits += h6

    packed = [(n.network_address.packed, n.prefixlen) for n in col_v4] + [
        (n.network_address.packed, n.prefixlen) for n in col_v6
    ]
    stats = {
        "raw_v4": raw_v4,
        "raw_v6": raw_v6,
        "col_v4": len(col_v4),
        "col_v6": len(col_v6),
        "dropped": dropped,
        "excluded": ex_hits,
    }
    return packed, col_v4, col_v6, stats


# ── 主构建流程 ──────────────────────────────────────────────────────────


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description="构建多源融合且深度去重的 honk geosite.dat / geoip.dat")
    ap.add_argument("--mcx-geosite", required=True, type=Path)
    ap.add_argument("--mcx-geoip", required=True, type=Path)
    ap.add_argument("--bm7-clash-dir", required=True, type=Path)
    ap.add_argument("--surfing-dir", required=True, type=Path)
    ap.add_argument("--awavenue-yaml", required=True, type=Path)
    ap.add_argument("--hackl0us-cn", required=True, type=Path)
    ap.add_argument("--clang-cn-v6", required=True, type=Path)
    ap.add_argument("--shelby-cn-v4", required=True, type=Path)
    ap.add_argument("--shelby-cn-v6", required=True, type=Path)
    ap.add_argument("--ipinfo-lite-csv", type=Path, default=None, help="IPinfo Lite 数据库（.csv 或 .csv.gz），按 country_code==CN 提取 IPv4+IPv6")
    ap.add_argument("--out-geosite", required=True, type=Path)
    ap.add_argument("--out-geoip", required=True, type=Path)
    ap.add_argument("--build-txt", type=Path, default=None)
    args = ap.parse_args()

    print("[1/5] 读取 MetaCubeX 基础库...")
    mcx_sites = read_geosite(args.mcx_geosite)
    mcx_ips = read_geoip(args.mcx_geoip)
    print(f"  MetaCubeX: geosite={len(mcx_sites)} codes, geoip={len(mcx_ips)} codes")

    # 缓存 bm7 解析结果，避免同一分类重复解析
    bm7_cache: dict[str, tuple[list[tuple[int, str]], list[str]]] = {}

    def get_bm7(rel: str) -> tuple[list[tuple[int, str]], list[str]]:
        if rel not in bm7_cache:
            bm7_cache[rel] = load_bm7_category(args.bm7_clash_dir, rel)
        return bm7_cache[rel]

    def collect_bucket(
        mcx_codes: list[str],
        bm7_cats: list[str],
        extra_domains: list[tuple[int, str]] | None = None,
        extra_cidrs: list[str] | None = None,
    ) -> tuple[list[tuple[int, str]], list[str]]:
        doms: list[tuple[int, str]] = []
        cidrs: list[str] = []
        for c in mcx_codes:
            doms.extend(load_mcx_site(mcx_sites, c))
        for cat in bm7_cats:
            d, ip_list = get_bm7(cat)
            doms.extend(d)
            cidrs.extend(ip_list)
        if extra_domains:
            doms.extend(extra_domains)
        if extra_cidrs:
            cidrs.extend(extra_cidrs)
        return doms, cidrs

    print("[2/5] 解析 Surfing 规则与 AWAvenue 广告库...")
    surfing_custom_doms, surfing_custom_ips = parse_rule_text(
        (args.surfing_dir / "box_bll/clash/etc/自定义规则.list").read_text(encoding="utf-8", errors="replace"),
        "classical",
    )
    # 补充 Surfing config.yaml 的 skip-domain（如 io.mi.com）
    surfing_custom_doms.append((T_DOMAIN, "io.mi.com"))

    surfing_webrtc_doms, surfing_webrtc_ips = parse_rule_text(
        (args.surfing_dir / "box_bll/clash/rules/WebRTC.list").read_text(encoding="utf-8", errors="replace"),
        "classical",
    )
    aw_doms, aw_ips = parse_rule_text(
        args.awavenue_yaml.read_text(encoding="utf-8", errors="replace"),
        "domain",
    )
    print(
        f"  Surfing 自定义={len(surfing_custom_doms)} 域, WebRTC={len(surfing_webrtc_doms)} 域, "
        f"AWAvenue={len(aw_doms)} 域 + {len(aw_ips)} IP"
    )

    print("[3/5] 融合并深度去重各语义域名桶...")
    merged_sites: dict[str, list[tuple[int, str]]] = {}
    bm7_bucket_ips: dict[str, list[str]] = {}
    domain_report: list[str] = []

    def build_domain_bucket(
        code: str,
        mcx_codes: list[str],
        bm7_cats: list[str],
        extra_domains: list[tuple[int, str]] | None = None,
        extra_cidrs: list[str] | None = None,
        excl_domains: set[tuple[int, str]] | None = None,
        excl_trie: SuffixTrie | None = None,
    ) -> list[tuple[int, str]]:
        doms, cidrs = collect_bucket(mcx_codes, bm7_cats, extra_domains, extra_cidrs)
        deduped, st = dedup_domains(doms, excl_domains, excl_trie)
        merged_sites[code] = deduped
        if cidrs:
            bm7_bucket_ips[code] = cidrs
        line = (
            f"  {code:22s}: raw={st['raw']:6d} -> exact={st['exact']:6d} "
            f"(excl={st['excluded']:5d}, subsumed={st['subsumed']:5d}) -> final={st['final']:6d}"
        )
        print(line)
        domain_report.append(line.strip())
        return deduped

    # 3.1 基础直连与白名单
    build_domain_bucket("merged-lan", ["private"], ["Lan", "NTPService"])
    surfing_direct = build_domain_bucket(
        "surfing-direct",
        [],
        [],
        extra_domains=surfing_custom_doms,
        extra_cidrs=surfing_custom_ips,
    )
    cn_mirror = build_domain_bucket(
        "merged-cn-mirror",
        [
            "apple-cn",
            "apple@cn",
            "microsoft@cn",
            "google-cn",
            "google@cn",
            "amazon@cn",
            "steam@cn",
            "category-games@cn",
            "category-dev-cn",
            "category-dev@cn",
            "bilibili-game",
        ],
        ["SteamCN", "Game/GameDownloadCN", "AmazonCN", "Cloudflarecn", "PrivateTracker"],
    )
    cn_mirror_set = set(cn_mirror)
    cn_mirror_trie = build_trie_from_entries(cn_mirror)

    # 3.2 广告拦截（AWAvenue + MetaCubeX ads-all + bm7 AdvertisingLite + Hijacking + BlockHttpDNS）
    # 明确扣减 Surfing 放行白名单 + 用户自建/测速/Play CDN 关键域名，避免误杀
    ads_allow_extra = [
        (T_DOMAIN, "00p.net"),
        (T_DOMAIN, "6kuai.top"),
        (T_DOMAIN, "20030913.xyz"),
        (T_DOMAIN, "mozhe.world"),
        (T_DOMAIN, "gvt1.com"),
        (T_DOMAIN, "xn--ngstr-lra8j.com"),
        (T_DOMAIN, "cp.cloudflare.com"),
        (T_DOMAIN, "gstatic.com"),
        (T_DOMAIN, "googleapis.com"),
        (T_DOMAIN, "io.mi.com"),
    ]
    ads_allow_all = list(surfing_direct) + ads_allow_extra
    ads_allow_set = set(ads_allow_all)
    ads_allow_trie = build_trie_from_entries(ads_allow_all)
    build_domain_bucket(
        "merged-ads",
        ["category-ads-all"],
        ["AdvertisingLite", "Hijacking", "BlockHttpDNS"],
        extra_domains=aw_doms,
        extra_cidrs=aw_ips,
        excl_domains=ads_allow_set,
        excl_trie=ads_allow_trie,
    )

    # 3.3 WebRTC / STUN
    build_domain_bucket(
        "merged-webrtc",
        [],
        ["STUN"],
        extra_domains=surfing_webrtc_doms,
        extra_cidrs=surfing_webrtc_ips,
    )

    # 3.4 大陆三大内容平台 + 大陆影音
    build_domain_bucket("merged-bilibili", ["bilibili", "bilibili-game"], ["BiliBili"])
    build_domain_bucket("merged-douyin", ["douyin"], ["DouYin"])
    build_domain_bucket("merged-xiaohongshu", ["xiaohongshu"], ["XiaoHongShu"])
    build_domain_bucket("merged-chinamedia", ["category-media-cn"], ["ChinaMedia"])

    # 3.5 海外专属服务（各桶内部去重；对含国内镜像的大厂扣减 cn_mirror）
    ov_openai = build_domain_bucket("merged-openai", ["openai"], ["OpenAI"])
    ov_ai = build_domain_bucket(
        "merged-ai",
        ["anthropic", "google-gemini", "github-copilot", "category-ai-!cn"],
        ["Claude", "Anthropic", "Gemini", "BardAI", "Copilot", "Civitai"],
        extra_domains=[
            (T_FULL, "ai.google.dev"),
            (T_FULL, "alkalimakersuite-pa.clients6.google.com"),
            (T_FULL, "makersuite.google.com"),
            (T_DOMAIN, "bard.google.com"),
            (T_DOMAIN, "deepmind.com"),
            (T_DOMAIN, "deepmind.google"),
            (T_DOMAIN, "gemini.google.com"),
            (T_DOMAIN, "generativeai.google"),
            (T_DOMAIN, "proactivebackend-pa.googleapis.com"),
            (T_DOMAIN, "apis.google.com"),
            (T_KEYWORD, "colab"),
            (T_KEYWORD, "developerprofiles"),
            (T_KEYWORD, "generativelanguage"),
        ],
    )
    ov_github = build_domain_bucket("merged-github", ["github"], ["GitHub"])
    ov_emby = build_domain_bucket("merged-emby", ["category-emby"], ["Emby"])
    ov_ehentai = build_domain_bucket("merged-ehentai", ["ehentai"], ["EHGallery"])
    ov_pixiv = build_domain_bucket("merged-pixiv", ["pixiv"], ["Pixiv"])
    ov_discord = build_domain_bucket("merged-discord", ["discord"], ["Discord"])
    ov_tiktok = build_domain_bucket("merged-tiktok", ["tiktok"], ["TikTok"])
    ov_twitter = build_domain_bucket("merged-twitter", ["twitter", "x"], ["Twitter"])
    ov_telegram = build_domain_bucket("merged-telegram", ["telegram"], ["Telegram"])
    ov_fcm = build_domain_bucket(
        "merged-googlefcm",
        ["googlefcm"],
        ["GoogleFCM"],
        extra_domains=[(T_KEYWORD, "mtalk.google")],
    )
    ov_youtube = build_domain_bucket("merged-youtube", ["youtube"], ["YouTube", "YouTubeMusic"])
    ov_google = build_domain_bucket(
        "merged-google",
        ["google"],
        ["Google", "GoogleDrive", "GoogleVoice"],
        excl_domains=cn_mirror_set,
        excl_trie=cn_mirror_trie,
    )
    ov_instagram = build_domain_bucket("merged-instagram", ["instagram"], ["Instagram", "Threads"])
    ov_netflix = build_domain_bucket("merged-netflix", ["netflix"], ["Netflix"])
    ov_spotify = build_domain_bucket("merged-spotify", ["spotify"], ["Spotify"])
    ov_steam = build_domain_bucket(
        "merged-steam",
        ["steam"],
        ["Steam"],
        excl_domains=cn_mirror_set,
        excl_trie=cn_mirror_trie,
    )
    ov_apple = build_domain_bucket(
        "merged-apple",
        ["apple"],
        ["AppleProxy", "AppStore", "iCloud", "TestFlight", "Apple"],
        excl_domains=cn_mirror_set,
        excl_trie=cn_mirror_trie,
    )
    ov_ms = build_domain_bucket(
        "merged-microsoft",
        ["microsoft"],
        ["Microsoft", "OneDrive", "Teams", "MicrosoftEdge", "Bing"],
        excl_domains=cn_mirror_set,
        excl_trie=cn_mirror_trie,
    )
    ov_fb = build_domain_bucket("merged-facebook", ["facebook"], ["Facebook"])
    ov_pikpak = build_domain_bucket(
        "merged-pikpak",
        ["pikpak"],
        ["PikPak"],
        extra_domains=[
            (T_DOMAIN, "mypikpak.com"),
            (T_DOMAIN, "mypikpak.net"),
            (T_DOMAIN, "pikpak.com"),
            (T_DOMAIN, "pikpak.me"),
            (T_DOMAIN, "pikpak.site"),
        ],
    )
    ov_asian = build_domain_bucket(
        "merged-asianmedia",
        ["bahamut"],
        ["Bahamut", "HBOHK", "HBOAsia", "TVB", "ViuTV", "myTVSUPER", "BiliBiliIntl", "AsianMedia"],
    )
    ov_media_other = build_domain_bucket(
        "merged-media-other",
        ["disney", "hbo", "primevideo", "apple-tvplus"],
        [
            "Disney",
            "HBO",
            "HBOUSA",
            "PrimeVideo",
            "AmazonPrimeVideo",
            "Hulu",
            "HuluJP",
            "HuluUSA",
            "Abema",
            "Niconico",
            "DMM",
            "Twitch",
            "BBC",
            "DAZN",
            "AppleTV",
            "AppleMusic",
            "GlobalMedia",
        ],
    )
    ov_dev_other = build_domain_bucket(
        "merged-dev-other",
        ["jetbrains", "stackexchange", "npmjs", "docker", "category-dev"],
        [
            "GitLab",
            "Docker",
            "Jetbrains",
            "Stackexchange",
            "Npmjs",
            "Python",
            "Developer",
            "Vercel",
            "DigitalOcean",
            "HashiCorp",
            "Atlassian",
            "Figma",
            "Notion",
            "Slack",
            "Adobe",
            "Dropbox",
            "MEGA",
            "Ubuntu",
            "Linux",
            "GlobalScholar",
            "Scholar",
            "Cloud/CloudGlobal",
        ],
        excl_domains=cn_mirror_set,
        excl_trie=cn_mirror_trie,
    )
    ov_social_other = build_domain_bucket(
        "merged-social-other",
        ["reddit"],
        ["Reddit", "Whatsapp", "Line", "LinkedIn", "Pinterest", "Wikipedia", "Wikimedia"],
    )
    ov_games_other = build_domain_bucket(
        "merged-games-other",
        ["epicgames", "xbox", "playstation", "nintendo", "category-games"],
        [
            "Epic",
            "Xbox",
            "PlayStation",
            "Nintendo",
            "Blizzard",
            "Battle",
            "Riot",
            "Rockstar",
            "EA",
            "Ubisoft",
            "Gog",
            "Supercell",
            "HoYoverse",
            "Game",
            "Game/GameDownload",
        ],
        excl_domains=cn_mirror_set,
        excl_trie=cn_mirror_trie,
    )
    ov_tech_other = build_domain_bucket(
        "merged-tech-other",
        ["amazon", "paypal", "cloudflare"],
        [
            "Amazon",
            "PayPal",
            "Stripe",
            "TeraBox",
            "Cryptocurrency",
            "Binance",
            "OKX",
            "Speedtest",
            "Download",
            "Cloudflare",
        ],
        extra_domains=[(T_DOMAIN, "v2ex.com")],
        excl_domains=cn_mirror_set,
        excl_trie=cn_mirror_trie,
    )

    # 3.6 大陆全量域名（MetaCubeX cn + geolocation-cn + bm7 ChinaMax + Direct + CloudCN + ChinaMedia）
    # 扣减强海外核心服务域名，确保大陆规则绝不误劫持海外服务（如 GitHub/OpenAI/Telegram/Google 等）
    strict_overseas_protect = (
        ov_openai
        + ov_ai
        + ov_github
        + ov_ehentai
        + ov_pixiv
        + ov_discord
        + ov_tiktok
        + ov_twitter
        + ov_telegram
        + ov_youtube
        + ov_google
        + ov_instagram
        + ov_netflix
        + ov_spotify
        + ov_fb
        + ov_pikpak
        + [
            (T_DOMAIN, "sehuatang.org"),
            (T_DOMAIN, "dmn12.vip"),
            (T_DOMAIN, "ttou.j03og.app"),
            (T_DOMAIN, "tu.ymawv.la"),
            (T_DOMAIN, "djhdhs.us"),
            (T_DOMAIN, "etboo.cc"),
            (T_DOMAIN, "ghfast.top"),
        ]
    )
    strict_ov_set = set(strict_overseas_protect)
    strict_ov_trie = build_trie_from_entries(strict_overseas_protect)

    merged_cn = build_domain_bucket(
        "merged-cn",
        ["cn", "geolocation-cn", "category-media-cn"],
        ["ChinaMax", "Direct", "Cloud/CloudCN", "ChinaMedia"],
        excl_domains=strict_ov_set,
        excl_trie=strict_ov_trie,
    )

    # 3.7 海外全量兜底域名（MetaCubeX geolocation-!cn + bm7 Global + Proxy）
    # 扣减所有已在前序规则出现的专属海外桶 + 大陆镜像 + 大陆全量，消除跨桶重复
    all_already_classified = (
        cn_mirror
        + merged_cn
        + ov_openai
        + ov_ai
        + ov_github
        + ov_emby
        + ov_ehentai
        + ov_pixiv
        + ov_discord
        + ov_tiktok
        + ov_twitter
        + ov_telegram
        + ov_fcm
        + ov_youtube
        + ov_google
        + ov_instagram
        + ov_netflix
        + ov_spotify
        + ov_steam
        + ov_apple
        + ov_ms
        + ov_fb
        + ov_pikpak
        + ov_asian
        + ov_media_other
        + ov_dev_other
        + ov_social_other
        + ov_games_other
        + ov_tech_other
    )
    already_set = set(all_already_classified)
    already_trie = build_trie_from_entries(all_already_classified)

    build_domain_bucket(
        "merged-overseas",
        ["geolocation-!cn"],
        ["Global", "Proxy"],
        excl_domains=already_set,
        excl_trie=already_trie,
    )

    # ── 4. 融合并超网聚合去重 GeoIP ─────────────────────────────────────
    print("[4/5] 融合并超网聚合去重 GeoIP（含 7 源大陆 IPv4+IPv6）...")
    merged_ips: dict[str, list[tuple[bytes, int]]] = {}
    ip_report: list[str] = []

    def build_ip_bucket(
        code: str,
        raw_cidrs: list[str],
        public_only: bool = True,
        excl_v4: list[ipaddress.IPv4Network] | None = None,
        excl_v6: list[ipaddress.IPv6Network] | None = None,
    ) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
        packed, c4, c6, st = collapse_cidrs(raw_cidrs, public_only, excl_v4, excl_v6)
        merged_ips[code] = packed
        line = (
            f"  {code:22s}: v4 {st['raw_v4']:5d}->{st['col_v4']:5d}, "
            f"v6 {st['raw_v6']:5d}->{st['col_v6']:5d} (drop={st['dropped']}, excl={st['excluded']})"
        )
        print(line)
        ip_report.append(line.strip())
        return c4, c6

    # 4.1 专属海外服务 IP 桶（先构建，以便保护不被大陆 CN 误含）
    tg_v4, tg_v6 = build_ip_bucket("merged-telegram-ip", load_mcx_ip(mcx_ips, "TELEGRAM") + bm7_bucket_ips.get("merged-telegram", []))
    tw_v4, tw_v6 = build_ip_bucket("merged-twitter-ip", load_mcx_ip(mcx_ips, "TWITTER") + bm7_bucket_ips.get("merged-twitter", []))
    oai_v4, oai_v6 = build_ip_bucket("merged-openai-ip", bm7_bucket_ips.get("merged-openai", []))
    ai_v4, ai_v6 = build_ip_bucket("merged-ai-ip", load_mcx_ip(mcx_ips, "AI") + bm7_bucket_ips.get("merged-ai", []))
    yt_v4, yt_v6 = build_ip_bucket("merged-youtube-ip", bm7_bucket_ips.get("merged-youtube", []))
    fcm_v4, fcm_v6 = build_ip_bucket("merged-googlefcm-ip", bm7_bucket_ips.get("merged-googlefcm", []))
    gg_v4, gg_v6 = build_ip_bucket("merged-google-ip", load_mcx_ip(mcx_ips, "GOOGLE") + bm7_bucket_ips.get("merged-google", []))
    nf_v4, nf_v6 = build_ip_bucket("merged-netflix-ip", load_mcx_ip(mcx_ips, "NETFLIX") + bm7_bucket_ips.get("merged-netflix", []))
    sp_v4, sp_v6 = build_ip_bucket("merged-spotify-ip", bm7_bucket_ips.get("merged-spotify", []))
    fb_v4, fb_v6 = build_ip_bucket("merged-facebook-ip", load_mcx_ip(mcx_ips, "FACEBOOK") + bm7_bucket_ips.get("merged-facebook", []))
    build_ip_bucket("merged-apple-ip", load_mcx_ip(mcx_ips, "APPLE") + bm7_bucket_ips.get("merged-apple", []))
    build_ip_bucket("merged-ehentai-ip", bm7_bucket_ips.get("merged-ehentai", []))
    build_ip_bucket("merged-asianmedia-ip", bm7_bucket_ips.get("merged-asianmedia", []))
    build_ip_bucket("merged-bilibili-ip", load_mcx_ip(mcx_ips, "BILIBILI") + bm7_bucket_ips.get("merged-bilibili", []))
    build_ip_bucket("merged-lan-ip", bm7_bucket_ips.get("merged-lan", []), public_only=False)
    build_ip_bucket("merged-webrtc-ip", bm7_bucket_ips.get("merged-webrtc", []), public_only=True)
    build_ip_bucket("merged-ads-ip", bm7_bucket_ips.get("merged-ads", []), public_only=True)

    # 4.2 大陆全量 IPv4 + IPv6（7 源融合 + 超网聚合 + 强海外服务 IP 防冲突扣减）
    def read_cidr_file(p: Path) -> list[str]:
        _, cidrs = parse_rule_text(p.read_text(encoding="utf-8", errors="replace"), "auto")
        return cidrs

    def read_ipinfo_lite_cn(p: Path | None) -> list[str]:
        if p is None or not p.exists() or p.stat().st_size == 0:
            return []
        opener = gzip.open if p.suffix == ".gz" else open
        cidrs: list[str] = []
        with opener(p, "rt", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return []
            try:
                net_i = header.index("network")
                cc_i = header.index("country_code")
            except ValueError:
                return []
            for row in reader:
                if len(row) > cc_i and row[cc_i] == "CN":
                    net_s = row[net_i].strip()
                    if net_s:
                        cidrs.append(net_s)
        return cidrs

    ipinfo_cn_cidrs = read_ipinfo_lite_cn(args.ipinfo_lite_csv)
    if args.ipinfo_lite_csv is not None:
        print(f"  IPinfo Lite CN 提取: {len(ipinfo_cn_cidrs):,} 条 CIDR（仅按国家码 CN 筛选）")

    _, bm7_chinaips_cidrs = get_bm7("ChinaIPs")
    cn_raw_cidrs = (
        load_mcx_ip(mcx_ips, "CN")
        + read_cidr_file(args.hackl0us_cn)
        + read_cidr_file(args.shelby_cn_v4)
        + read_cidr_file(args.shelby_cn_v6)
        + read_cidr_file(args.clang_cn_v6)
        + ipinfo_cn_cidrs
        + bm7_chinaips_cidrs
        + bm7_bucket_ips.get("merged-cn", [])
        + bm7_bucket_ips.get("merged-chinamedia", [])
        + bm7_bucket_ips.get("merged-bilibili", [])
        + bm7_bucket_ips.get("merged-cn-mirror", [])
    )

    protect_ov_v4 = list(ipaddress.collapse_addresses(tg_v4 + tw_v4 + oai_v4 + ai_v4 + yt_v4 + fcm_v4 + gg_v4 + nf_v4 + sp_v4 + fb_v4))
    protect_ov_v6 = list(ipaddress.collapse_addresses(tg_v6 + tw_v6 + oai_v6 + ai_v6 + yt_v6 + fcm_v6 + gg_v6 + nf_v6 + sp_v6 + fb_v6))

    cn_v4, cn_v6 = build_ip_bucket("CN", cn_raw_cidrs, public_only=True, excl_v4=protect_ov_v4, excl_v6=protect_ov_v6)
    merged_ips["cn-v4"] = [(n.network_address.packed, n.prefixlen) for n in cn_v4]
    merged_ips["cn-v6"] = [(n.network_address.packed, n.prefixlen) for n in cn_v6]

    # 4.3 海外其余兜底 IP（扣除 CN 避免重叠）
    ov_other_raw_ips = (
        bm7_bucket_ips.get("merged-media-other", [])
        + bm7_bucket_ips.get("merged-dev-other", [])
        + bm7_bucket_ips.get("merged-social-other", [])
        + bm7_bucket_ips.get("merged-games-other", [])
        + bm7_bucket_ips.get("merged-tech-other", [])
        + bm7_bucket_ips.get("merged-overseas", [])
        + bm7_bucket_ips.get("merged-steam", [])
    )
    build_ip_bucket("merged-overseas-ip", ov_other_raw_ips, public_only=True, excl_v4=cn_v4, excl_v6=cn_v6)

    # ── 5. 写出 geosite.dat / geoip.dat ─────────────────────────────────
    print("[5/5] 写出合并去重后的 geosite.dat 与 geoip.dat...")
    out_sites = dict(mcx_sites)
    for code, entries in merged_sites.items():
        if entries:
            out_sites[code] = [(t, v, []) for t, v in entries]

    out_ips = dict(mcx_ips)
    for code, entries in merged_ips.items():
        if entries:
            out_ips[code] = entries

    args.out_geosite.parent.mkdir(parents=True, exist_ok=True)
    args.out_geoip.parent.mkdir(parents=True, exist_ok=True)
    write_geosite(args.out_geosite, out_sites)
    write_geoip(args.out_geoip, out_ips)

    gs_sz, gi_sz = args.out_geosite.stat().st_size, args.out_geoip.stat().st_size
    gs_sha, gi_sha = sha256_file(args.out_geosite), sha256_file(args.out_geoip)
    print(f"  geosite.dat: {len(out_sites)} codes, {gs_sz:,} bytes, sha256={gs_sha[:16]}...")
    print(f"  geoip.dat  : {len(out_ips)} codes, {gi_sz:,} bytes, sha256={gi_sha[:16]}...")

    if args.build_txt:
        summary = [
            f"built: {datetime.datetime.now().isoformat(timespec='seconds')}",
            "sources:",
            "  - MetaCubeX/meta-rules-dat (base geosite/geoip + Surfing .mrs upstream)",
            "  - blackmatrix7/ios_rule_script (rule/Clash full *_Classical.yaml)",
            "  - GitMetaio/Surfing (AWAvenue-Ads-Rule + 自定义规则.list + WebRTC.list)",
            "  - Hackl0us/GeoIP2-CN (CN-ip-cidr.txt)",
            "  - ispip.clang.cn/all_cn_ipv6.txt",
            "  - X-Shelby/geoip (cn_v4.txt + cn_v6.txt)",
            f"  - IPinfo Lite (country_code==CN, {len(ipinfo_cn_cidrs):,} raw CIDRs)" if ipinfo_cn_cidrs else "  - IPinfo Lite (skipped)",
            f"geosite.dat: {gs_sz} bytes ({len(out_sites)} codes) sha256={gs_sha}",
            f"geoip.dat: {gi_sz} bytes ({len(out_ips)} codes) sha256={gi_sha}",
            "",
            "[Domain Dedup Report]",
            *domain_report,
            "",
            "[GeoIP Collapse Report]",
            *ip_report,
        ]
        args.build_txt.write_text("\n".join(summary) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
