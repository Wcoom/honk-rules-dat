#!/usr/bin/env python3
"""Verify generated geosite.dat and geoip.dat integrity before publishing Release."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib.util

spec = importlib.util.spec_from_file_location("bg", Path(__file__).resolve().parent / "build-geo.py")
bg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bg)

dist = Path(sys.argv[1])
gs_path = dist / "geosite.dat"
gi_path = dist / "geoip.dat"

assert gs_path.stat().st_size > 4_000_000, f"geosite.dat too small: {gs_path.stat().st_size}"
assert gi_path.stat().st_size > 10_000_000, f"geoip.dat too small: {gi_path.stat().st_size}"

sites = bg.read_geosite(gs_path)
ips = bg.read_geoip(gi_path)

req_sites = [
    "merged-lan", "surfing-direct", "merged-cn-mirror", "merged-ads",
    "merged-webrtc", "merged-bilibili", "merged-douyin", "merged-xiaohongshu",
    "merged-chinamedia", "merged-openai", "merged-ai", "merged-github",
    "merged-emby", "merged-ehentai", "merged-pixiv", "merged-discord",
    "merged-tiktok", "merged-twitter", "merged-telegram", "merged-googlefcm",
    "merged-youtube", "merged-google", "merged-instagram", "merged-netflix",
    "merged-spotify", "merged-steam", "merged-apple", "merged-microsoft",
    "merged-facebook", "merged-pikpak", "merged-asianmedia", "merged-media-other",
    "merged-dev-other", "merged-social-other", "merged-games-other",
    "merged-tech-other", "merged-cn", "merged-overseas", "private", "cn",
]
for code in req_sites:
    cnt = len(sites.get(code) or sites.get(code.upper()) or [])
    assert cnt > 0, f"missing or empty geosite code: {code}"

req_ips = [
    "CN", "cn-v4", "cn-v6", "merged-lan-ip", "merged-webrtc-ip", "merged-ads-ip",
    "merged-telegram-ip", "merged-twitter-ip", "merged-openai-ip", "merged-ai-ip",
    "merged-youtube-ip", "merged-googlefcm-ip", "merged-google-ip", "merged-netflix-ip",
    "merged-spotify-ip", "merged-facebook-ip", "merged-apple-ip", "merged-ehentai-ip",
    "merged-asianmedia-ip", "merged-bilibili-ip", "merged-overseas-ip",
]
for code in req_ips:
    cnt = len(ips.get(code) or ips.get(code.upper()) or [])
    assert cnt > 0, f"missing or empty geoip code: {code}"

assert len(sites["merged-cn"]) > 50_000, f"merged-cn unexpectedly small: {len(sites['merged-cn'])}"
assert len(sites["merged-ads"]) > 20_000, f"merged-ads unexpectedly small: {len(sites['merged-ads'])}"
assert len(ips["CN"]) > 8_000, f"geoip:CN unexpectedly small: {len(ips['CN'])}"
assert len(ips["cn-v4"]) > 5_000, f"geoip:cn-v4 unexpectedly small: {len(ips['cn-v4'])}"
assert len(ips["cn-v6"]) > 2_000, f"geoip:cn-v6 unexpectedly small: {len(ips['cn-v6'])}"

import ipaddress

cn_v4_nets = [ipaddress.IPv4Network((b, p)) for b, p in ips["cn-v4"]]
cn_v6_nets = [ipaddress.IPv6Network((b, p)) for b, p in ips["cn-v6"]]

def in_cn(ip_s: str) -> bool:
    ip = ipaddress.ip_address(ip_s)
    nets = cn_v4_nets if ip.version == 4 else cn_v6_nets
    return any(ip in n for n in nets)

for must_cn in ["223.5.5.5", "114.114.114.114", "119.29.29.29", "180.101.50.242", "240e::1", "2409:8000::1"]:
    assert in_cn(must_cn), f"expected CN IP missing from geoip:CN: {must_cn}"
for must_not_cn in ["8.8.8.8", "1.1.1.1", "149.154.167.50", "140.82.112.4", "104.21.89.181"]:
    assert not in_cn(must_not_cn), f"overseas IP wrongly included in geoip:CN: {must_not_cn}"

print(
    f"VERIFY PASSED: geosite={len(sites)} codes ({gs_path.stat().st_size:,} B, "
    f"merged-cn={len(sites['merged-cn'])}, merged-ads={len(sites['merged-ads'])}, "
    f"merged-overseas={len(sites['merged-overseas'])}); "
    f"geoip={len(ips)} codes ({gi_path.stat().st_size:,} B, "
    f"CN={len(ips['CN'])} [v4={len(ips['cn-v4'])}, v6={len(ips['cn-v6'])}])"
)
