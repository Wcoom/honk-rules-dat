# honk-rules-dat

为 `honk`（桌面端 & Android 端）自动融合并深度去重构建的 `geosite.dat` / `geoip.dat` 云端仓库。

## 融合上游源（7 源）

1. [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)（基础 `geosite.dat` / `geoip.dat`，亦为 Surfing 全部 `.mrs` 的上游）
2. [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)（完整 `*_Classical.yaml` / `*_Domain.yaml` + `*_IP.yaml`）
3. [GitMetaio/Surfing](https://github.com/GitMetaio/Surfing)（`AWAvenue-Ads-Rule` 去广告库、`自定义规则.list` IMS/VoWiFi 放行、`WebRTC.list`）
4. [Hackl0us/GeoIP2-CN](https://github.com/Hackl0us/GeoIP2-CN)（`CN-ip-cidr.txt` IPv4）
5. [ispip.clang.cn/all_cn_ipv6.txt](https://ispip.clang.cn/all_cn_ipv6.txt)（大陆运营商 IPv6）
6. [X-Shelby/geoip](https://github.com/X-Shelby/geoip)（`cn_v4.txt` + `cn_v6.txt`）
7. [IPinfo Lite](https://ipinfo.io/lite) 免费国家数据库（`ipinfo_lite.csv.gz`，通过 Actions Secret `IPINFO_TOKEN` 拉取，仅按国家码 `country_code == CN` 提取中国 IPv4 + IPv6 参与超网聚合与去重）

## 自动发布计划

- **GitHub Actions**：每天北京时间 **`00:00`** 与 **`12:00`**（UTC `0 4,16 * * *`）自动拉取 7 个上游源、执行 Trie 域名覆盖去重 + CIDR 超网聚合 + 跨桶冲突扣减 + 完整性校验，并同步发布到两个通道：
  1. **直链通道（`release` 单提交 orphan 分支，HTTP 200 无重定向，供 `honk` 直接拉取）**：
     - `geosite.dat`: `https://raw.githubusercontent.com/Wcoom/honk-rules-dat/release/geosite.dat`
     - `geoip.dat`: `https://raw.githubusercontent.com/Wcoom/honk-rules-dat/release/geoip.dat`
     - jsDelivr CDN 镜像：`https://fastly.jsdelivr.net/gh/Wcoom/honk-rules-dat@release/{geosite,geoip}.dat`
     - 校验文件（`honk` 自动拉取验证）：同名 `.sha256sum`
  2. **Release 通道（`latest` Release，方便网页/手动下载）**：
     - `https://github.com/Wcoom/honk-rules-dat/releases/tag/latest`
- 也可在 Actions 页面点击 `Run workflow` 随时手动触发。

> 注：`honk` 的 `geodata` 下载器刻意不跟随 HTTP 302 重定向，因此 `assets.geodata` 必须配置 `raw.githubusercontent.com/.../release/...`（或 `fastly.jsdelivr.net`）直链，不能填写会 302 跳转的 GitHub Releases 下载地址。
