# honk-rules-dat

为 `honk`（桌面端 & Android 端）自动融合并深度去重构建的 `geosite.dat` / `geoip.dat` 云端仓库。

## 融合上游源（6 源）

1. [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)（基础 `geosite.dat` / `geoip.dat`，亦为 Surfing 全部 `.mrs` 的上游）
2. [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)（完整 `*_Classical.yaml` / `*_Domain.yaml` + `*_IP.yaml`）
3. [GitMetaio/Surfing](https://github.com/GitMetaio/Surfing)（`AWAvenue-Ads-Rule` 去广告库、`自定义规则.list` IMS/VoWiFi 放行、`WebRTC.list`）
4. [Hackl0us/GeoIP2-CN](https://github.com/Hackl0us/GeoIP2-CN)（`CN-ip-cidr.txt` IPv4）
5. [ispip.clang.cn/all_cn_ipv6.txt](https://ispip.clang.cn/all_cn_ipv6.txt)（大陆运营商 IPv6）
6. [X-Shelby/geoip](https://github.com/X-Shelby/geoip)（`cn_v4.txt` + `cn_v6.txt`）

## 自动发布计划

- **GitHub Actions**：每天北京时间 **`00:00`** 与 **`12:00`**（UTC `0 4,16 * * *`）自动拉取 6 个上游源、执行 Trie 域名覆盖去重 + CIDR 超网聚合 + 跨桶冲突扣减 + 完整性校验，并自动覆盖发布到 `latest` Release（附 `.sha256sum`）。
- 也可在 Actions 页面点击 `Run workflow` 随时手动触发。

## 固定拉取地址（`honk` `assets.geodata`）

- `geosite.dat`: `https://github.com/Wcoom/honk-rules-dat/releases/download/latest/geosite.dat`
- `geoip.dat`: `https://github.com/Wcoom/honk-rules-dat/releases/download/latest/geoip.dat`
- 校验文件（`honk` 自动拉取验证）：同名 `.sha256sum`
