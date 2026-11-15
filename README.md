# beacon-hunter

内网信标（beaconing）检测采集器：UDP 接收交换机导出的 **NetFlow v9（RFC 3954）** 与 **IPFIX（RFC 7011）** 流量记录，按源/目的主机对做周期性回连检测，终端实时刷新并可导出 JSON。

**纯 Rust 标准库实现，零外部 crate**，离线环境可直接 `cargo build --release`。

## 快速开始

```bash
# 1. 编译
cargo build --release

# 2. 启动采集器（默认监听 0.0.0.0:2055，每 30s 自动导出 beacons.json）
./target/release/beacon-hunter -b 0.0.0.0:2055 -o beacons.json

# 3. 另开终端，用内置生成器打混合测试流量（NF9 + IPFIX、延迟模板、4 个信标）
python3 -I tools/gen_flows.py --target 127.0.0.1:2055
```

TTY 下每秒重绘仪表盘；输出被管道/重定向时自动降级为每秒一行的摘要日志（适合 journald/文件）。
交互命令：`q` 退出并导出，`e` 立即导出；`-d 90s` 可定时退出。

## 检测原理与阈值权衡

记录按**完整五元组** `(src_ip, dst_ip, src_port, dst_port, protocol)` 聚合，取每条流的结束时间戳排序后计算相邻间隔。判定一个对为 `BEACON` 需**同时**满足：

| 条件 | 阈值 | 取舍理由 |
|---|---|---|
| 最少样本 | ≥ 6 个时间戳（5 个间隔） | 样本太少时任何间隔序列都可能“看起来很齐”，误报率不可控 |
| 中位间隔范围 | 5 s … 2 h | 下限排除秒级轮询/突发闲聊；上限排除近乎休眠的偶发连接 |
| 稳健抖动 `MAD/median`（×1.4826 归一化） | ≤ **35%** | MAD 是稳健统计量，少量丢包/漏采不会把它拉大；35% 能覆盖典型恶意软件 sleep 抖动，又明显低于随机流量 |
| 综合评分 | ≥ **60/100** | 稳健抖动 60 分 + 经典变异系数 CV 25 分 + 样本置信度 15 分（20 个间隔饱和），双指标互相纠偏 |

设计上的两个关键容错：

- **容忍抖动**：用中位数绝对偏差（MAD）而非标准差。一次漏报产生的双倍间隔只会污染少数样本，MAD 基本不受影响；同时保留经典 CV 作为第二信号，防止 MAD 对宽分布过度宽容。
- **容忍漏采**：滚动窗口保留最近 256 个时间戳，MAD 可吸收约 30% 的污染样本；集成测试里含一个故意制造的 2 倍间隔，仍可正确检出。

未达评分线但通过抖动门限的对标记为 `candidate`；样本不足为 `warming-up`；间隔越界或抖动超标为 `aperiodic`。每个判定都在 JSON 的 `reasons` 字段给出可解释依据。

### 正常心跳排除

默认白名单（可用 CLI 覆盖）：

- 端口 **53（DNS）、123（NTP）** —— 双向匹配
- 协议 **1（ICMP）** —— 整协议排除

白名单对**照常统计和展示**（仪表盘里标 `whitelisted`，评分也照算），只是永远不会给 BEACON 判定，方便事后审计“如果不排除它会有多像信标”。

```bash
./target/release/beacon-hunter --whitelist-ports 53,123,5353 --whitelist-protos 1
```

## 协议处理

- **模板按 `(导出器 IP, 观察域 ID)` 分别缓存**：两台交换机复用同一模板 ID 但字段布局不同时互不干扰（生成器与集成测试专门构造了这种场景）。
- **模板晚到先缓存**：数据 flowset 引用未知模板时整段缓冲，模板到达后按原始报文的导出时间上下文回放解析。缓冲有每域 2048 / 全局 16384 的上限，溢出丢弃最旧数据并计数，防止异常导出器耗尽内存。
- 支持 NF9 相对 sysUpTime 时间戳（IE 21/22）与 IPFIX 绝对毫秒时间戳（IE 152/153）、IPv4/IPv6 地址、IPFIX 企业位（E-bit）字段与变长（0xffff）字段。
- 解析器只抽取检测所需 IE（五元组、字节数、时间戳），未知 IE 按模板长度跳过。

## JSON 导出

`beacons.json` 含采集器计数（报文/flowset/缓冲/回放/解码错误）、信标总数、每个对的完整指标：

```json
{
  "generated_ms": 1700000600000,
  "uptime_ms": 60000,
  "collector": { "packets": 24, "records": 468, "records_buffered": 5,
                 "records_replayed": 21, "decode_errors": 0, "...": "..." },
  "beacon_count": 4,
  "pairs": [
    {
      "src_ip": "10.10.0.8", "dst_ip": "198.51.100.40",
      "src_port": 40000, "dst_port": 8080, "protocol": 6,
      "records": 18, "bytes": 9120, "last_seen_ms": 1700001560000,
      "metrics": {
        "verdict": "BEACON", "whitelisted": false,
        "samples": 18, "intervals": 17,
        "median_interval_ms": 91700, "robust_cv": 0.035,
        "cv": 0.030, "score": 94.9,
        "reasons": ["period ~91.7s, robust jitter 3.5%, score 95"]
      }
    }
  ]
}
```

写文件走 `tmp + rename` 原子替换，读取方不会看到半截文件。

## 测试流量生成器

`tools/gen_flows.py` 仅用 Python 标准库按线协议手工构造报文（建议始终以 `python3 -I` 运行，隔离当前目录）：

| 角色 | 流量特征 |
|---|---|
| 信标 A（NF9） | 60s 周期 ±8s 抖动，26 次 |
| 信标 B（IPFIX） | 120s 周期 ±30s 抖动，含 1 次漏采（2 倍间隔） |
| 信标 C（IPFIX） | 45s 周期 ±5s 抖动，30 次 |
| 信标 D（IPFIX，模板 258 延迟到 t=200s） | 90s 周期 ±6s 抖动 |
| NTP / DNS / ICMP | 规则心跳，验证白名单 |
| 随机闲聊 | LCG 随机间隔，验证不误报 |

默认开启 `--late-templates`（NF9 模板压到 t=150s、IPFIX 258 压到 t=200s 才发）；
`--no-late-templates` 切换为模板先发；`--pace --speed 60` 按压缩时间轴匀速发送；
`--dry-run` 只组包不发送。

## 测试

```bash
cargo test          # 16 个测试：协议解析/晚到回放/域隔离/变长字段/检测阈值
cargo clippy --all-targets
cargo fmt --check
```

## 已知边界

- 仅支持 UDP 传输（SCTP/TCP 上的 IPFIX 未实现，机房交换机 UDP 导出为主流形态）。
- 不做 NetFlow v5/IPFIX options 数据记录的业务解读（options 模板可解析缓存，选项数据按通用模板解码，缺五元组时计入 `records_incomplete`）。
- std 无法捕获 SIGINT，Ctrl-C 时依赖最近一次自动导出兜底；`q`/`e` 与 `-d` 退出路径均保证落盘。
