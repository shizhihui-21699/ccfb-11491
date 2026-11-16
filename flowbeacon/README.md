# flowbeacon

机房出口 NetFlow v9 / IPFIX 采集 + C2 信标（beacon）检测器。零外部依赖，纯 std。

## 用法

```bash
cargo build --release

# 采集端：UDP 9995 收流，终端实时刷新，Ctrl-C 退出并输出 JSON
./target/release/flowbeacon listen --bind 0.0.0.0:9995 --export beacons.json

# 测试流量：向采集端发送 v9 + IPFIX 报文（噪声 + NTP/DNS 心跳 + 3 个带抖动信标）
./target/release/flowbeacon gen --target 127.0.0.1:9995 --protocol both --beacons 3

# 模板晚到演练：先发数据后发模板，验证暂存回放
./target/release/flowbeacon gen --target 127.0.0.1:9995 --late-template
```

## 实现要点

- **模板缓存**：按 `(导出器地址, 观察域/SourceID, 模板ID)` 三元组分别缓存，v9 与 IPFIX 共用一套元素号语义。
- **模板晚到**：Data Set 到达时无模板则按缓存键暂存原始字节（每键上限 64 个，防内存膨胀），模板到达后回放解析。
- **五元组 + 字节数**：从模板字段提取 src/dst IP、端口、协议、octetDeltaCount；时间戳优先用记录里的 `flowStartMilliseconds`，v9 的相对时间戳（FIRST_SWITCHED）用包头 `unix_secs - sys_uptime` 换算，都没有则退化为采集端接收时间。
- **信标检测**：按 `(源IP, 目的IP, 目的端口)` 聚合连接时刻，对相邻间隔计算均值/标准差/CV。

## 判定阈值（默认值，均可命令行覆盖）

| 参数 | 默认 | 理由 |
|---|---|---|
| `--min-count` | 8 | CV 在样本 <8 时统计上不稳定，宁缺毋滥 |
| `--max-cv` | 0.25 | 容忍 ±25% 抖动；真实 C2 抖动一般 <15%，>30% 基本不是信标 |
| `--min-span` | 4.0 | 首末跨度至少覆盖 4 个周期，防止突发流量误判 |
| `--max-byte-cv` | 0.5 | 信标心跳载荷大小稳定，字节数波动大则降权排除 |
| `--exclude-ports` | 53,123 | DNS/NTP 正常心跳直接不进入检测；组播/广播地址同样排除 |

评分 = 0.6×周期性 + 0.25×样本量 + 0.15×字节一致性，≥0.7 终端红色高亮。
