# NetLens · 课程实验 1A

NetLens 是一个桌面网络嗅探器。它通过 libpcap 或 Npcap 读取网卡及捕获文件，通过 Tkinter 显示协议字段、原始字节和 TCP 双向流。安装 Python（带 Tk）和平台抓包库后即可运行，无需第三方 Python 包。

## 快速开始

```sh
python3 main.py --demo
python3 main.py --list
```

- **离线查看**：点击「加载课程样本」或「打开 PCAP」。样本使用文档示例地址，无需抓包权限。
- **打开失败时保留旧结果**：尝试打开新文件或新网卡时，先检查来源及 BPF。打开失败时仍可查看、筛选和导出上一轮记录。
- **导出**：停止抓包或读完文件后，点击「导出 PCAP…」。导出的是当前缓存里全部保留的记录，包括暂时被显示过滤隐藏的行。导出的文件可用「打开 PCAP…」重新读取。
- **实时抓包**：选择接口，填写可选的 BPF 表达式后点击「开始抓包」。macOS 需要有权限打开 `/dev/bpf*`，Linux 需要平台配置的抓包权限。Windows 安装 Npcap 后用 `py main.py` 启动。
- **安全复现**：macOS 选 `lo0`，填 `(tcp port 18765) or (udp and host 127.0.0.1)` 并开始抓包。另开终端运行 `python3 demo_traffic.py talk`。它只在 `127.0.0.1` 上产生 HTTP 和 UDP 流量。
- **录制进程关联**：用 `python3 demo_traffic.py talk --hold 20` 保持 HTTP 连接打开 20 秒。回到 NetLens，点击「TCP 流…」→「读取本机进程」，再从「全部进程」下拉框选对应进程。
- **独立验收**：用有抓包权限的账户运行 `python3 demo_traffic.py live-check`，输出报文分类、双向载荷、进程快照命中和停止延迟的 JSON。例如在 macOS 可运行 `sudo /usr/bin/env PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 demo_traffic.py live-check`。
- **重新生成固定样本**：`python3 demo_traffic.py fixture`。

## 过滤与 TCP 流

BPF 在每次打开采集来源时编译和安装，例如 `tcp port 18765`。显示协议只隐藏当前保留的行。TCP 过滤包含标记为 HTTP 的 TCP 段。双击「TCP 流」窗口中的某行可跟踪该流，或在主界面使用「跟踪所选包」。

TCP 流统计基于当前保留窗口。载荷字节含重传，不表示应用层实际交付量。同一端点对在窗口内重复使用时会合并统计。macOS/Linux 的进程按钮通过 `lsof` 查当前可见的本机套接字，短连接、已关闭连接和当前账号不可见的连接可能无法匹配。Windows 进程匹配待移植。

## 文件

| 文件 | 作用 |
|---|---|
| `main.py` | Tk 界面、会话控制和有界缓存 |
| `capture.py` | libpcap/Npcap、BPF、实时和离线数据源 |
| `packet.py` | 链路层、IP、传输层和 HTTP 首行解码 |
| `flows.py` | TCP 流统计与当前可见的本机进程快照 |
| `demo_traffic.py` | 本地流量与可复现的样本生成 |
| `netlens_demo.pcap` | 含 15 条记录的固定课程样本 |

## 扩展验证

- `python3 verify_offline.py` 检查两个样本、导出往返和不完整文件的启动行为。用「打开 PCAP…」载入 `netlens_http_split.pcap`，选 HTTP 后点击第 6 帧。协议详情里点击「帧 #4」会打开对应的十六进制页，再点「回到重组帧」可回第 6 帧。来源帧被缓存淘汰时会显示不可查看。
- `python3 demo_traffic.py split-fixture` 重建跨段样本。
- `sudo /usr/bin/python3 -B verify_extended.py all --duration 2 --trials 3` 在 macOS 回环上验证跨段请求与响应、两客户端 PID 筛选，并完成 12 轮 UDP 性能对照。该脚本只使用回环接口和本机临时端口。可加 `--output result.json` 保存原始记录。

HTTP/1.x 首行重组按方向最多跟踪 512 字节，识别成功时列出来源帧。支持已看到 SYN 时的乱序、重传和序号回绕。连接中途开始采集时，只能从能识别的首行前缀开始。保留现有单段检测用于后续请求。当前版本不做完整 TCP 字节流或 HTTP 消息体重组、TLS 解密和多接口同时采集。Windows Npcap 和 Linux 实机尚未验证。
