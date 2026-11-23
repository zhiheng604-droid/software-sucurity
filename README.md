# NetLens · 课程实验 1A

NetLens 是一个桌面网络嗅探器。它通过 libpcap 或 Npcap 读取网卡及捕获文件，通过 Tkinter 显示协议字段、原始字节和 TCP 双向流。安装 Python（带 Tk）和平台抓包库后即可运行，无需第三方 Python 包。

## 快速开始

```sh
python3 main.py --demo
python3 main.py --list
```

- **离线查看**：点击「加载课程样本」或「打开 PCAP」。样本使用文档示例地址，无需抓包权限。
- **实时抓包**：选择接口，填写可选的 BPF 表达式后点击「开始抓包」。macOS 需要有权限打开 `/dev/bpf*`，Linux 需要平台配置的抓包权限。Windows 安装 Npcap 后用 `py main.py` 启动。
- **安全复现**：macOS 选 `lo0`，填 `(tcp port 18765) or (udp and host 127.0.0.1)` 并开始抓包。另开终端运行 `python3 demo_traffic.py talk`。它只在 `127.0.0.1` 上产生 HTTP 和 UDP 流量。
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

明文 HTTP/1.x 分类要求在一个捕获 TCP 段内看到完整首行。当前版本支持常见链路类型、有限协议字段和部分 PCAPNG 格式，不做 TCP 字节流重组、TLS 解密或多接口同时采集。Windows Npcap 和 Linux 实机尚未验证。
