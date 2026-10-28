# NAT4 直连

thl 通过双端协调预测，在严格来源过滤、端口顺序分配的 NAT4 网络中建立原生 WebRTC 直连。公网验证覆盖两个发起方向，长测每端完成 1,800 个输入包、180 个可靠控制包及对应回显，数据错误和控制乱序均为零。数据经 ICE、DTLS、SCTP 传输，双方直接交换加密报文。

| 策略 | 适用映射 | 连接方式 |
| --- | --- | --- |
| 协调预测 | 目标 IP 和端口相关映射，顺序分配 | 双方观测公网端口，同步交付预测候选，使用原 ICE socket 建连 |
| 扫描与端口轮换 | 目标 IP 相关映射，顺序分配 | 扫描端固定 socket，轮换端寻找匹配端口，随后交接给原生 WebRTC |

Python 负责观测与协调，C++ 负责认证传输和数据校验。两种策略共用双向输入通道、可靠控制通道与逐包校验。

## 验证

| 论证目标 | 验证依据 |
| --- | --- |
| 公网直传 | 所选候选与网关记录的双方数据端点一致，流量分类确认 DTLS 应用数据 |
| 双向数据完整性 | 公网长测逐包校验输入、可靠控制和回显，中途暂停发送 15 秒后恢复 |
| 扫描后的连接交接 | 隔离网络中完成端口轮换、重绑、认证建连与双向数据传输 |
| 对端身份验证 | 错误证书指纹被 DTLS 拒绝 |
| 预测与映射的一致性 | 标准候选、偏移端口和随机分配对照用于界定预测策略的适用条件 |
| 资源生命周期 | 结束时释放进程、网关映射与隔离网络 |

[结构化结果](results.json)记录网络条件、逐端计数、验证职责和源码身份。数据包为 96 字节协议测试载荷。网络由 Linux 隔离网关构造，公网验证跨两台服务器，试验内映射固定；暂停发送时 ICE 保活持续运行。上述结果对应连接原型和所列映射条件。

## 构建与运行

构建依赖 C++17、CMake 3.21+ 和 OpenSSL 开发文件。固定 libdatachannel 及其子模块版本：

```sh
git clone https://github.com/paullouisageneau/libdatachannel.git .local/libdatachannel
git -C .local/libdatachannel checkout bdc5ff28e9d3b863144c94a677ecf5bf043aaf15
git -C .local/libdatachannel submodule update --init --recursive
cmake -S nat4 -B build -DLIBDATACHANNEL_SOURCE="$PWD/.local/libdatachannel" -DCMAKE_BUILD_TYPE=Release
cmake --build build --target thl-native-peer -j2
```

隔离网络验证使用 Linux root、Python 3.12+、iproute2 和 TUN。每次运行使用独立输出目录：

```sh
sudo python3 nat4/run_lab.py --native "$PWD/build/thl-native-peer" --cases double4 --strategy next-port --output artifacts/prediction
sudo python3 nat4/run_lab.py --native "$PWD/build/thl-native-peer" --cases double4-address --strategy nat22 --output artifacts/scan
```

公网验证在两个 SSH 端点部署 `nat4` 目录和原生程序。配置包含 `stun` 观察端点，以及 `a`、`b` 两端对象：

| 字段 | 内容 |
| --- | --- |
| `ssh` | SSH 参数数组，例如 `["server-a"]` |
| `directory` | 远端 `nat4` 目录的绝对路径 |
| `native` | 远端原生程序的绝对路径 |
| `outputRoot` | 已存在的远端输出根目录 |
| `external` | 主机绑定 IPv4 地址 |
| `public` | 对外 IPv4 地址 |
| `base` | UDP 映射池起点，例如 40000、50000 |

`stun` 使用 `IPv4:端口` 格式。运行器通过 SSH 交换信令，数据走双方 UDP 端点；隔离网络内的策略路由与进程随本轮结束释放。

```sh
python3 nat4/live_native_lab.py control --config .local/hosts.json --output artifacts/public --offer b --packets 1800 --idle-seconds 15
```
