## scts_extractor_v1.0

scts_extractor基于：

1. 项目v1.3.0以及之前的 exactor/flow_based 的特征提取方法（虽然称为flow，但本质是提取双向流（stream）的字段与统计特征），可以视为对 exactor/flow_based 的加强

2. 结合tshark命令行工具进行提取TLS以及DNS特征

> tshark是wireshark提供的命令行工具，可以用于解析pcap等文件，并指定提取wireshark官方文档中提供的一些字段
>
> `https://www.wireshark.org/docs/dfref/`
>
> 因此使用该特征提取方法时需要将tshark的路径添加到环境变量！！！

#### 为什么结合scapy和tshark

- scapy
  - scapy本身提取流量TLS特征很麻烦，虽然也有一些基于scapy的TLS解析库，比如scapy-ssl_tls，都是至少5年前更新，最重要的是，社区不活跃
  - 流的划分问题，五元组相同的数据包不一定都属于同一个流（时间间隔很长），用python脚本去划分流就会很复杂，但是流量分析工具比如wrieshark应该会有详细的机制，
- tshark
  - tshark提取特征的效果严重依赖于选择的字段（比如关于TLS，tshark提供了360多个可以提取的字段），且字段值的类型各不相同
  - tshark很慢，即便现在总体特征提取用了三个进程和一个线程池，但tshark提取时间还是拖后腿

#### 问题

- tshark的双向流（stream）的划分必须和原exactor/flow_based 的特征提取的划分一致，并对应
- tshark的结果是单个包为单位，必须用stream_id聚合获得双向流（stream）的特征

#### 设计

1. 用面向对象的方式描述flow（单向流），stream（双向流）、他们的关系以及对pkg_list的字段与统计特征提取类，重写原exactor/flow_based特征提取
   - (一定时间范围内)五元组对应完全相同定义为一个**flow, 单向流**
   - (一定时间范围内)`<ip1:port1>, <ip2:port2>, <protocol>` 的集合相同定义为一个**stream, 双向流**
   - 一个stream中可以有多个flow
2. 使用`tshark -r 1.pcap -T fields -e frame.number -e tcp.stream`获取stream双向流的划分，python解析结果得到stream_id索引的pkg_id列表
3. scapy读取pcap文件，获取数据包列表，结合双向流的划分，创建并实例化stream对象，未来将对这若干个stream对象进行特征提取，获得csv文件
4. 用重写后的原方法提取stream的字段与统计特征
5. 选定tshark提取的字段，构造tshark命令，交给线程获得返回，输出重定向到csv文件
6. 将两个csv文件处理，合并，降维，获取最终的stream特征

> 注意
>
> 提供了对官方文档的爬虫，方便选择字段，
>
> tshark可以提取所有字段，包括但不限于现在使用的tls，dns类别，但需要考虑效率



#### 其他

恶意流量中，加密的很多，这里是通用的流量特征提取方式，“通用”指无论是否加密，都不考虑tls会去加密的payload等

tshark

tshark -r {} -Y "{}" -Y "tcp.stream=={}" -T fields -e ... 获取包的字段以及其他信息(实际tcp.stream是按照双向流来区分的)

tshark -r {} -n -q -z conv,tcp,tcp.stream==2 获取双向流的一些统计特征

tshark -r 1.pcap -T fields -e frame.number -e tcp.stream获取stream和pkgid的对应关系mapping dict



v1.0选择了以下字段，加上原有的72维统计特征，总共记名特征105个，降维后72个

```python
[
  "tcp.stream",
  "tls.handshake",
  "tls.handshake.cert_types",
  "tls.handshake.ciphersuites",
  "tls.handshake.cipher_suites_length",
  "tls.handshake.extensions_reneg_info_len",
  "tls.handshake.extensions_server_name_list_len",
  "tls.handshake.extensions_server_name_type",
  "tls.handshake.certificates_length",
  "tls.handshake.client_point_len",
  "tls.handshake.comp_methods_length",
  "tls.handshake.extensions_length",
  "tls.handshake.extensions_server_name",
  "tls.handshake.extensions_server_name_len",
  "tls.handshake.extensions_server_name_type",
  "tls.handshake.length",
  "tls.handshake.ocsp_response_len",
  "tls.handshake.session_id",
  "tls.handshake.session_ticket_length",
  "tls.handshake.sig_hash_alg",
  "tls.handshake.type",
  "tls.handshake.version",
  "tls.sct.scts_length",
  "tls.sct.sct_timestamp",
  "tls.record.content_type",
  "tls.quic.parameter.type",
  "dns.a",
  "dns.aaaa",
  "dns.cert.algorithm",
  "dns.count.answers",
  "dns.resp.ttl",
  "dns.resp.len",
  "dns.resp.type"
]
```
