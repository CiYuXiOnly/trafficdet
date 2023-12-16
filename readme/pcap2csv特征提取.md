## 特征提取

### 特征提取说明

现有的一些流量以及入侵检测数据集大多都是使用现有工具或其他编程语言来实现特征提取（pcap to csv）的

虽然可以考虑融合包、流、会话的特征提取方式，但是暂时不考虑，难以直接集成在该项目中的工具提取特征也暂时不考虑

### 实验数据

实验数据：CIC-IDS 2017 pcap数据集中的一部分（大约几个G）



### scapy基于包的特征提取

##### 概述

pcap转csv

csv提取特征得到csv （10个特征）---已经弃用 --改为提取23特征

原（10个特征）参考`github.com/iotsecty/malicious_traffic_detection_platform`

新23特征

```
基于包的特征提取主要是
标志位，比如syn，ack；
字段，比如seq_num，checksum，icmptype，对该列标准化，或类别编码
内容，比如tcp_payload，udp_payload，提取了协议关键字，连接成表示包的协议层次的字符串，然后类别编码
时间，计算相对第一个包的相对时间
ip端口，组合筛选，类别编码
```

```
['layerInfo', 'len', 'protocol', 'tcp_seq_number', 'tcp_ack_number',
       'tcp_window_size', 'tcp_flags', 'tcp_header_length', 'tcp_checksum',
       'tcp_urgent_pointer', 'udp_length', 'udp_checksum', 'icmp_type',
       'icmp_code', 'icmp_checksum', 'icmp_id', 'icmp_seq', 'icmp_payload',
       'src', 'dst', 'RelativeSeconds', 'tcp_pay_load_action',
       'udp_pay_load_action']
```
封装
```python
# main API CsvfeatureExtractOp()
# main API Pcap2csvOp()
op1 = Pcap2csvOp(pcapfilepath, csvfilepath, isadded)
# pcap生成csv
op1.generateCSV()

op2 = CsvfeatureExtractOp(csvpath, featured_csvpath, isadded)
# 对生成的csv进行特征提取
op2.extract()
```

##### 实验结果

训练效果Test set: Average loss: 0.6894, Accuracy: 61135/120000 (51%)

预测的计算概率都基本在50概率左右，区分性差

原因分析：即便已经对包做了一定语义提取（比如提取协议关键字，类别编码），但是不够



### scapy基于流的特征提取

##### 概述

pcap提取流特征得到csv（72个特征）

参考`github.com/jiangph1001/flow-feature`

```
['fiat_mean', 'fiat_min', 'fiat_max', 'fiat_std', 'biat_mean',
       'biat_min', 'biat_max', 'biat_std', 'diat_mean', 'diat_min', 'diat_max',
       'diat_std', 'duration', 'fwin_total', 'fwin_mean', 'fwin_min',
       'fwin_max', 'fwin_std', 'bwin_total', 'bwin_mean', 'bwin_min',
       'bwin_max', 'bwin_std', 'dwin_total', 'dwin_mean', 'dwin_min',
       'dwin_max', 'dwin_std', 'fpnum', 'bpnum', 'dpnum', 'bfpnum_rate',
       'fpnum_s', 'bpnum_s', 'dpnum_s', 'fpl_total', 'fpl_mean', 'fpl_min',
       'fpl_max', 'fpl_std', 'bpl_total', 'bpl_mean', 'bpl_min', 'bpl_max',
       'bpl_std', 'dpl_total', 'dpl_mean', 'dpl_min', 'dpl_max', 'dpl_std',
       'bfpl_rate', 'fpl_s', 'bpl_s', 'dpl_s', 'fin_cnt', 'syn_cnt', 'rst_cnt',
       'pst_cnt', 'ack_cnt', 'urg_cnt', 'cwe_cnt', 'ece_cnt', 'fwd_pst_cnt',
       'fwd_urg_cnt', 'bwd_pst_cnt', 'bwd_urg_cnt', 'fp_hdr_len', 'bp_hdr_len',
       'dp_hdr_len', 'f_ht_len', 'b_ht_len', 'd_ht_len']
```

封装

```python
# main API FlowProcess()
'''
在pcap模式下，来自同一个pcap的所有数据包会被视为属于同一个流，csv中的头两个字段为pcap文件名和目的IP数量
在flow模式下，相同五元组的数据包会被视为同一个流，头两个字段为src和dst。
'''
config = {  
        "run_mode": '',  # 'pcap' or 'flow'
        "pcap_loc": '',  # pcap dir
        "pcap_name": '',  # pcap file name
        "csv_path": '',  # csv file path/name
        "print_colname": True,  
        "read_all": False
    }
p = FlowProcess(config)
p.extract_flow_feature_from_pcap()
```

##### 实验结果

训练效果Test set: Average loss: 0.3810, Accuracy: 303/346 (88%)

预测显著偏向良性，但是有很好的区分性

恶意样本检测属于良性的计算概率结果75-80%，而良性样本检测属于良性的计算概率结果大多在90%以上，设置如0.85的阈值下可以很好区分



### scapy基于会话的特征提取

##### 概述

得到23个特征

参考`github.com/Dan-Rdd/Feature-Extraction`

```
["src_ip", "dst_ip", "sport", "dport"]
['type', 'Avg_syn_flag', 'Avg_urg_flag', 'Avg_fin_flag', 'Avg_ack_flag',
       'Avg_psh_flag', 'Avg_rst_flag', 'Duration_window_flow',
       'Avg_delta_time', 'Min_delta_time', 'Max_delta_time',
       'StDev_delta_time', 'Avg_pkts_lenght', 'Min_pkts_lenght',
       'Max_pkts_lenght', 'Total_pkts_Length', 'StDev_pkts_lenght',
       'Avg_small_payload_pkt', 'Avg_payload', 'Min_payload', 'Max_payload',
       'StDev_payload', 'Num Packets']
['label']
```

封装

```python
# main API SessProcess()

op = SessProcess()
op.extract_sess_feature_from_pcap(pcap_path="", 
                                    csv_path=",
                                    label='0',
                                    per_print=10)
```

##### 实验结果

训练效果Test set: Average loss: 0.5840, Accuracy: 1215/1669 (73%)

预测显著偏向良性，区分性差，良性样本和恶意样本的计算概率大概在70-75%之间，难以区分

原因分析：对训练集要求高，否则提取不出多少很有意义的会话，对预测样本要求高，要求会话长时间保留，否则一次会话相当于一个流，并且特征还没有那么细粒度



### 基于tshark的加密流特征提取

##### 概述

工具提取pcap文件中，tshark是比较简单易用的命令行工具，可以用subprocess去获取命令的执行结果

这里参考了论文：[[2208.03862\] DeepTLS: comprehensive and high-performance feature extraction for encrypted traffic (arxiv.org)](https://arxiv.org/abs/2208.03862)

文章中是对加密流量特征提取的工具包，其中给出的开源工具`https://github.com/zliucd/pysharkfeat`利用python使用tshark对加密流量进行特征提取，转换为json文件，并且实践发现，对tls过滤器的特征提取，对于tcp过滤器也是可以正常运行的

对该开源工具优化：

修复在windows上的命令执行BUG；os.system重写；修改支持单个pcap文件，支持非加密流量的特征提取，对json文件转换为csv文件，实验特征提取的效果

提取特征后的tls流或tcp流共45个特征（包括源目的ip和端口）**但是该方法提取特征非常慢**

```
['stream_index', 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'timestamp', 'duration', 'pkt_total_num', 'pkt_up_num', 'pkt_down_num', 'pkt_len_total_sum', 'pkt_len_total_max', 'pkt_len_total_min', 'pkt_len_total_mean', 'pkt_len_total_std', 'pkt_len_up_sum', 'pkt_len_up_max', 'pkt_len_up_min', 'pkt_len_up_mean', 'pkt_len_up_std', 'pkt_len_down_sum', 'pkt_len_down_max', 'pkt_len_down_min', 'pkt_len_down_mean', 'pkt_len_down_std', 'pkt_iat_total_sum', 'pkt_iat_total_max', 'pkt_iat_total_min', 'pkt_iat_total_mean', 'pkt_iat_total_std', 'pkt_iat_up_sum', 'pkt_iat_up_max', 'pkt_iat_up_min', 'pkt_iat_up_mean', 'pkt_iat_up_std', 'pkt_iat_down_sum', 'pkt_iat_down_max', 'pkt_iat_down_min', 'pkt_iat_down_mean', 'pkt_iat_down_std', 'bd_std', 'bd_entropy', 'mean_mc_len', 'mean_mc_time', 'mean_bd_dist']
```

封装

```python
# main class API TsharkExtractorProcess()

tp = TsharkExtractorProcess(pcap_path='upload/1.pcap', # dir or path
                            output_dir='data/featured_csv/',
                            saved_file_type='csv') # json or csv
# if all, pcap_path should be a dir
# "tls" or "ssl" or "tcp", 前两者可以视为等价
tp.extract(target="tls", isall=False)
```

##### 实验结果

训练 Test set: Average loss: 0.6747, Accuracy: 110/185 (59%)

比较显著偏向非恶意，概率都是57左右，没有较强的区分效果

