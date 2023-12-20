'''
Description: 
version: 
Author: zlx
Date: 2023-12-19 19:58:37
LastEditors: zlx
LastEditTime: 2023-12-20 12:56:14
'''
import csv
from extractor.scts_extractor.traffic_description.t_flow import CreateTcpFlow
from extractor.scts_extractor.traffic_description.t_stream import CreateTcpStream
from extractor.scts_extractor.traffic_description.feature_make import TcpStreamFeatureMake
from extractor.scts_extractor.utils import get_mapped_pkgs
'''
根据tshark划分的stream用scapy提取stream的字段和统计特征
'''
def create_statistic_feature(pcap_file_path, output_csv_path):
    pcap_path = pcap_file_path
    # 根据pcap文件获取用stream id索引的包列表
    stream_pkg_map_dict = get_mapped_pkgs(pcap_path)
    
    index_stream_map = {}
    for key, value in stream_pkg_map_dict.items():
        sub_pkt_list = value
        # 创建flow对象
        flow_creator = CreateTcpFlow()
        flow_lst = flow_creator.create_from_packets(sub_pkt_list)
        
        # 创建stream对象
        stream_creator = CreateTcpStream()
        stream_lst = stream_creator.create_from_flows(flow_lst)
        if len(stream_lst) != 1:
            print('tshark may divide stream getting wrong')
            return None
        index_stream_map[key] = stream_lst[0]
    
    print('(statis report) stream num: ', len(index_stream_map))
    
    # 提取双向流的特征
    maker = TcpStreamFeatureMake()
    # 打开CSV文件进行写入  
    with open(output_csv_path, mode='w', newline='') as file:
        writer = csv.writer(file, delimiter=',')
        # 获取字段和统计特征名字
        feature_names = maker.get_feature_names()
        # 加入stream_id字段
        feature_names.insert(0, 'stream_id')
        writer.writerow(feature_names)
        
        for i, tcp_stream in index_stream_map.items():
            # 获取字段和统计特征值
            its_feature = maker.get_feature(tcp_stream)
            # 加入stream_id字段值
            its_feature.insert(0, i)
            writer.writerow(its_feature)
    return


# if __name__ == "__main__":
#     print()
    
#     create_statistic_feature('1.pcap', './output.csv')