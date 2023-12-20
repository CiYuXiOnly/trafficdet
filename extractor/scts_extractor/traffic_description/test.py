'''
Description: 
version: 
Author: zlx
Date: 2023-12-18 19:47:41
LastEditors: zlx
LastEditTime: 2023-12-20 15:08:33
'''
import csv
from .t_flow import CreateTcpFlow
from .t_stream import CreateTcpStream
from .feature_make import TcpStreamFeatureMake, FeatureMakeBasePkgList
from scapy.all import rdpcap

def test1():
    filename = "./test.pcap"
    packets = rdpcap(filename)
    
    flow_creator = CreateTcpFlow()
    tcp_flow_lst = flow_creator.create_from_packets(packets)
    print(len(tcp_flow_lst))
    print(len(flow_creator.get_tuple_flow_dict()))
    # for tcp_flow in tcp_flow_lst:
    #     print(tcp_flow.src_ip)
    #     print(len(tcp_flow.packets))
    #     print()
        
    stream_creator = CreateTcpStream()
    stream_lst = stream_creator.create_from_flows(tcp_flow_lst)
    print(len(stream_lst))

    testflow = stream_lst[0].flows[0]
    print(len(testflow.packets))
    print(testflow)
    
    # stream划分fwd_flows和bwd_flows
    print(len(stream_lst[0].flows))
    fwd_flows, bwd_flows = stream_lst[0]._divide_flows(stream_lst[0].flows, '13.107.246.73')
    print(len(fwd_flows))
    print(len(bwd_flows))
    
    # stream划分fwd_flows和bwd_flows, API
    print()
    stream_lst[0].get_divided_flows_in_stream()
    print(len(stream_lst[0].fwd_flows))
    print(len(stream_lst[0].bwd_flows))
    print(stream_lst[0])
    
    # stream划分为上行包列表和下行包列表, API
    print('-----')
    index = 1
    p = stream_lst[index].get_all_pkgs_from_stream()
    p1, p2 = stream_lst[index].get_divided_pkgs_in_stream()
    p.sort(key=lambda pkt: pkt.time)
    p1.sort(key=lambda pkt: pkt.time)
    p2.sort(key=lambda pkt: pkt.time)
    print(len(p))
    print(len(p1))
    print(len(p2))
    print(stream_lst[index])
    print(FeatureMakeBasePkgList().packet_hdr_len(p2))
    print(FeatureMakeBasePkgList().packet_hdr_len(p1))
    print(FeatureMakeBasePkgList().packet_hdr_len(p))
    return


def test2():
    '''
    给一个tcp stream对象列表，将提取到的特征写入csv文件
    '''
    maker = TcpStreamFeatureMake()
    
    filename = "../test.pcap"
    packets = rdpcap(filename)
    flow_creator = CreateTcpFlow()
    tcp_flow_lst = flow_creator.create_from_packets(packets)
    stream_creator = CreateTcpStream()
    stream_lst = stream_creator.create_from_flows(tcp_flow_lst)

    # 打开CSV文件进行写入  
    with open('./output.csv', mode='w', newline='') as file:
        writer = csv.writer(file, delimiter=',')
        feature_names = maker.get_feature_names()
        writer.writerow(feature_names)
        for tcp_stream in stream_lst:
            one_record = maker.get_feature(tcp_stream)
            writer.writerow(one_record)

if __name__ == '__main__':
    print()
    
    test1()
    
    # test2()