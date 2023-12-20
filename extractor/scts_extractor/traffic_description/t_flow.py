'''
Description: 
version: 
Author: zlx
Date: 2023-12-18 18:39:31
LastEditors: zlx
LastEditTime: 2023-12-19 16:25:50
'''

from scapy.all import *
from scapy.all import TCP, IP

import hashlib
'''
(一定时间范围内)五元组对应完全相同定义为一个flow, 单向流
'''
class Flow:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
        '''
        五元组
        '''
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = []
    
    def add_packet(self, packet):
        self.packets.append(packet)
    
    def get_all_pkgs_from_flow(self):
        return self.packets
    
    def __repr__(self):
        return "{}:{} -> {}:{}, totally {} packets".format(self.src_ip,
                                             self.src_port,self.dst_ip,
                                             self.dst_port,len(self.packets))    

'''
tcp flow, 继承自flow
'''
class TcpFlow(Flow):
    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
        super().__init__(src_ip, src_port, dst_ip, dst_port, protocol)
        self.protocol = 'tcp'

    # 重写父类的add_packet方法
    def add_packet(self, packet):
        # 判断是否是 IP 包
        if IP in packet:
            ip_packet = packet[IP]
            # 判断是否是 TCP 包
            if TCP in ip_packet:
                tcp_packet = ip_packet[TCP]
                # 判断是否是目标流
                if tcp_packet.sport == self.src_port and tcp_packet.dport == self.dst_port \
                    and ip_packet.src == self.src_ip and ip_packet.dst == self.dst_ip:
                    self.packets.append(packet)
        return

'''
从packets中创建TcpFlow对象列表
'''
class CreateTcpFlow:
    def __init__(self):
        self.tcp_flow_list = [] # TcpFlow对象列表
        self.five_tuple_hash_set = set() # 五元组哈希集合
        self.tuple_flow_dict = {} # 五元组哈希和TcpFlow对象的映射
    
    def calculate_sha256(self, string):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(string.encode('utf-8'))
        return sha256_hash.hexdigest()
    
    def create_from_packets(self, packets):
        for packet in packets:
            # 判断是否是 IP 包
            if IP in packet:
                ip_packet = packet[IP]
                # 判断是否是 TCP 包
                if TCP in ip_packet:
                    tcp_packet = ip_packet[TCP]
                    # 解析五元组
                    src_ip = ip_packet.src
                    src_port = tcp_packet.sport
                    dst_ip = ip_packet.dst
                    dst_port = tcp_packet.dport
                    protocol = 'tcp' # 事实上已经在TcpFlow的init函数中指定了
                    five_tuple = str(src_ip) + '-' + str(src_port) + '-' + str(dst_ip) + '-' + str(dst_port) + '-' + str(protocol)
                    tuple_hash = self.calculate_sha256(five_tuple)
                    
                    # 如果是新流
                    if tuple_hash not in self.five_tuple_hash_set:
                        # 创建flow对象
                        tcp_flow = TcpFlow(src_ip, src_port, dst_ip, dst_port, protocol)
                        # 添加包到flow对象中
                        tcp_flow.add_packet(packet)
                        # 添加flow对象到字典中
                        self.tuple_flow_dict[tuple_hash] = tcp_flow
                        # 添加flow对象到列表中
                        self.tcp_flow_list.append(tcp_flow)
                        # 把五元组哈希添加到集合中
                        self.five_tuple_hash_set.add(tuple_hash)
                    # 如果不是，根据五元组哈希查找该包属于的流，并添加包到流中
                    else:
                        exist_tcp_flow = self.tuple_flow_dict[tuple_hash]
                        # 添加包到flow对象中
                        exist_tcp_flow.add_packet(packet)
        
        return self.tcp_flow_list
    
    def get_tuple_flow_dict(self):
        return self.tuple_flow_dict
    

     