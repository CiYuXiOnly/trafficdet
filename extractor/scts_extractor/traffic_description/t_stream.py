'''
Description: 
version: 
Author: zlx
Date: 2023-12-18 18:18:03
LastEditors: zlx
LastEditTime: 2023-12-20 10:41:00
'''

from scapy.all import *

'''
(一定时间范围内)<ip1:port1>, <ip2:port2>, <protocol> 的集合相同定义为一个stream, 双向流
一个stream中可以有多个flow
'''
class Stream:
    def __init__(self, comm_entity1, comm_entity2, protocol):
        '''
        comm_entity1: 'ip:port'
        comm_entity2: 'ip:port'
        protocol: 'protocol'
        '''
        self.comm_entity1 = comm_entity1
        self.comm_entity2 = comm_entity2
        self.protocol = protocol
        # 每次实例化stream时，都会构造一个src_dst_set，配合check_flow_as_stream用来判断新stream和当前stream是否相同
        self.src_dst_set = self._construct_src_dst_set(self.comm_entity1, self.comm_entity2, self.protocol)
        self.flows = []
        self.fwd_flows = []
        self.bwd_flows = []

    def _construct_src_dst_set(self, comm_entity1, comm_entity2, protocol):
        sd_set = set()
        sd_set.add(comm_entity1)
        sd_set.add(comm_entity2)
        sd_set.add(protocol)
        return sd_set
    
    def check_flow_as_stream(self, flow):
        pass
    
    def get_all_pkgs_from_stream(self):
        flows = self.flows
        pkgs = []
        for flow in flows:
            pkg_sub_list = flow.packets
            for pkg in pkg_sub_list:
                pkgs.append(pkg)
        return pkgs
    
    def __repr__(self):
        obj_str = '{} <-> {}, totally {} flows\n'.format(self.comm_entity1, self.comm_entity2, len(self.flows))
        obj_str = obj_str + '{} -> {}, {} flows\n'.format(self.comm_entity1, self.comm_entity2, len(self.fwd_flows))
        obj_str = obj_str + '{} <- {}, {} flows\n'.format(self.comm_entity1, self.comm_entity2, len(self.bwd_flows))
        return obj_str


'''
Tcp stream, 继承自Stream
'''
class TcpStream(Stream):
    def __init__(self, comm_entity1, comm_entity2, protocol):
        super().__init__(comm_entity1, comm_entity2, protocol)
        self.protocol = 'tcp'
        
    def add_flow_from_flow_list(self, flows):
        '''
        从一个flow list中添加flow到当前的stream中
        '''
        for flow in flows:
            if self.check_flow_as_stream(flow):
                self.flows.append(flow)
        return self.flows

    # 重写父类的check_flow_as_stream方法
    def check_flow_as_stream(self, flow):
        '''
        给定一个flow, 检查是否可以加入到当前的stream中
        '''
        ret = False
        sset = set()
        comm_entity1 = flow.src_ip + ':' + str(flow.src_port)
        comm_entity2 = flow.dst_ip + ':' + str(flow.dst_port)
        protocol = flow.protocol
        sset.add(comm_entity1)
        sset.add(comm_entity2)
        sset.add(protocol)
        if sset == self.src_dst_set:
            ret = True
        return ret
    
    def _divide_flows(self, flows, src_ip):
        '''
        把一个flow list分成两个flow list, 分别是从src_ip发出的fwd_flows和从src_ip接收的bwd_flows
        第一个参数一般是stream.flows
        要求这些flows都是属于同一个stream的
        '''
        fwd_flows=[]
        bwd_flows=[]
        for flow in flows:
            # 一个flow中所有包的五元组都是完全相同的，所以只需要检查第一个包即可
            pkt_first = flow.packets[0]
            if pkt_first["IP"].src == src_ip:
                fwd_flows.append(flow)
            else:
                bwd_flows.append(flow)
        return fwd_flows, bwd_flows
    
    def get_divided_flows_in_stream(self, is_reverse=False):
        '''
        把一个stream.flows分成两个stream.fwd_flows, stream.bwd_flows, 
        分别是从src_ip发出的fwd_flows和从src_ip接收的bwd_flows
        默认情况下, is_reverse=False, 第一个流的方向是fwd方向
        '''
        # 首先确定通信双方的ip，可以拿第一个流查看
        flow_first = self.flows[0]
        ip1 = flow_first.src_ip
        ip2 = flow_first.dst_ip
        
        if not is_reverse:
            self.fwd_flows, self.bwd_flows = self._divide_flows(self.flows, ip1)
        else:
            self.fwd_flows, self.bwd_flows = self._divide_flows(self.flows, ip2)
        
        return self.fwd_flows, self.bwd_flows
    
    def get_divided_pkgs_in_stream(self):
        '''
        划分包列表为上行包列表和下行包列表
        '''
        # 划分包列表之前需要先划分流, 使self.fwd_flows非空
        self.get_divided_flows_in_stream()
        
        fwd_flows = self.fwd_flows
        bwd_flows = self.bwd_flows
        fwd_pkgs = []
        bwd_pkgs = []
        for fwd_flow in fwd_flows:
            pkg_sub_list = fwd_flow.get_all_pkgs_from_flow()
            for pkg in pkg_sub_list:
                fwd_pkgs.append(pkg)
        for bwd_flow in bwd_flows:
            pkg_sub_list = bwd_flow.get_all_pkgs_from_flow()
            for pkg in pkg_sub_list:
                bwd_pkgs.append(pkg)
        return fwd_pkgs, bwd_pkgs

'''
创建TcpStream对象
'''
class CreateTcpStream():
    def __init__(self):
        self.tcp_stream_list = [] # TcpStream对象列表
        return
    
    '''
    从一个flows对象列表中创建TcpStream对象列表
    '''
    def create_from_flows(self, flows):
        for flow in flows:
            comm_entity1 = flow.src_ip + ':' + str(flow.src_port)
            comm_entity2 = flow.dst_ip + ':' + str(flow.dst_port)
            protocol = flow.protocol
            
            tcp_stream = TcpStream(comm_entity1, comm_entity2, protocol)
            
            # 如果是第一个stream，则直接添加
            if len(self.tcp_stream_list) == 0:
                tcp_stream.flows.append(flow)
                self.tcp_stream_list.append(tcp_stream)
                continue
            # 如果不是第一个stream，则检查是否属于某个已有的 Stream，如果是，则将该流添加到对应的 Stream 中
            # 前面创建的tcp_stream对象将无用
            belong_to_existing_stream = False
            for stream in self.tcp_stream_list:
                if stream.check_flow_as_stream(flow):
                    stream.flows.append(flow)
                    belong_to_existing_stream = True
                    break
            
            # 如果当前流不属于任何已有的 Stream，则创建一个新的 Stream（前面已经创建），并添加当前flow
            if not belong_to_existing_stream:
                tcp_stream.flows.append(flow)
                self.tcp_stream_list.append(tcp_stream)
            
        return self.tcp_stream_list
    
    