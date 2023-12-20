'''
Description: 
version: 
Author: zlx
Date: 2023-12-19 16:15:21
LastEditors: zlx
LastEditTime: 2023-12-20 15:19:38
'''
import decimal
import math
from extractor.scts_extractor.traffic_description.t_feature import TcpStreamFeature

'''
传入一个pkg list, 计算其字段特征和统计特征
'''
class FeatureMakeBasePkgList():
    def __init__(self):
        return
    
    def calculation(self, pkglist):
        mean_,min_,max_,std_=0,0,0,0
        if len(pkglist) < 1:
            return [mean_,min_,max_,std_]
        else:
            min_=round(min(pkglist),6)
            max_=round(max(pkglist),6)
            mean_ = round(sum(pkglist)/len(pkglist),6)
            sd = sum([(i - mean_) ** 2 for i in pkglist])
            std_ = round(math.sqrt(sd / (len(pkglist))),6)
            return [mean_,min_,max_,std_]
    
    # Packet arrival interval
    def packet_iat(self, pkglist):    
        piat=[]
        if len(pkglist)>0:
            pre_time = pkglist[0].time
            for pkt in pkglist[1:]:
                next_time = pkt.time
                piat.append(next_time-pre_time)
                pre_time=next_time
            piat_mean,piat_min,piat_max,piat_std=self.calculation(piat)
        else:
            piat_mean,piat_min,piat_max,piat_std=0,0,0,0
        return piat_mean,piat_min,piat_max,piat_std


    # 包长度特征
    def packet_len(self, pkglist):   
        pl=[]
        for pkt in pkglist:
            pl.append(len(pkt))
        pl_total=round(sum(pl), 6)
        pl_mean,pl_min,pl_max,pl_std=self.calculation(pl)
        return pl_total,pl_mean,pl_min,pl_max,pl_std

    # 拥塞窗口大小特征        
    def packet_win(self, pkglist):
        if len(pkglist)==0:
            return 0,0,0,0,0
        if pkglist[0]["IP"].proto != 6:
            return 0,0,0,0,0
        pwin = [] 
        for pkt in pkglist:
            pwin.append(pkt['TCP'].window)
        pwin_total = round(sum(pwin), 6)
        pwin_mean,pwin_min,pwin_max,pwin_std=self.calculation(pwin)
        return pwin_total,pwin_mean,pwin_min,pwin_max,pwin_std

    # 包中的标志字段统计
    def packet_flags(self, pkglist, key):
        flag=[0,0,0,0,0,0,0,0]
        if len(pkglist) == 0:
            if key == 0:
                return [-1,-1,-1,-1,-1,-1,-1,-1]
            else:
                return -1,-1 
        if pkglist[0]["IP"].proto != 6:
            if key == 0:
                return [-1,-1,-1,-1,-1,-1,-1,-1]
            else:
                return -1,-1 
        for pkt in pkglist:
            flags=int(pkt['TCP'].flags)
            for i in range(8):
                flag[i] += flags%2
                flags=flags//2
        if key==0:
            return flag
        else:
            return flag[3],flag[5]

    # length of packet header
    def packet_hdr_len(self, pkglist): 
        p_hdr_len=0
        for pkt in pkglist:
            p_hdr_len = p_hdr_len+14+4*pkt['IP'].ihl+20
        return p_hdr_len

'''
TcpStream特征make, 继承于TcpStreamFeature和FeatureMakeBasePkgList
'''
class TcpStreamFeatureMake(TcpStreamFeature, FeatureMakeBasePkgList):
    def __init__(self):
        super().__init__()
    
    '''
    输入一个TcpStream对象, 输出一个列表
    '''
    def get_feature(self, tcp_stream):
        # 获取stream中的所有包
        pkts = tcp_stream.get_all_pkgs_from_stream()
        # 获取fwd_flow和bwd_flow中的所有包
        fwd_pkts, bwd_pkts = tcp_stream.get_divided_pkgs_in_stream()
        # 根据时间戳对数据包列表进行排序 
        pkts.sort(key=lambda pkt: pkt.time)
        fwd_pkts.sort(key=lambda pkt: pkt.time)
        bwd_pkts.sort(key=lambda pkt: pkt.time)
        
        if len(pkts) == 0:
            print("warnning double stream has no packet")
        # elif len(fwd_pkts) == 0:
        #     print("warnning fwd flow has no packet")
        # elif len(bwd_pkts) == 0:
        #     print("warnning bwd flow has no packet")
        
        # feature about packet arrival interval 13  
        self.fiat_mean, self.fiat_min, self.fiat_max, self.fiat_std = self.packet_iat(fwd_pkts)  
        self.biat_mean, self.biat_min, self.biat_max, self.biat_std = self.packet_iat(bwd_pkts)  
        self.diat_mean, self.diat_min, self.diat_max, self.diat_std = self.packet_iat(pkts)  
        
        # 为了防止除0错误，不让其为0
        # 第一个数据包到最后一个数据包之间的时间差  
        self.duration = round(pkts[-1].time - pkts[0].time + decimal.Decimal(0.0001), 6)  
        
        # 拥塞窗口大小特征 15  
        self.fwin_total, self.fwin_mean, self.fwin_min, self.fwin_max, self.fwin_std = self.packet_win(fwd_pkts)  
        self.bwin_total, self.bwin_mean, self.bwin_min, self.bwin_max, self.bwin_std = self.packet_win(bwd_pkts)  
        self.dwin_total, self.dwin_mean, self.dwin_min, self.dwin_max, self.dwin_std = self.packet_win(pkts)  
        
        # feature about packet num  7  
        self.fpnum = len(fwd_pkts)  
        self.bpnum = len(bwd_pkts)  
        self.dpnum = self.fpnum + self.bpnum  
        # 包数比率  
        self.bfpnum_rate = round(self.bpnum / (self.fpnum + 0.001), 6)  
        # 单位时间内的包数  
        self.fpnum_s = round(self.fpnum / self.duration, 6)  
        self.bpnum_s = round(self.bpnum / self.duration, 6)  
        self.dpnum_s = self.fpnum_s + self.bpnum_s  
        
        # 包的总长度 19  
        self.fpl_total, self.fpl_mean, self.fpl_min, self.fpl_max, self.fpl_std = self.packet_len(fwd_pkts)  
        self.bpl_total, self.bpl_mean, self.bpl_min, self.bpl_max, self.bpl_std = self.packet_len(bwd_pkts)  
        self.dpl_total, self.dpl_mean, self.dpl_min, self.dpl_max, self.dpl_std = self.packet_len(pkts)  
        # 包长比率  
        self.bfpl_rate = round(self.bpl_total / (self.fpl_total + 0.001), 6)  
        # 单位时间的包长  
        self.fpl_s = round(self.fpl_total / self.duration, 6)  
        self.bpl_s = round(self.bpl_total / self.duration, 6)  
        self.dpl_s = self.fpl_s + self.bpl_s  
        
        # 包的标志特征 12  
        self.fin_cnt, self.syn_cnt, self.rst_cnt, self.pst_cnt, self.ack_cnt, self.urg_cnt, self.cwe_cnt, self.ece_cnt = self.packet_flags(pkts, 0)  
        self.fwd_pst_cnt, self.fwd_urg_cnt = self.packet_flags(fwd_pkts, 1)  
        self.bwd_pst_cnt, self.bwd_urg_cnt = self.packet_flags(bwd_pkts, 1)
        
        # 包头部长度 6
        self.fp_hdr_len=self.packet_hdr_len(fwd_pkts)
        self.bp_hdr_len=self.packet_hdr_len(bwd_pkts)
        self.dp_hdr_len=self.fp_hdr_len + self.bp_hdr_len
        self.f_ht_len=round(self.fp_hdr_len /(self.fpl_total+1), 6)
        self.b_ht_len=round(self.bp_hdr_len /(self.bpl_total+1), 6)
        self.d_ht_len=round(self.dp_hdr_len /self.dpl_total, 6)

        feature = [
                    self.fiat_mean, self.fiat_min, self.fiat_max, self.fiat_std, self.biat_mean, self.biat_min, self.biat_max, self.biat_std,  
                    self.diat_mean, self.diat_min, self.diat_max, self.diat_std, self.duration, self.fwin_total, self.fwin_mean, self.fwin_min,  
                    self.fwin_max, self.fwin_std, self.bwin_total, self.bwin_mean, self.bwin_min, self.bwin_max, self.bwin_std, self.dwin_total,  
                    self.dwin_mean, self.dwin_min, self.dwin_max, self.dwin_std, self.fpnum, self.bpnum, self.dpnum, self.bfpnum_rate, self.fpnum_s,  
                    self.bpnum_s, self.dpnum_s, self.fpl_total, self.fpl_mean, self.fpl_min, self.fpl_max, self.fpl_std, self.bpl_total, self.bpl_mean,  
                    self.bpl_min, self.bpl_max, self.bpl_std, self.dpl_total, self.dpl_mean, self.dpl_min, self.dpl_max, self.dpl_std, self.bfpl_rate,  
                    self.fpl_s, self.bpl_s, self.dpl_s, self.fin_cnt, self.syn_cnt, self.rst_cnt, self.pst_cnt, self.ack_cnt, self.urg_cnt,  
                    self.cwe_cnt, self.ece_cnt, self.fwd_pst_cnt, self.fwd_urg_cnt, self.bwd_pst_cnt, self.bwd_urg_cnt, self.fp_hdr_len,self.bp_hdr_len,
                    self.dp_hdr_len, self.f_ht_len, self.b_ht_len, self.d_ht_len 
                ]

        return feature