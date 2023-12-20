'''
Description: 
version: 
Author: zlx
Date: 2023-12-19 15:56:20
LastEditors: zlx
LastEditTime: 2023-12-19 17:49:37
'''

class TcpStreamFeature():
    def __init__(self):
        self.feature_names = ['fiat_mean', 'fiat_min', 'fiat_max', 'fiat_std', 'biat_mean', 'biat_min', 'biat_max', 'biat_std',  
               'diat_mean', 'diat_min', 'diat_max', 'diat_std', 'duration', 'fwin_total', 'fwin_mean', 'fwin_min',  
               'fwin_max', 'fwin_std', 'bwin_total', 'bwin_mean', 'bwin_min', 'bwin_max', 'bwin_std', 'dwin_total',  
               'dwin_mean', 'dwin_min', 'dwin_max', 'dwin_std', 'fpnum', 'bpnum', 'dpnum', 'bfpnum_rate', 'fpnum_s',  
               'bpnum_s', 'dpnum_s', 'fpl_total', 'fpl_mean', 'fpl_min', 'fpl_max', 'fpl_std', 'bpl_total', 'bpl_mean',  
               'bpl_min', 'bpl_max', 'bpl_std', 'dpl_total', 'dpl_mean', 'dpl_min', 'dpl_max', 'dpl_std', 'bfpl_rate',  
               'fpl_s', 'bpl_s', 'dpl_s', 'fin_cnt', 'syn_cnt', 'rst_cnt', 'pst_cnt', 'ack_cnt', 'urg_cnt',  
               'cwe_cnt', 'ece_cnt', 'fwd_pst_cnt', 'fwd_urg_cnt', 'bwd_pst_cnt', 'bwd_urg_cnt', 'fp_hdr_len',  
               'bp_hdr_len', 'dp_hdr_len', 'f_ht_len', 'b_ht_len', 'd_ht_len']
        
        self.fiat_mean = None
        self.fiat_min = None
        self.fiat_max = None
        self.fiat_std = None
        self.biat_mean = None
        self.biat_min = None
        self.biat_max = None
        self.biat_std = None
        self.diat_mean = None
        self.diat_min = None
        self.diat_max = None
        self.diat_std = None
        self.duration = None
        self.fwin_total = None
        self.fwin_mean = None
        self.fwin_min = None
        self.fwin_max = None
        self.fwin_std = None
        self.bwin_total = None
        self.bwin_mean = None
        self.bwin_min = None
        self.bwin_max = None
        self.bwin_std = None
        self.dwin_total = None
        self.dwin_mean = None
        self.dwin_min = None
        self.dwin_max = None
        self.dwin_std = None
        self.fpnum = None
        self.bpnum = None
        self.dpnum = None
        self.bfpnum_rate = None
        self.fpnum_s = None
        self.bpnum_s = None
        self.dpnum_s = None
        self.fpl_total = None
        self.fpl_mean = None
        self.fpl_min = None
        self.fpl_max = None
        self.fpl_std = None
        self.bpl_total = None
        self.bpl_mean = None
        self.bpl_min = None
        self.bpl_max = None
        self.bpl_std = None
        self.dpl_total = None
        self.dpl_mean = None
        self.dpl_min = None
        self.dpl_max = None
        self.dpl_std = None
        self.bfpl_rate = None
        self.fpl_s = None
        self.bpl_s = None
        self.dpl_s = None
        self.fin_cnt = None
        self.syn_cnt = None
        self.rst_cnt = None
        self.pst_cnt = None
        self.ack_cnt = None
        self.urg_cnt = None
        self.cwe_cnt = None
        self.ece_cnt = None
        self.fwd_pst_cnt = None
        self.fwd_urg_cnt = None
        self.bwd_pst_cnt = None
        self.bwd_urg_cnt = None
        self.fp_hdr_len = None
        self.bp_hdr_len = None
        self.dp_hdr_len = None
        self.f_ht_len = None
        self.b_ht_len = None
        self.d_ht_len = None
        return
        
    def get_feature_names(self):
        return self.feature_names  
    
        

    
