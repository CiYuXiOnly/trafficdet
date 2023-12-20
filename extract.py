'''
Description: 
version: 
Author: zlx
Date: 2023-12-11 09:35:49
LastEditors: zlx
LastEditTime: 2023-12-20 15:22:24
'''

from extractor.flow_based.pcap_flow_feature import FlowProcess
from extractor.pkg_based.csv_feature import CsvfeatureExtractOp
from extractor.pkg_based.pcap2csv import Pcap2csvOp
from extractor.sess_based.pcap_sess_feature import SessProcess

def extract_based_pkg():
    op1 = Pcap2csvOp(pcapfilepath='data/pcap/benign_small.pcap', 
                     csvfilepath='data/csv/benign_small_pkg.csv', 
                     isadded=False,)
    op2 = CsvfeatureExtractOp(csvpath='data/csv/benign_small_pkg.csv', 
                              featured_csvpath='data/featured_csv/benign_small_pkg.csv', 
                              isadded=False)
    # pcap生成csv
    op1.generateCSV(per_print=5000)
    # 对生成的csv进行特征提取
    op2.extract()
    
    op1 = Pcap2csvOp(pcapfilepath='data/pcap/malicious_small.pcap', 
                     csvfilepath='data/csv/malicious_small_pkg.csv', 
                     isadded=False)
    op2 = CsvfeatureExtractOp(csvpath='data/csv/malicious_small_pkg.csv', 
                              featured_csvpath='data/featured_csv/malicious_small_pkg.csv', 
                              isadded=False)
    # pcap生成csv
    op1.generateCSV(per_print=5000)
    # 对生成的csv进行特征提取
    op2.extract()
    return

def extract_based_flow():
    config = {
        "run_mode": "flow",  
        "pcap_loc": "data/pcap",  
        "pcap_name": "2.pcapng",  
        "csv_path": "data/featured_csv/2_statis.csv",  
        "print_colname": True,  
        "read_all": False
    }
    p = FlowProcess(config)
    p.extract_flow_feature_from_pcap()
    
    # config = {  
    #     "run_mode": "flow",  
    #     "pcap_loc": "data/pcap",  
    #     "pcap_name": "malicious_small.pcap",  
    #     "csv_path": "data/featured_csv/malicious_small_flow.csv",  
    #     "print_colname": True,  
    #     "read_all": False
    # }
    # p = FlowProcess(config)
    # p.extract_flow_feature_from_pcap()
    
    return

def extract_based_sess():
    op = SessProcess()
    op.extract_sess_feature_from_pcap(pcap_path='data/pcap/benign_small.pcap', 
                                      csv_path='data/featured_csv/benign_small_sess.csv',
                                      label='0')
    op.extract_sess_feature_from_pcap(pcap_path='data/pcap/malicious_small.pcap', 
                                      csv_path='data/featured_csv/malicious_small_sess.csv',
                                      label='1')
    return

def extract_tshark():
    from extractor.tshark_flow.tshark_feat_extract import TsharkExtractorProcess
    tp = TsharkExtractorProcess(pcap_path='data/pcap/malicious_small.pcap', 
                                output_dir='data/featured_csv/',
                                saved_file_type='csv')
    tp.extract(target="tls", isall=False)


def scts_exactor_use():
    from extractor.scts_extractor.main import SCTS_Extractor
    pcap_path = 'data/pcap/test.pcap'
    csv_path = 'data/featured_csv/test_scts.csv'
    e = SCTS_Extractor(pcap_path, csv_path)
    e.run()
    return

if __name__ == "__main__":
    print()
    
    # extract_based_pkg()
    
    # extract_based_flow()
    
    # extract_based_sess()
    
    # extract_tshark()
    
    scts_exactor_use()