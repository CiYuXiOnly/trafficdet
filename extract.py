'''
Description: 
version: 
Author: zlx
Date: 2023-12-11 09:35:49
LastEditors: zlx
LastEditTime: 2023-12-21 16:05:53
'''

from extractor.flow_based.pcap_flow_feature import FlowProcess
from extractor.scts_extractor.main import SCTS_Extractor

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

def scts_exactor_use():
    # pcap_path = 'data/pcap/benign_small.pcap'
    # csv_path = 'data/featured_csv/benign_small_scts.csv'
    # e = SCTS_Extractor(pcap_path, csv_path)
    # e.run()
    
    # pcap_path = 'data/pcap/malicious_small.pcap'
    # csv_path = 'data/featured_csv/malicious_small_scts.csv'
    # e = SCTS_Extractor(pcap_path, csv_path)
    # e.run()
    
    # test
    from extractor.scts_extractor.merge_process import merger_and_decom
    merger_and_decom('data/csv/output1.csv', 'data/csv/output2.csv', 'data/featured_csv/example_scts.csv')
    return

if __name__ == "__main__":
    print()
    
    # extract_based_flow()
    
    scts_exactor_use()