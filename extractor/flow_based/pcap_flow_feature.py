'''
Description: 
version: 
Author: zlx
Date: 2023-12-08 21:49:47
LastEditors: zlx
LastEditTime: 2023-12-18 08:28:50
'''
from extractor.flow_based.flow import *
from extractor.flow_based.flow import feature_names
from joblib import *
'''
main API FlowProcess()

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

'''
class FlowProcess():

    def __init__(self, config_dict):
        self.run_mode = config_dict.get('run_mode', 'flow')
        self.pcap_loc = config_dict.get('pcap_loc', 'data/pcap')
        self.pcap_name = config_dict.get('pcap_name', 'pkg.pcap')
        self.csv_path = config_dict.get('csv_path', 'data/featured_csv/features.csv')
        self.print_colname = config_dict.get('print_colname', True)
        self.read_all = config_dict.get('read_all', False)
    
    
    def extract_flow_feature_from_pcap(self):
        start_time = time.time()
        '''
        在pcap模式下，来自同一个pcap的所有数据包会被视为属于同一个流，csv中的头两个字段为pcap文件名和目的IP数量
        在flow模式下，相同五元组的数据包会被视为同一个流，头两个字段为src和dst。
        '''
        run_mode = self.run_mode
        pcap_loc = self.pcap_loc
        pcap_name = self.pcap_name
        csv_path = self.csv_path
        print_colname = self.print_colname
        read_all = self.read_all
        
        print('processing file: {}/{}......'.format(pcap_loc, pcap_name))
        # 决定后续read_pcap代表的函数
        if run_mode == "pcap":
            read_pcap = get_pcap_feature_from_pcap
        else:
            read_pcap = get_flow_feature_from_pcap
            
        # decide whether write column name to csv
        if print_colname:
            with open(csv_path,"w", newline="") as file:
                writer = csv.writer(file)
                print("write colname")
                feature_name = feature_names
                if run_mode == "flow":
                    feature_name = ['src','sport','dst','dport'] + feature_name
                else:
                    feature_name = ['pcap_name','flow_num'] + feature_name
                print('>>> feature len: {}'.format(len(feature_name)))
                writer.writerow(feature_name) 
            file = open(csv_path,"a+", newline="")
            writer = csv.writer(file)
        else:
            file = open(csv_path,"w+", newline="")
            writer = csv.writer(file)

        if read_all:
            # read all pcap files in specified directory
            path = pcap_loc
            if path == "./" or path == "pwd":
                path = os.getcwd()
            all_file = os.listdir(path)
            for pcap_name in all_file:
                if ".pcap" in pcap_name:
                    read_pcap(path+'/'+pcap_name,writer)
        else:
            # read specified pcap file
            pcap_path = pcap_loc +'/'+pcap_name
            if ".pcap" in pcap_name:
                read_pcap(pcap_path, writer)

        end_time = time.time()
        print("using {} s".format(end_time-start_time))
    
