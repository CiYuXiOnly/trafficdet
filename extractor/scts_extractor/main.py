'''
Description: 
version: 
Author: zlx
Date: 2023-12-19 20:50:34
LastEditors: zlx
LastEditTime: 2023-12-20 15:20:34
'''
from extractor.scts_extractor.statis_exactor import create_statistic_feature
from extractor.scts_extractor.tshark_exactor import create_tshark_feature

import multiprocessing  

from extractor.scts_extractor.merge_process import merger_and_decom

class SCTS_Extractor():
    def __init__(self, pcap_file_path, output_path):
        self.pcap_file_path = pcap_file_path
        self.output_path = output_path
    
    def run(self):
        pcap_path = self.pcap_file_path
        output_path1 = './data/csv/output1.csv'
        output_path2 = './data/csv/output2.csv'
        final_csv_path = self.output_path
        # 创建进程池
        pool = multiprocessing.Pool()  
        # 启动第一个进程
        pool.apply_async(create_statistic_feature, args=(pcap_path,output_path1))  
        # 启动第二个进程
        pool.apply_async(create_tshark_feature, args=(pcap_path,output_path2))  
    
        # 等待任务create_statistic_feature和任务create_tshark_feature完成  
        pool.close()
        pool.join()
        print(">>> 任务create_statistic_feature和任务create_tshark_feature已完成")
        print(">>> 开始合并, 规范化, 降维...")
        # 启动第三个进程执行任务 
        pool = multiprocessing.Pool()  
        pool.apply_async(merger_and_decom, args=(output_path1, output_path2, final_csv_path))  
        pool.close()
        pool.join()
        
        print(">>> done !")
        return
