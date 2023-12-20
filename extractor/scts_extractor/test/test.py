'''
Description: 
version: 
Author: zlx
Date: 2023-12-17 16:06:11
LastEditors: zlx
LastEditTime: 2023-12-19 19:44:08
'''
import subprocess
from tempfile import NamedTemporaryFile
import pandas as pd

from scapy.all import rdpcap  
  
# # 读取PCAP文件  
# packets = rdpcap('1.pcap')  
  
# # 遍历每个包并获取编号  
# for i, packet in enumerate(packets, start=1):
#     print("Packet Number:", i)
#     # You can further process or analyze each packet's other attributes

lst1 = ["a", "b", "c", "d", "e"]

dict2 = {}

for i, item in enumerate(lst1, start=1):
    dict2[str(i)] = item
    
print(dict2)

# maplst = ['1', '3', '4']
# lst3 = []
# for i, item in enumerate(lst1, start=1):
#     if str(i) in maplst:
#         lst3.append(item)
# print(lst3)

stream_pkg_index_dict = {'1': ['1', '3'], '2': ['2'], '4':['4', '5']}

stream_pkg_map_dict = {}

for key, value in stream_pkg_index_dict.items():
    stream_pkg_map_dict[key] = []
    for item in value:
        stream_pkg_map_dict[key].append(dict2[item])
print(stream_pkg_map_dict)