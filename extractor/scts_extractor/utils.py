'''
Description: 
version: 
Author: zlx
Date: 2023-12-19 20:03:36
LastEditors: zlx
LastEditTime: 2023-12-20 15:21:22
'''
import csv
import subprocess
from tempfile import NamedTemporaryFile
from scapy.all import rdpcap
from extractor.scts_extractor.field_filter import get_filtered_field_name_list

def execute_command_backward(cmd_str):  
    """  
    执行命令, 然后读取并返回结果
    """  
    with NamedTemporaryFile("w+t") as f:  
        with subprocess.Popen(cmd_str, stdout=f, stderr=subprocess.PIPE, shell=True) as proc:  
            ret = proc.wait()  
            stderr_content = proc.stderr.read().decode()  
              
            if ret == 0:  
                f.seek(0)
                result = f.read().splitlines()
            else:  
                result = None  
                print(f"Error executing tshark: {stderr_content}")            
    return result

'''
获取stream id和包 id的映射关系
'''
def get_sid_pid_mapping(pcap_path):
    slist = execute_command_backward('tshark -r {} -T fields -e frame.number -e tcp.stream'.format(pcap_path))
    # 获取结果并将有效的行存入tmp_lst
    tmp_lst = []
    for string in slist:
        left_string, right_string = string.split('\t', 1)
        
        if right_string != '':
            # print(left_string, right_string)
            sub_lst = []
            sub_lst.append(left_string)
            sub_lst.append(right_string)
            tmp_lst.append(sub_lst)
    # print(tmp_lst)

    # 获取所有的stream id
    stream_id_set = set()
    stream_pkg_dict = {}
    for each in tmp_lst:
        stream_id_set.add(each[1])

    # print(stream_id_set)

    # 将每个stream id对应的包id存入字典中, key为stream id, value为包id列表
    for stream_id in stream_id_set:
        stream_pkg_dict[stream_id] = []
        
    for each in tmp_lst:
        stream_pkg_dict[each[1]].append(each[0])
    # print(stream_pkg_dict)
    
    return stream_pkg_dict

'''
获取根据stream id划分的包列表
'''
def get_stream_devided_pkgs(pkg_list, stream_pkg_index_dict):
    # 把包列表加上id
    pkgdict = {}
    for i, item in enumerate(pkg_list, start=1):
        pkgdict[str(i)] = item
    # print(pkgdict)
    
    # 获取用stream id索引的包列表
    stream_pkg_map_dict = {}
    for key, value in stream_pkg_index_dict.items():
        stream_pkg_map_dict[key] = []
        for item in value:
            stream_pkg_map_dict[key].append(pkgdict[item])
    # print(stream_pkg_map_dict)
    
    return stream_pkg_map_dict

'''
根据pcap文件获取用stream id索引的包列表
'''
def get_mapped_pkgs(pcap_path):
    # 读文件获取包列表
    pkg_list = rdpcap(pcap_path)
    # 获取stream id和包 id的映射关系
    stream_pkg_index_dict =  get_sid_pid_mapping(pcap_path)
    # 获取用stream id索引的包列表
    stream_pkg_map_dict = get_stream_devided_pkgs(pkg_list, stream_pkg_index_dict)
    return stream_pkg_map_dict


def write_fields_names_to_csv():
    lst = get_filtered_field_name_list()
    
    with open('data/fields.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for item in lst:
            writer.writerow([item])
    return