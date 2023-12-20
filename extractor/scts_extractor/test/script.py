'''
Description: 
version: 
Author: zlx
Date: 2023-12-16 21:19:24
LastEditors: zlx
LastEditTime: 2023-12-19 19:25:48
'''

import csv
import os
import subprocess
from tempfile import NamedTemporaryFile


pcap_path = './test.pcap'
output_path = './data/output.csv'
f = 'tls'

def execute_command_backward(cmd_str):  
    """  
    Run tshark command and return results  
    :param cmd_str(str): tshark command line  
    :return: result(str or None): result from tshark,  
                                  raw outputs if successfully executed, otherwise none.  
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


tshark_cmd1 = """tshark -r {} -Y "{}" -T fields -e tcp.stream""".format(pcap_path, f)

stream_list = execute_command_backward(tshark_cmd1)
unique_set = set(stream_list)
# 使用集合推导式来移除空元素  
unique_set = {x for x in unique_set if x} 
new_stream_list = list(unique_set)
# print(new_stream_list)
print('stream num: ', len(new_stream_list))


'''
cmd = """tshark -r {} -Y "{}" -Y "tcp.stream=={}" -T fields \
                            -e tcp.stream \
                            -e ip.src \
                            -e ip.dst \
                            -e tcp.srcport \
                            -e tcp.dstport \
                            -e frame.time_epoch \
                            -e frame.time_delta_displayed \
                            -e ip.len \
                            -e tls.alert_message \
                            -e tls.connection_id_length \
                            -E separator=, >> ./test.csv""".format(pcap_path, f, stream_index)

'''

from field_filter import get_filtered_field_name_list

# 写入表头
lst = get_filtered_field_name_list()
print('field num: ', len(lst))
with open(output_path, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(lst)

# 写入数据
i = 0
for stream_index in new_stream_list:
    
    # 构造tshark命令
    cmd = 'tshark -r '
    cmd = cmd + pcap_path + ' '
    cmd = cmd + '-Y ' + '"' + f + '"' + ' '
    cmd = cmd + '-Y ' + '"' + 'tcp.stream==' + stream_index + '"' + ' '
    cmd = cmd + '-T fields '
    
    lst = get_filtered_field_name_list()
    for item in lst:
        cmd = cmd + '-e ' + item + ' '
        
    cmd = cmd + '-E separator=, >> ' + output_path
    
    _ = execute_command_backward(cmd)
    i = i + 1
    
    if i+1 % 1 == 0:
        print('has processed {} streams'.format(i+1))
        
print('all streams have been processed')

print('csv file was saved in {}'.format(output_path))
print('done')
