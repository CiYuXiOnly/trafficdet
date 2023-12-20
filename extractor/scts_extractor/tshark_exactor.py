'''
Description: 
version: 
Author: zlx
Date: 2023-12-18 11:23:50
LastEditors: zlx
LastEditTime: 2023-12-20 15:21:13
'''
import csv
from tempfile import NamedTemporaryFile
import threading
import subprocess
from extractor.scts_extractor.field_filter import get_filtered_field_name_list
import concurrent.futures

lock = threading.Lock()

'''
tshark生成的特征分隔符是;
'''
def execute_command(cmd_list_format):
    '''
    执行单条命令, 输入列表
    第一个子列表cmd单字符列表形式list(cmd), 避免引号问题
    第二个子列表表示进度信息, 第一个index, 第二个perprint
    ''' 
    command = ''.join(cmd_list_format[0])
    i = int(cmd_list_format[1][0])
    perprint = int(cmd_list_format[1][1])
    if i % perprint == 0:
        print('processing {} streams...'.format(i)) 
    
    # 获取锁
    lock.acquire()  
    try:  
        # 执行命令  
        process = subprocess.Popen(command, shell=True)  
        process.wait()
        
    finally:  
        # 释放锁  
        lock.release()  

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

def get_stream_list(pcap_path, f):
    '''
    获取pcap文件中指定f的tcp.stream(实际是双向流)的id列表
    '''
    cmd = """tshark -r {} -Y "{}" -T fields -e tcp.stream""".format(pcap_path, f)
    stream_list = execute_command_backward(cmd)
    unique_set = set(stream_list)
    # 使用集合推导式来移除空元素  
    unique_set = {x for x in unique_set if x} 
    new_stream_list = list(unique_set)
    # print(new_stream_list)
    return new_stream_list
    
def get_field_cmd(pcap_path, f, stream_index, output_path):
    '''
    获取tshark命令中的字段部分
    '''
    # 构造tshark命令
    cmd = 'tshark -r '
    cmd = cmd + pcap_path + ' '
    cmd = cmd + '-Y ' + '"' + f + '"' + ' '
    cmd = cmd + '-Y ' + '"' + 'tcp.stream==' + stream_index + '"' + ' '
    cmd = cmd + '-T fields '
    
    lst = get_filtered_field_name_list()
    for item in lst:
        cmd = cmd + '-e ' + item + ' '
        
    cmd = cmd + '-E separator=; >> ' + output_path
    
    return cmd

'''
main API 根据传递的字段列表提取字段到csv文件中
'''
def create_tshark_feature(pcap_file_path, output_csv_path, perprint=2):
    pcap_path = pcap_file_path
    f = 'tcp'
    output_path = output_csv_path
    perprint = 2 # 每处理perprint个流打印一次进度
    
    # 获取tcp.stream(实际是双向流)的id列表
    stream_list = get_stream_list(pcap_path, f)
    print('(tshark script report) stream num: ', len(stream_list))
    
    # 写入表头
    lst = get_filtered_field_name_list()
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=';')
        writer.writerow(lst)
    print('field num: ', len(lst))
    
    print('start threads...')
    i = 0
    threads = []
    # 创建一个线程池
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        for stream_index in stream_list:
            # print( 'processing stream {}'.format(stream_index))
            cmd = get_field_cmd(pcap_path, f, stream_index, output_path)
            
            param = []
            param.append(list(cmd))
            infolst = list(str(i+1))
            infolst.append(perprint)
            param.append(infolst)
            
            # 添加任务到线程池
            future = executor.submit(execute_command, param)
            threads.append(future)
            
            i = i + 1

    # 等待所有任务完成
    concurrent.futures.wait(threads)
    
    print('all streams have been processed')
    print('csv file was saved in {}'.format(output_path))
    
    return

    
# if __name__ == "__main__":
#     print()
#     create_tshark_feature('1.pcap', './output.csv')