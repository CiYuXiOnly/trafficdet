'''
Description: 
version: 
Author: zlx
Date: 2023-12-08 08:58:09
LastEditors: zlx
LastEditTime: 2023-12-11 20:04:19
'''
import os
import scapy.all as scapy
from extractor.pkg_based.pcapDecode import PcapDecode

class Pcap2csvOp():
    def __init__(self, pcapfilepath, csvfilepath, isadded=False, usingflag=None):
        self.csvfilepath=csvfilepath
        self.pcapfilepath=pcapfilepath
        self.isadded=isadded
        self.usingflag = usingflag

    def generateCSV(self, per_print=1000):
        """
        :param csvfilepath: 数据包存储位置，需要是csv格式
        :param pcapfilepath: pcap包读取位置
        :return: None
        """
        PD = PcapDecode()
        scapy.load_layer('tls')
        
        # 检查文件是否存在  
        if not os.path.exists(self.csvfilepath):  
            # 如果文件不存在，则创建文件  
            open(self.csvfilepath, 'w').close()
            
        if self.isadded:
            mode = 'a+'  # 向文件追加数据
        # 不向文件追加数据
        else:
            mode = 'w'           
                    
        with open(self.csvfilepath, mode) as f:
                with scapy.PcapReader(self.pcapfilepath) as packets:
                    num_packets = sum(1 for _ in packets)  # 计算数据包数量
                    print(f"{self.pcapfilepath}中有{num_packets}个数据包")
                with scapy.PcapReader(self.pcapfilepath) as packets:
                    # 处理每个数据行
                    for i, pkt in enumerate(packets):
                        data = PD.ether_decode(pkt)

                        if i == 0:  
                            print('原始特征字典键个数: {}'.format(len(data.keys())))
                            # 获取字典的键列表
                            keys = list(data.keys())
                            # 将键列表连接成字符串，并用逗号分隔
                            keys_line = '_!_'.join(keys)
                            # 将拼接好的键字符串写入文件的第一行
                            f.write(keys_line + '_!_label\n')
                        
                        # 处理并写入字典的值
                        values = [str(value).replace(',', ' ') if isinstance(value, str) else str(value) for value in data.values()]
                        values_line = '_!_'.join(values)
                        f.write(values_line + '_!_')

                        # 写入 usingflag 值
                        if self.usingflag == 'good':
                            f.write('good\n')
                        elif self.usingflag == 'bad':
                            f.write('bad\n')
                        else:
                            f.write('unknown\n')

                        if ((i + 1) % per_print == 0):
                            print(f"目前已处理{self.pcapfilepath}中{i + 1}个数据包.")

                    print(f"已处理完{self.pcapfilepath}中所有数据包.")        


if __name__=="__main__":
        
    op = Pcap2csvOp('data/pcap/test.pcap', 'data/csv/test.csv', isadded=False)
    op.generateCSV()