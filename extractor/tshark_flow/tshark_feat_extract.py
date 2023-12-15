'''
Description: 
version: 
Author: zlx
Date: 2023-12-15 17:49:13
LastEditors: zlx
LastEditTime: 2023-12-15 21:08:49
'''

import pandas as pd
from extractor.tshark_flow.stream import Pkt, Stream
from extractor.tshark_flow.util import run_tshark_command, test_tshark, format_tshark_results

import os, json
from pathlib import Path
from datetime import datetime
import csv

'''
main class API TsharkExtractorProcess()

tp = TsharkExtractorProcess(pcap_path='upload/1.pcap', # dir or path
                            output_dir='data/featured_csv/',
                            saved_file_type='csv') # json or csv
# if all, pcap_path should be a dir
# "tls" or "ssl" or "tcp", 前两者等价
tp.extract(target="tls", isall=False)
'''
class TsharkExtractorProcess():
    """
    Main class of PysharkFeat
    """
    def __init__(self, pcap_path, output_dir, saved_file_type='json'):
        """
        Initiator of FeatureExtractor

        """
        # 转换为绝对路径
        self.pcap_path = os.path.abspath(pcap_path)
        
        if saved_file_type == 'json':
            self.json_dir = output_dir
        elif saved_file_type == 'csv':
            self.csv_dir = output_dir
        
        self.saved_file_type = saved_file_type
        # test if tshark works properly
        test_tshark()

    def extract(self, target="tcp", isall=True):
        """
        Main function to be called to generate features
        -- isall=False时one_pcap_file才有效
        :return: output_summary(string): analysis summary
        """
        
        # 检查target是否合法
        t_lst = ['ssl', 'tls', 'tcp']
        if target not in t_lst:
            err_msg = "Target invalid. Please check the target :%s" % target
            raise Exception(err_msg)  
            
        # start clocking
        start_time = datetime.now()
        
        # 获取pcap文件列表
        pcap_files = []
        # 扫描全部pcap文件
        if isall:
            if os.path.isfile(self.pcap_path):
                print('Warrning: Choosed all files, but params:pcap_path only a file is given, so only this file will be processed.')
                pcap_files.append(self.pcap_path)
            elif os.path.isdir(self.pcap_path):
                for root, dir_names, file_names in os.walk(self.pcap_path):
                    for f in file_names:
                        if f[0:2] != "._" and f[-5:] == ".pcap":
                            pcap_files.append(os.path.join(root, f))
            else:
                err_msg = "Pcap path invalid. Please check the pcap path :%s" % self.pcap_path
                raise Exception(err_msg)
        # 只处理单个pcap文件
        else:
            pcap_files.append(self.pcap_path)
        
        tls_num = 0

        for pcap_path in pcap_files:
            pcap_name = Path(pcap_path).name
            pcap_feats_dict = dict()

            pcap_feats = self.extract_pcap_feat(pcap_path, target)

            tls_num += len(pcap_feats)

            pcap_feats_dict[pcap_name] = pcap_feats

            if self.saved_file_type == 'json':
                self.save_feats_json(pcap_feats)
            elif self.saved_file_type == 'csv':
                self.save_feats_processed_csv(pcap_feats)
        
        end_time = datetime.now()
        elapsed_seconds = (end_time - start_time).total_seconds()

        # 获取最终以及统计结果
        output = dict()
        output["summary"] = dict()
        output["summary"]["software"] = "Pysharkfeat"
        # output["summary"]["start_time"] = start_time.strftime("%Y-%m-%d, %H:%M:%s")
        # output["summary"]["end_time"] = end_time.strftime("%Y-%m-%d, %H:%M:%s")
        output["summary"]["start_time"] = start_time.strftime("%Y-%m-%d, %H:%M:%S")
        output["summary"]["end_time"] = end_time.strftime("%Y-%m-%d, %H:%M:%S")
        output["summary"]["elapsed"] = str(round(elapsed_seconds, 2)) + " seconds"
        output["summary"]["pcap_files"] = len(pcap_files)
        output["summary"]["TLS_stream_num"] = tls_num
        output["feats"] = pcap_feats_dict
        summary_output = json.dumps(output["summary"], indent=4)

        return summary_output


    def extract_pcap_feat(self, pcap_path, target):
        """
        Main function to analyze and extract features from a single pcap
        :param pcap_path(str): pcap path
        :return: feats(list): features for the pcap
        """

        stream_dict = self.preprocess_pcap(pcap_path, target)
        feats = self.generate_streams_feat(stream_dict)

        return feats


    def preprocess_pcap(self, pcap_file_path, target):
        """
        Preprocess pcap with tshark
        target: 'ssl', 'tls', 'tcp'
        :param pcap_file_path(str): pcap path
        :return: stream_dict(dict): streams in the pcap
        """

        stream_dict = dict()
        
        # tshark_cmd = ("tshark -r %s -Y 'ssl' -T fields -e tcp.stream" % pcap_file_path)
        tshark_cmd = """tshark -r {} -Y "{}" -T fields -e tcp.stream""".format(pcap_file_path, target)
        
        print(tshark_cmd)
        result = run_tshark_command(tshark_cmd)

        if len(result) == 0:
            print("No TLS/tcp streams found in %s" % pcap_file_path)
            return stream_dict
        # print("result length: ", len(result))
        
        stream_indexes = []
        for line in result:
            tmp = line.replace("\n","")
            tmp_idx = int(tmp)
            if tmp_idx not in stream_indexes:
                stream_indexes.append(tmp_idx)
        # print(stream_indexes)
        print('len(stream_indexes): ', len(stream_indexes))
        
        for stream_index in stream_indexes:
            # this is for linux
            # tshark_cmd = "tshark -r {} -Y 'ssl' -Y 'tcp.stream=={}' -T fields " \
            #              "-e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport " \
            #              "-e tcp.stream -e frame.time_epoch -e frame.time_delta_displayed -e ip.len -e tcp.payload" \
            #              .format(pcap_file_path, stream_index)
            
            # this is for windows
            tshark_cmd = """tshark -r {} -Y "{}" -Y "tcp.stream=={}" -T fields \
                        -e ip.src \
                        -e ip.dst \
                        -e tcp.srcport \
                        -e tcp.dstport \
                        -e tcp.stream \
                        -e frame.time_epoch \
                        -e frame.time_delta_displayed \
                        -e ip.len \
                        -e tcp.payload""".format(pcap_file_path, target, stream_index)
            
            # print(tshark_cmd)
            result = run_tshark_command(tshark_cmd)
            if result == None:
                print('this stream is empty: {}'.format(stream_index))
                continue
                
            formatted_result = format_tshark_results(result)

            pcap_file_name = Path(pcap_file_path).name

            stream = Stream(pcap_file_name, stream_index)
            stream_dict[(pcap_file_name, stream_index)] = stream

            i = 0
            pkt0_src_ip = ""
            pkt0_dest_ip = ""

            for line in formatted_result:
                try:
                    pkt = Pkt()
                    pkt.id = i
                    pkt.src_ip = line[0]
                    pkt.dest_ip = line[1]
                    pkt.src_port = int(line[2])
                    pkt.dest_port = int(line[3])
                    pkt.stream_index = int(line[4])
                    pkt.timestamp = float(line[5])
                    pkt.time_delta = float(line[6])
                    pkt.pkt_len = float(line[7])     # in rare cases, tshark parsing results have incorrect data
                    pkt.payload_hex = line[8]
                    payload_formatted = pkt.payload_hex.replace(":","")
                    pkt.payload = bytes.fromhex(payload_formatted)

                    if pkt.id == 0:
                        pkt.direction = "up"
                        pkt0_src_ip = pkt.src_ip
                        pkt0_dest_ip = pkt.dest_ip
                    else:

                        if pkt.src_ip == pkt0_src_ip and pkt.dest_ip == pkt0_dest_ip:
                            pkt.direction = "up"
                        else:
                            pkt.direction = "down"

                    stream.pkts.append(pkt)
                    i += 1

                except:
                    msg = "[Warning] %s  stream %s pkt error" % (pcap_file_name, stream_index)
                    continue
            
            if stream_index % 10 == 0:
                msg = "%s  stream %s [analyzed by tshark]" % (pcap_file_name, stream_index)
                print(msg)
        
        print('Has analyzed all streams in %s' % pcap_file_path)
        return stream_dict

    def generate_streams_feat(self, stream_dict):
        """
        Generate features for every TLS stream
        :return: stream_feat(list): list of features and
                                    every element represents the feature dict for the stream
        """

        feats = []

        for k, stream in stream_dict.items():
            feat = stream.generate_stream_features()    # feat in dict format
            feats.append(feat)

        return feats

    def save_feats_json(self, pcap_result_dict_list):
        """
        Save features as JSON files in self.json_dir with identical file stem with the pcap.
        :param pcap_result_dict(dict): pcap_feat_dcit
        :return: nothing
        """

        if self.json_dir == None:
            print('json_dir is None')
            return

        p = Path(self.json_dir)
        if not p.is_dir():
            os.mkdir(self.json_dir, 0o755)

        output_dir_abs_path = os.path.abspath(self.json_dir)

        if pcap_result_dict_list:
            p = Path(pcap_result_dict_list[0]["pcap_name"])
            feat_file_name = p.stem + '_tshark'+ '.json'
            feat_file_path = os.path.join(output_dir_abs_path, feat_file_name)

            with open(feat_file_path, "w") as f:
                json.dump(pcap_result_dict_list, f, indent=4)
        else:
            print("pcap_result_dict is empty.")

        return
    
    
    def save_feats_processed_csv(self, pcap_result_dict_list):
        """
        Save features as CSV files in self.csv_dir with identical file stem with the pcap.
        :param pcap_result_dict(dict): pcap_result_dict_list
        :return: nothing
        """

        if self.csv_dir == None:
            print('csv_dir is None')
            return

        data = pcap_result_dict_list
        
        # 获取csv_path
        csvname = data[0]["pcap_name"].split('.')[0] + '_tshark' + '.csv'
        file_path = os.path.join(self.csv_dir, csvname)
        
        # 首先需要把"mc_len" "mc_time" "bd_dist"键指向的列表转均值
        for i in range(len(data)):
            dict1 = data[i]
            # 计算均值
            mean_mc_len = sum(dict1["mc_len"]) / len(dict1["mc_len"])
            mean_mc_time = sum(dict1["mc_time"]) / len(dict1["mc_time"])
            mean_bd_dist = sum(dict1["bd_dist"]) / len(dict1["bd_dist"])
            # 赋予其他键名
            dict1["mean_mc_len"] = mean_mc_len
            dict1["mean_mc_time"] = mean_mc_time
            dict1["mean_bd_dist"] = mean_bd_dist
            # 删除原有键
            del dict1["mc_len"]
            del dict1["mc_time"]
            del dict1["bd_dist"]
            # 删除"pcap_name"键
            del dict1["pcap_name"]
    
        # # test
        # with open('data.json', 'w') as json_file:
        #     json_data = json.dumps(data[0], indent=4)  # 将JSON对象转换为JSON字符串
        #     json_file.write(json_data)
        # print(data[0].keys())
        # print(len(data[0].keys()))
        
        # 写入csv文件
        csv_file = open(file_path, 'w', newline='', encoding='utf-8')
        writer = csv.writer(csv_file)
        # 写入CSV文件头部
        header = data[0].keys()
        writer.writerow(header)
        # 写入每条记录
        for row in data:
            values = row.values()
            writer.writerow(values)
        csv_file.close()
        
        # 验证csv文件
        df = pd.read_csv(file_path)
        print('csv file shape: ', df.shape)
        
        return

        