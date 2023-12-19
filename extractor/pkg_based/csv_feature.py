'''
Description: 
version: 
Author: Zhang Lingxin
Date: 2023-12-08 09:24:35
LastEditors: Zhang Lingxin
LastEditTime: 2023-12-11 21:11:15
'''
#!/usr/bin/env python
# -*- coding:utf-8 -*-
import numpy as np
from datetime import datetime
import csv
import numpy as np
from datetime import datetime
import pandas as pd
import re
from sklearn import preprocessing


class GetFeature():
    def __init__(self):
        pass

    def make_features(self, csvpath, featured_csvpath):
        '''
        此函数添加用于提取统计特征
        '''
        df_csv = pd.read_csv(csvpath, sep='_!_')
        print('csv shape before: ', df_csv.shape)
        if df_csv.shape[1] != 27:
            print('headers len {}'.format(df_csv.shape[1]))
            print('headers: {}'.format(df_csv.columns))
        
        data1 = df_csv[["info"]].copy()
        # 遍历并替换指定列的记录
        data1["info"] = data1["info"].str.replace("https", "443").str.replace("http", "80")
        final_list = []
        i = 0
        for string in data1["info"]:
            # 找到第一个数字和最后一个数字，并提取之间的内容
            pattern = r"(\d+).*(\d+)"
            match = re.search(pattern, string)
            if match:
                in_between_content = match.group(0)
                new_string = string.replace(in_between_content, "")
                new_string = new_string.replace(" ", "")
                # print("去掉提取出来的内容后的字符串：", new_string)
                in_between_content = in_between_content.replace(" ", "")
                # print("提取出来的内容：", in_between_content)
                sublist = [new_string]
                final_list.append(sublist)
            else:
                new_string = string.replace(" ", "")
                sublist = [new_string]
                final_list.append(sublist)  
            i += 1
        # print("final_list: ", final_list)
        
        subdata = pd.DataFrame(final_list, columns=["layerInfo"])
        data2 = pd.concat([subdata, df_csv], axis=1)
        data2 = data2.drop(["info"], axis=1)
        
        # ip和端口合并
        data3 = data2.copy()
        data3["src"] = data3["source_ip"] + ":" + data3["source_port"].astype(str)
        data3["dst"] = data3["dest_ip"] + ":" + data3["dest_port"].astype(str)
        data3.drop(["source_ip", "source_port", "dest_ip", "dest_port"], axis=1, inplace=True)
        
        # 处理时间
        data4 = data3.copy()
        # 将字符串时间转换为 Pandas 时间类型
        data4['Time'] = pd.to_datetime(data4["time"])
        # 获取最早时间的 Timestamp 对象
        earliest_time = data4['Time'].min()
        # 计算每个时间与最早时间的相对秒数
        data4['RelativeSeconds'] = (data4['Time'] - earliest_time).dt.total_seconds()
        data4 = data4.drop(["Time", "time"], axis=1)
        
        # 类别编码
        data5 = data4.copy()
        # 对协议等信息进行普通类别编码
        le1 = preprocessing.LabelEncoder()
        le1.fit(data5["layerInfo"])
        data5["layerInfo"] = le1.transform(data5["layerInfo"])

        le2 = preprocessing.LabelEncoder()
        le2.fit(data5["protocol"])
        data5["protocol"] = le2.transform(data5["protocol"])

        le3 = preprocessing.LabelEncoder()
        le3.fit(data5["tcp_flags"])
        data5["tcp_flags"] = le3.transform(data5["tcp_flags"])

        le4 = preprocessing.LabelEncoder()
        le4.fit(data5["src"])
        data5["src"] = le4.transform(data5["src"])

        le5 = preprocessing.LabelEncoder()
        le5.fit(data5["dst"])
        data5["dst"] = le5.transform(data5["dst"])

        data5 = data5.drop(["label", "tcp_options"], axis=1)
        
        # 对tcp 和 UDP payload筛选关键词
        data6 = data5.copy()
        flist = []
        for item in data6["tcp_payload"]:
            item = str(item).replace("Raw", "RAW")
            # 使用正则表达式查找全是大写字母的子串
            matches = re.findall(r'\b[A-Z]{2,}\b', item)
            # 将匹配项列表转换为集合，去除其中重复项，并将结果转换回列表
            if len(matches)>0:
                matches = list(set(matches))
                # 将匹配项列表转换为字符串，并用空格连接起来
                result = ' '.join(matches)
                # 去掉字符串首尾的空格
                result = result.strip()
            else:
                result = "EMPTY"
            sublist = [result]
            flist.append(sublist)

        tmpdf1 = pd.DataFrame(flist, columns=["tcp_pay_load_action"])

        flist = []
        for item in data6["udp_payload"]:
            item = str(item).replace("Raw", "RAW")
            # 使用正则表达式查找全是大写字母的子串
            matches = re.findall(r'\b[A-Z]{2,}\b', item)
            # 将匹配项列表转换为集合，去除其中重复项，并将结果转换回列表
            if len(matches)>0:
                matches = list(set(matches))
                # 将匹配项列表转换为字符串，并用空格连接起来
                result = ' '.join(matches)
                # 去掉字符串首尾的空格
                result = result.strip()
            else:
                result = "EMPTY"
            sublist = [result]
            flist.append(sublist)

        tmpdf2 = pd.DataFrame(flist, columns=["udp_pay_load_action"])

        data6 = pd.concat([data6, tmpdf1, tmpdf2], axis=1)
        data6 = data6.drop(["udp_payload", "tcp_payload"], axis=1)

        # 编码 tcp, udp，icmp payload
        le6 = preprocessing.LabelEncoder()
        le6.fit(data6["udp_pay_load_action"])
        data6["udp_pay_load_action"] = le6.transform(data6["udp_pay_load_action"])

        le7 = preprocessing.LabelEncoder()
        le7.fit(data6["tcp_pay_load_action"])
        data6["tcp_pay_load_action"] = le7.transform(data6["tcp_pay_load_action"])

        le7 = preprocessing.LabelEncoder()
        le7.fit(data6["tcp_pay_load_action"])
        data6["tcp_pay_load_action"] = le7.transform(data6["tcp_pay_load_action"])

        le7 = preprocessing.LabelEncoder()
        le7.fit(data6["icmp_payload"])
        data6["icmp_payload"] = le7.transform(data6["icmp_payload"])
        
        # 转换为 float 类型
        # 遍历所有列
        for column in data6.columns:
            # 检查列的数据类型是否为Object
            if data6[column].dtype == 'object':
                # 将该列的值全部置为0
                data6[column] = 0
                # 将该列的数据类型改为float
                data6[column] = data6[column].astype(float)

        # 将整个DataFrame的数据类型改为float
        data6 = data6.astype(float)
        
        data7 = data6.copy()
        # 获取特定列的均值
        # 将特定列的值除以均值
        data7["tcp_seq_number"] = data7["tcp_seq_number"] / data7["tcp_seq_number"].mean() if data7["tcp_seq_number"].mean() != 0 else 1
        data7["tcp_ack_number"] = data7["tcp_ack_number"] / data7["tcp_ack_number"].mean() if data7["tcp_ack_number"].mean() != 0 else 1
        data7["tcp_window_size"] = data7["tcp_window_size"] / data7["tcp_window_size"].mean() if data7["tcp_window_size"].mean() != 0 else 1
        data7["tcp_checksum"] = data7["tcp_checksum"] / data7["tcp_checksum"].mean() if data7["tcp_checksum"].mean() != 0 else 1
        data7["icmp_checksum"] = data7["icmp_checksum"] / data7["icmp_checksum"].mean() if data7["icmp_checksum"].mean() != 0 else 1
        data7["icmp_seq"] = data7["icmp_seq"] / data7["icmp_seq"].mean() if data7["icmp_seq"].mean() != 0 else 1
        data7["udp_checksum"] = data7["udp_checksum"] / data7["udp_checksum"].mean() if data7["udp_checksum"].mean() != 0 else 1
        
        print('pkg feature extracted after shape: ', data7.shape)
        data6.to_csv(featured_csvpath, index=False)
        return


class CsvfeatureExtractOp():
    def __init__(self, csvpath, featured_csvpath, isadded=False):
        self.csvpath=csvpath
        self.featured_csvpath=featured_csvpath
        self.isadded=isadded

    def extract(self):
        GetFeature().make_features(self.csvpath, self.featured_csvpath)
        print(f"Feature data has been saved to {self.featured_csvpath}.")


if __name__=="__main__":
    op = CsvfeatureExtractOp('data/csv/test.csv', 'data/featured_csv/test.csv', isadded=False)
    op.extract()