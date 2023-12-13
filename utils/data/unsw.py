'''
Description: 
version: 
Author: Zhang Lingxin
Date: 2023-12-11 12:04:03
LastEditors: Zhang Lingxin
LastEditTime: 2023-12-11 12:06:29
'''
import pandas as pd
import numpy as np
unsw = pd.read_csv("dataset/unsw/UNSW-NB15_1.csv", header=None)

# 恶意流量源ip随机化
srcip_list = ["172.16.0.1","172.17.0.1","172.18.0.1","172.19.0.1","172.20.0.1","172.21.0.1","172.22.0.1","172.23.0.1",
              "172.24.0.1","172.25.0.1","172.26.0.1","172.27.0.1","172.28.0.1","172.29.0.1","172.30.0.1","172.31.0.1"]
unsw1 = unsw.copy()
unsw1[0] = np.random.choice(srcip_list, unsw1.shape[0])
unsw1[unsw1.iloc[:,47].notna()][0].unique()

# ip和端口合并
unsw2 = unsw.copy()
unsw2[0] = unsw2[0].astype(str)+":"+unsw2[1].astype(str)
unsw2[2] = unsw2[2].astype(str)+":"+unsw2[3].astype(str)
unsw2.drop(columns=[1,3], inplace=True)

# 对协议等信息进行普通类别编码
from sklearn import preprocessing
le1 = preprocessing.LabelEncoder()
le1.fit(unsw2[4])
unsw2[4] = le1.transform(unsw2[4])
le2 = preprocessing.LabelEncoder()
le2.fit(unsw2[5])
unsw2[5] = le2.transform(unsw2[5])
le3 = preprocessing.LabelEncoder()
le3.fit(unsw2[13])
unsw2[13] = le3.transform(unsw2[13])

# 47列多分类标签正常流量标签设为Normal
# 48列二分类标签
unsw2[47] = unsw2[47].fillna("Normal")
# 47列多分类标签编码
multi = unsw2[47].replace({'Normal':1, 'Exploits':1, 'Reconnaissance':2, 'DoS':3, 'Generic':4,
                           'Shellcode':5, ' Fuzzers':6, 'Worms':7, 'Backdoors':8, 'Analysis':9})

# 标准化
unsw2.iloc[:,2:-2] = unsw2.iloc[:,2:-2].apply(lambda x: (x-x.mean())/ x.std(), axis=0)
unsw2.head()

# 去掉列
unsw3 = unsw2.copy()
unsw3["label"] = unsw3[48]
unsw3 = unsw3.drop([0,2,47,48], axis=1)

# 获取每一列的数据类型  
column_dtypes = unsw3.dtypes  

list = []
# 每一列的数据类型  
for column_name, dtype in column_dtypes.items():  
    i = str(dtype)
    list.append(i)

unsw3.to_csv('unsw.csv', index=False)

