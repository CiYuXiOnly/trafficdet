'''
Description: 
version: 
Author: zlx
Date: 2023-12-13 12:48:32
LastEditors: zlx
LastEditTime: 2023-12-13 15:51:14
'''
import pandas as pd
import numpy as np
data_path = "./alg/dataset/UNSW-NB15/"
unsw = pd.read_csv(data_path+"UNSW-NB15_1.csv", header=None)

# 恶意流量源ip随机化
srcip_list = ["172.16.0.1","172.17.0.1","172.18.0.1","172.19.0.1","172.20.0.1","172.21.0.1","172.22.0.1","172.23.0.1",
              "172.24.0.1","172.25.0.1","172.26.0.1","172.27.0.1","172.28.0.1","172.29.0.1","172.30.0.1","172.31.0.1"]
unsw1 = unsw.copy()
unsw1[0] = np.random.choice(srcip_list, unsw1.shape[0])

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

# 标准化
unsw2.iloc[:,2:-2] = unsw2.iloc[:,2:-2].apply(lambda x: (x-x.mean())/ x.std(), axis=0)
# print(unsw2.head())

# 47列多分类标签编码
# 47列多分类标签正常流量标签设为Normal
unsw3 = unsw2.copy()
unsw3[47] = unsw3[47].fillna("Normal")
unsw3[47] = unsw3[47].replace({'Normal':1, 'Exploits':1, 'Reconnaissance':2, 'DoS':3, 'Generic':4,
                           'Shellcode':5, ' Fuzzers':6, 'Worms':7, 'Backdoors':8, 'Analysis':9})
unsw3[47].unique()
unsw3["mul"] = unsw3[47]
unsw3["bin"] = unsw3[48]
unsw3 = unsw3.drop([47,48], axis=1)
# print(unsw3["mul"].unique())
# print(unsw3["bin"].unique())

# 去掉源和目的ip端口
unsw4 = unsw3.copy()
unsw4.drop(columns=[0,2], inplace=True)

# 保存处理后的数据
print(unsw4.shape[1])
unsw4.to_csv(data_path+"resnet/data.csv", index=False)

# 检查保存的数据
# 验证是否保存成功
try:
    _ = pd.read_csv(data_path+"resnet/data.csv")
    print(unsw4.shape)
except Exception as e:
    print(f"An error occurred: {e}")

print('Done!')


