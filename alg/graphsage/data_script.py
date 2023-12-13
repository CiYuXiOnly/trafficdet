'''
Description: 
version: 
Author: zlx
Date: 2023-12-11 12:04:03
LastEditors: zlx
LastEditTime: 2023-12-13 13:33:10
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

# 保存处理后的数据
unsw2.to_pickle(data_path+"graphsage/unsw.pkl")

# 把特征值作为边特征保存
unsw3 = unsw2.copy()
edge_feat = unsw3.iloc[:,2:45].to_numpy()
np.save(data_path+"graphsage/edge_feat_scaled.npy", edge_feat)

# 保存节点信息
srcnode = set(unsw3[0])
dtnode = set(unsw3[2])
nodes = list(dtnode.union(srcnode))
print(len(nodes))
np.save(data_path+"graphsage/nodes.npy", nodes)

# 48列是二分类标签，是0或1，不用转换，直接保存
binary = unsw3[48].to_numpy()
np.save(data_path+"graphsage/label_bi.npy", binary)

# 保存邻接表
'''
['59.166.0.0:1390', '149.171.126.6:53'],
['59.166.0.0:33661', '149.171.126.9:1024'],
...
'''
adj = unsw3[[0,2]].to_numpy()
np.save(data_path+"graphsage/adj.npy", adj)

# 47列多分类标签编码
# 47列多分类标签正常流量标签设为Normal
unsw2[47] = unsw2[47].fillna("Normal")
multi = unsw2[47].replace({'Normal':0, 'Exploits':1, 'Reconnaissance':2, 'DoS':3, 'Generic':4,
                           'Shellcode':5, ' Fuzzers':6, 'Worms':7, 'Backdoors':8, 'Analysis':9})
multi = multi.astype(np.int16)
np.save(data_path+"graphsage/label_mul.npy", multi)

# 验证是否保存成功
try:
    _ = np.load(data_path+"graphsage/unsw.pkl", allow_pickle=True)
    _ = np.load(data_path+"graphsage/edge_feat_scaled.npy")
    _ = np.load(data_path+"graphsage/nodes.npy", allow_pickle=True)
    _ = np.load(data_path+"graphsage/label_bi.npy")
    _ = np.load(data_path+"graphsage/label_mul.npy")
    _ = np.load(data_path+"graphsage/adj.npy", allow_pickle=True)
except Exception as e:
    print(f"An error occurred: {e}")

print("Done!")
