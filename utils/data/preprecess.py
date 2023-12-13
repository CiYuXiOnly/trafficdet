'''
Description: 
version: 
Author: zlx
Date: 2023-12-09 14:10:33
LastEditors: zlx
LastEditTime: 2023-12-11 17:03:32
'''
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

'''
对dataframe进行预处理, 比如处理缺失值, 规范化(去量纲)
'''

def precess_nan_and_scaler(df):
    # 处理缺失值
    df.fillna(0, inplace=True)

    # 规范化
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(df.values)
    # 将标准化后的数据转换回 DataFrame
    df_scaled = pd.DataFrame(data_scaled, columns=df.columns)

    return df_scaled

