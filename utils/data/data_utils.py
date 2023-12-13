'''
Description: 
version: 
Author: zlx
Date: 2023-12-08 10:16:31
LastEditors: zlx
LastEditTime: 2023-12-09 12:49:46
'''

import pandas as pd  
import numpy as np  
from torch.utils.data import Dataset, DataLoader, random_split
import torch
  
# 自定义数据集类，继承自Dataset类    
class CustomDataset(Dataset):
    def __init__(self, data, targets, num_classes):
        self.data = data.astype(np.float32)
        self.targets = targets.astype(np.int64)
        self.num_classes = num_classes

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        x = self.data[idx]
        y = torch.zeros(self.num_classes)
        y[self.targets[idx]] = 1
        return x, y  


class GetDataObj():
    def __init__(self):
        pass
    
    # 根据dataframe创建创建DataLoader对象
    def get_dataloader(self, df, num_classes=2, batch_size=32):
        
        # 将DataFrame转换为NumPy数组  
        data = df.drop('label', axis=1).values.astype(np.float32)
        targets = df['label'].values.astype(np.int64) 
        
        # 创建自定义数据集对象  
        dataset = CustomDataset(data, targets, num_classes)  
        
        # 创建DataLoader对象，使用自定义数据集  
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        return dataloader
    
    def get_splited_dataloader(self, df, num_classes, batch_size=32, train_ratio=0.8):
        
        data_loader = self.get_dataloader(df, num_classes=2, batch_size=32)
        
        # 确定训练集和测试集的划分比例    
        test_ratio = 1 - train_ratio  

        # 获取数据集的总大小  
        total_size = len(data_loader.dataset)  

        # 计算训练集和测试集的大小  
        train_size = int(total_size * train_ratio)  
        test_size = total_size - train_size  

        # 使用random_split划分数据集  
        train_dataset, test_dataset = random_split(data_loader.dataset, [train_size, test_size])  

        # 重新创建DataLoader以使用新的数据集  
        train_dataloader = DataLoader(dataset=train_dataset, batch_size=batch_size, shuffle=True)  
        test_dataloader = DataLoader(dataset=test_dataset, batch_size=batch_size, shuffle=False)
        
        return train_dataloader, test_dataloader
    
    # 根据csv文件生成有标签dataframe
    def get_df_from_featured_csv_add_label(self, featured_csv_path, label):
        
        df = pd.read_csv(featured_csv_path)
        
        # 添加label列，并赋值
        if label=='good':
            df['label'] = 0
        elif label=='bad':
            df['label'] = 1
        elif label=='unknown':
            df['label'] = 2
        else:
            raise Exception('label error')
        
        # print(df.head())
        
        return df
    
    # 根据csv文件生成无标签dataframe
    def get_df_from_featured_csv(self, featured_csv_path):
        
        df = pd.read_csv(featured_csv_path)
        
        # print(df.head())
        
        return df