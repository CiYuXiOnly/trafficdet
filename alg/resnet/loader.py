'''
Description: 
version: 
Author: zlx
Date: 2023-12-13 12:48:17
LastEditors: zlx
LastEditTime: 2023-12-13 15:52:19
'''
import numpy as np
import torch
import pandas as pd
from torch.utils.data import Dataset, DataLoader, random_split

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
        # 自动one-hot编码
        y = torch.zeros(self.num_classes)
        y[self.targets[idx]] = 1
        return x, y

# 根据dataframe创建创建DataLoader对象
def get_dataloader(df, num_classes, batch_size=32):
    # 将DataFrame转换为NumPy数组
    data = df.drop('label', axis=1).values # data[n, n_feature]
    # Reshape the data to (n, n_feature, 1, 1)
    # reshaped_data.shape will be (n, (n_feature, 1, 1))
    data = data.reshape(data.shape[0], data.shape[1], 1, 1)

    targets = df['label'].values 
    # 创建自定义数据集对象
    dataset = CustomDataset(data, targets, num_classes)  
    # 创建DataLoader对象，使用自定义数据集 
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    return dataloader

def get_splited_dataloader(df, num_classes, batch_size, train_ratio=0.8):
        data_loader = get_dataloader(df, num_classes, batch_size)
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
    
def unsw_dataloader(path, num_classes, batch_size, train_ratio=0.8):
    df = pd.read_csv(path)
    if num_classes == 2:
        df['label'] = df['bin']
    elif num_classes == 10:
        df['label'] = df['mul']
    else:
        print("Error: num_classes must be 2 or 10")
        return
    df = df.drop(["mul","bin"], axis=1)
    # test
    df = df[:20000]
    train_dataloader, test_dataloader = get_splited_dataloader(df, num_classes, batch_size, train_ratio)
    return train_dataloader, test_dataloader


if __name__ == '__main__':
    print()
    unsw_dataloader('./alg/dataset/UNSW-NB15/resnet/data.csv', 10, 32, 0.8)