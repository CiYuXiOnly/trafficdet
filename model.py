'''
Description: 
version: 
Author: Zhang Lingxin
Date: 2023-12-08 09:55:03
LastEditors: Zhang Lingxin
LastEditTime: 2023-12-12 10:43:23
'''
import torch
from torch import nn
import torch.nn.functional as F

class Net(nn.Module):
    def __init__(self, indim):
        super(Net, self).__init__()
        self.indim = indim
        
        if indim not in [23, 43, 72]:
            raise ValueError("Unsupported input dimension. Supported dimensions are 23, 27, 43, and 72.")
        
        # 动态创建卷积层
        if indim == 23:
            self.conv1 = nn.Conv1d(1, 16, kernel_size=2, stride=1, padding=1)
        elif indim == 43:
            self.conv1 = nn.Conv1d(1, 16, kernel_size=4, stride=1, padding=1)
        elif indim == 72:
            self.conv1 = nn.Conv1d(1, 16, kernel_size=5, stride=1, padding=2)
            
        # 动态创建池化层
        self.pool = nn.MaxPool1d(kernel_size=2, stride=2)
        
        # 定义全连接层
        if indim == 23:
            self.fc1 = nn.Linear(16 * 12, 64)
        elif indim == 43:
            self.fc1 = nn.Linear(16 * 20, 64)
        elif indim == 72:
            self.fc1 = nn.Linear(16 * 36, 64)
            
        self.fc2 = nn.Linear(64, 2)
        
    def forward(self, x):
        # 输入x的维度为 [batch_size, indim]
        x = x.unsqueeze(1)  # 在第二个维度上增加一个维度，变成 [batch_size, 1, indim]
        x = self.conv1(x)
        x = F.relu(x)
        x = self.pool(x)
        
        # 根据输入维度动态调整全连接层的输入维度
        if self.indim == 23:
            x = x.view(-1, 16 * 12)  # 展开成一维向量
        elif self.indim == 27:
            x = x.view(-1, 16 * 14)  # 展开成一维向量
        elif self.indim == 43:
            x = x.view(-1, 16 * 20)  # 展开成一维向量
        elif self.indim == 72:
            x = x.view(-1, 16 * 36)  # 展开成一维向量
            
        x = self.fc1(x)
        x = F.relu(x)
        x = self.fc2(x)
        
        return x