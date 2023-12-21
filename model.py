'''
Description: 
version: 
Author: zlx
Date: 2023-12-08 09:55:03
LastEditors: zlx
LastEditTime: 2023-12-21 16:07:32
'''
import torch
from torch import nn
import torch.nn.functional as F

class Net(nn.Module):
    def __init__(self, indim):
        super(Net, self).__init__()
        self.indim = indim
        
        if indim not in [72]:
            raise ValueError("Unsupported input dimension. Supported dimensions are 72.")
        
        self.conv1 = nn.Conv1d(1, 32, kernel_size=3, stride=1, padding=1)
        self.conv2 = nn.Conv1d(32, 64, kernel_size=3, stride=1, padding=1)
        self.conv3 = nn.Conv1d(64, 128, kernel_size=3, stride=1, padding=1)
        self.pool = nn.MaxPool1d(kernel_size=2, stride=2)
        
        # 动态调整全连接层的输入维度
        if indim == 72:
            self.fc1 = nn.Linear(128 * 9, 256)
        
        self.fc2 = nn.Linear(256, 64)
        self.fc3 = nn.Linear(64, 2)
        
    def forward(self, x):
        x = x.unsqueeze(1)
        
        # 多层卷积和池化
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = self.pool(F.relu(self.conv3(x)))
        
        # 根据输入维度调整全连接层的输入维度
        if self.indim == 72:
            x = x.view(-1, 128 * 9)
        
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        
        return x

class MyLSTM(nn.Module):  
    def __init__(self, input_size, hidden_size, output_size=2):  
        super(MyLSTM, self).__init__()  
        
        self.hidden_size = hidden_size  
        self.lstm = nn.LSTM(input_size, hidden_size, bidirectional=True)  
        self.fc = nn.Linear(hidden_size * 2, output_size)  # 双向LSTM的输出是隐藏状态的2倍  
    
    def forward(self, x):  
        h0 = torch.zeros(1, x.size(0), self.hidden_size)  # 初始化隐藏状态  
        c0 = torch.zeros(1, x.size(0), self.hidden_size)  # 初始化细胞状态  
        
        out, _ = self.lstm(x, (h0, c0))  # LSTM的输出包含最终的隐藏状态和最后的细胞状态  
        out = out[:, -1, :]  # 取最后一个时间步的输出  
        out = self.fc(out)  # 全连接层得到最终输出  
        return out