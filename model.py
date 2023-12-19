import torch
from torch import nn
import torch.nn.functional as F

class Net(nn.Module):
    def __init__(self, indim):
        super(Net, self).__init__()
        self.indim = indim
        
        if indim not in [23, 43, 72]:
            raise ValueError("Unsupported input dimension. Supported dimensions are 23, 27, 43, and 72.")
        
        # 使用更多卷积层和全连接层
        self.conv1 = nn.Conv1d(1, 32, kernel_size=3, stride=1, padding=1)
        self.conv2 = nn.Conv1d(32, 64, kernel_size=3, stride=1, padding=1)
        self.conv3 = nn.Conv1d(64, 128, kernel_size=3, stride=1, padding=1)
        self.pool = nn.MaxPool1d(kernel_size=2, stride=2)
        
        # 动态调整全连接层的输入维度
        if indim == 23:
            self.fc1 = nn.Linear(128 * 3, 256)
        elif indim == 43:
            self.fc1 = nn.Linear(128 * 5, 256)
        elif indim == 72:
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
        if self.indim == 23:
            x = x.view(-1, 128 * 3)
        elif self.indim == 43:
            x = x.view(-1, 128 * 5)
        elif self.indim == 72:
            x = x.view(-1, 128 * 9)
        
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        
        return x