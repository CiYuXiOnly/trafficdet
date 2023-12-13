import sys

import numpy as np
import torch
from torch import nn
import torch.nn.functional as F
from torch.autograd import Variable


# 用卷积模块实现一个残差块
class residual_block(nn.Module):
    def __init__(self, in_channel, out_channel, same_shape=True):
        super(residual_block, self).__init__()
        self.same_shape = same_shape
        stride=1 if self.same_shape else 2

        self.conv1 = nn.Conv2d(in_channel, out_channel, 3, stride=stride, padding=1, bias=False)
        self.bn1 = nn.BatchNorm2d(out_channel)

        # conv2 的输入通道数与 conv1 的输出通道数一致
        # conv1 stride=1, conv2 stride=1
        # conv1 stride=2, conv2 stride=1
        self.conv2 = nn.Conv2d(out_channel, out_channel, 3, stride=1, padding=1, bias=False)
        self.bn2 = nn.BatchNorm2d(out_channel)
        
        # 如果输入输出形状不同，需要把输入形状转换成输出形状
        if not self.same_shape:
            self.conv3 = nn.Conv2d(in_channel, out_channel, 1, stride=stride)

    def forward(self, x):
        out = self.conv1(x)
        out = F.relu(self.bn1(out), True)
        out = self.conv2(out)
        out = F.relu(self.bn2(out), True)

        # 如果输入输出形状不同，需要把输入形状转换成输出形状
        if not self.same_shape:
            x = self.conv3(x)
         
        # 残差连接
        # 原始输入（可能经过形状变换）和经过卷积批归一化处理的数据相加，
        # 然后应用 ReLU 激活函数。
        return F.relu(x+out, True)
    
# 测试残差块的输出
def test_residual_block():
    net = residual_block(32, 16, False)
    x = Variable(torch.zeros(1, 32, 96, 96))
    y = net(x)
    print(y.shape)
    
    net = residual_block(16, 16, False)
    x = Variable(torch.zeros(1, 16, 64, 64))
    y = net(x)
    print(y.shape)
    
    net = residual_block(43, 64, False)
    # x[b, feature_num]
    x = Variable(torch.zeros(5, 43))
    x = x.unsqueeze(-1).unsqueeze(-1)  # 将 x 扩展为 (1, 43, 1, 1) 的四维张量
    y = net(x)  # 将张量输入到残差块中进行处理
    print(y.shape)

  
# 实现一个 ResNet，它就是 residual block 模块的堆叠
class ResNet(nn.Module):
    def __init__(self, in_channel, num_classes):
        super(ResNet, self).__init__()

        self.block1 = nn.Conv2d(in_channel, 64, 1, 1)

        self.block2 = nn.Sequential(
            residual_block(64, 64),
            residual_block(64, 64)
        )

        self.block3 = nn.Sequential(
            residual_block(64, 128, False),
            residual_block(128, 128)
        )

        self.block4 = nn.Sequential(
            residual_block(128, 256, False),
            residual_block(256, 256)
        )
        
        # 全局池化, 降维
        self.pooling = nn.AdaptiveAvgPool2d((1,1))

        self.classifier = nn.Linear(256, num_classes)

    def forward(self, x):
        x = self.block1(x)
        # print('block 1 output: {}'.format(x.shape))
        
        x = self.block2(x)
        # print('block 2 output: {}'.format(x.shape))
        
        x = self.block3(x)
        # print('block 3 output: {}'.format(x.shape))
        
        x = self.block4(x)
        # print('block 4 output: {}'.format(x.shape))
        
        x = self.pooling(x)
        # print('pooling output: {}'.format(x.shape))
        
        x = x.view(x.shape[0], -1)
        x = self.classifier(x)
        return x
    
# 测试 ResNet 的输出
def test_resnet():
    net = ResNet(32, 3)
    x = Variable(torch.randn(1, 32, 96, 96))
    y = net(x)
    print(y.shape)
    
    net = ResNet(43, 2)
    # x[b, feature_num]
    x = Variable(torch.zeros(11, 43))
    x = x.unsqueeze(-1).unsqueeze(-1)  # 将 x 扩展为 (b, 43, 1, 1) 的四维张量
    y = net(x)
    print(y.shape)
    
    
if __name__ == '__main__':
    print()
    test_residual_block()
    test_resnet()