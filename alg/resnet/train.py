'''
Description: 
version: 
Author: zlx
Date: 2023-12-13 13:40:22
LastEditors: zlx
LastEditTime: 2023-12-13 15:54:13
'''
import argparse
import numpy as np
import torch
from alg.resnet.model import ResNet
from alg.resnet.loader import unsw_dataloader
from torch import nn

data_class = {"UNSW-NB15":10}
data_lr = {"UNSW-NB15":0.01}
data_feats = {"UNSW-NB15":43}

def fit(dataset, train_loader, test_loader, num_class, model_save_path, epoch, per_print=100):
    # ResNet(feature_num, num_class)
    net = ResNet(data_feats[dataset], num_class)
    optimizer = torch.optim.SGD(net.parameters(), lr=data_lr[dataset])
    criterion = nn.CrossEntropyLoss()
    
    for e in range(epoch):
        net.train()
        for idx, (x, y) in enumerate(train_loader):
            # x[b, feature_num, 1, 1]
            # print(x.shape)
            output = net(x)
            loss = criterion(output, y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            if idx % per_print == 0:
                print('Epoch: {}, idx: {}, loss: {}'.format(e+1, idx, loss.item()))
        
        # save model
        # 保存模型参数  
        torch.save(net.state_dict(), model_save_path)
        
        # 测试
        net.eval()
        running_acc = 0.0
        losses, nums = [], []
        for x, y in test_loader:
            out = net(x)
            loss = criterion(out, y)
            
            # print(out.shape)
            # print(y.shape)
            # # pred and y [b, num_class] (one-hoted)
            
            # 计算准确率
            pred = torch.argmax(out, dim=1).squeeze()
            y_true = torch.argmax(y, dim=1).squeeze()
            correct = (pred == y_true).float().sum()  
            running_acc += correct.item()
    
            losses.append(loss.item())
            # 当前批次样本数
            nums.append(x.size(0))

        # print(np.sum(nums))
        test_avg_loss = np.sum(np.multiply(losses, nums)) / np.sum(nums)
        test_acc = running_acc / np.sum(nums)
        print('Epoch: {}, 验证集平均损失：{} 验证集准确率：{}'.format(e+1, test_avg_loss, test_acc))


if __name__ == '__main__':

    DATASET = ['UNSW-NB15']
    isbinary = [1, 0]
    
    p = argparse.ArgumentParser()
    p.add_argument('--dataset',
                   help='Experimental dataset.',
                   type=str,
                   default='UNSW-NB15',
                   choices=DATASET)
    p.add_argument('--binary',
                   help='Perform binary or muticlass task',
                   type=int,
                   choices=isbinary,
                   default=1)

    args = p.parse_args()
    
    dataset = args.dataset
    if args.binary:
        num_class = 2
    else:
        num_class = data_class[dataset]
    
    print('num_class: {}'.format(num_class))
    
    data_path = 'alg/dataset/'+ dataset + '/resnet/data.csv'
    model_save_path = 'alg/resnet/model.pth'
    train_loader, test_loader = unsw_dataloader(data_path, num_class, batch_size=32, train_ratio=0.8)
    
    # Training and testing
    fit(dataset, train_loader, test_loader, num_class, model_save_path, epoch=1, per_print=100)