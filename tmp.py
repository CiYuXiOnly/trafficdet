
'''
Description: 
version: 
Author: zlx
Date: 2023-12-08 09:34:30
LastEditors: zlx
LastEditTime: 2023-12-20 15:54:23
'''
from sklearn.model_selection import train_test_split
from utils.data.data_utils import GetDataObj, CustomDataset
from model import Net
from model_operate import ModelOperation
import torch
from torch.utils.data import DataLoader  
import pandas as pd

'''
此部分代码仅用于测试功能
'''

def test2():
    op = GetDataObj()
    '''
    good 0
    bad 1
    unknown 2
    '''
    df = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/good.csv', label='good')
    # print(df)
    dataloader = op.get_dataloader(df, batch_size=2)
    print(dataloader)
    
    # 测试dataloader是否正常运行
    for epoch in range(1):  # num_epochs表示训练的轮数  
        for i, (inputs, targets) in enumerate(dataloader):   
            if i == 1:
                inputs = torch.tensor(inputs, dtype=torch.float32)  
                targets = torch.tensor(targets, dtype=torch.long)
                # 打印输入数据和目标值  
                print("Input data:\n", inputs)  
                print("Targets shape:\n", targets.shape)
                break       
    return

def test3():
    op = GetDataObj()
    df_good = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/good.csv', label='good')
    df_bad = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/bad.csv', label='bad')
    
    df = pd.concat([df_good, df_bad])
    
    dataloader = op.get_dataloader(df, num_classes=2, batch_size=32)
    train_dl,test_dl = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)   
    print(train_dl)
    print(test_dl)
    return

def test4():
    
    net = Net(indim=23) # 特征数，这里是10
    usemodel = ModelOperation()
    
    return


if __name__=='__main__':
    print()
    
    # test0()
    
    # test1()
    
    # test2()
    
    # test3()
    
    # test4()
    