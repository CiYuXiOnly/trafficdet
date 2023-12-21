'''
Description: 
version: 
Author: zlx
Date: 2023-12-09 14:14:33
LastEditors: zlx
LastEditTime: 2023-12-21 16:01:11
'''

'''
基于pytorch的训练代码
'''
import pandas as pd
from model import Net
from model_operate import ModelOperation
from utils.data.data_utils import GetDataObj
from utils.data.preprecess import precess_nan_and_scaler


def flow_based_train():
    model_usr = ModelOperation()
    print()
    print('++++++++++++++++基于流检测+++++++++++++++')
    print('=============CIC-IDS-2017数据集=============')
    
    model = Net(indim=72)
    op = GetDataObj()
    df_good = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/benign_small_flow.csv', label='good')
    df_bad = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/malicious_small_flow.csv', label='bad')
    df = pd.concat([df_good, df_bad])
    df = df.drop(["src", "sport", "dst", "dport"], axis=1)
    df = precess_nan_and_scaler(df) # 处理缺失值和标准化
    train_dataloader, test_dataloader  = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)

    # 训练模型
    model_path = 'model/flow_model_CIC.pth'
    model_usr.train_test(model=model, 
                         train_dataloader=train_dataloader, 
                         test_dataloader=test_dataloader,
                         num_epochs=20, 
                         model_path=model_path,
                         per_print=20
                         )
    print('模型保存在 {}'.format(model_path))


def scts_train():
    print()
    print('+++++++++++++++ scts_extractor ++++++++++++++')
    print('=============CIC-IDS-2017数据集=============')
    
    model_usr = ModelOperation()
    model = Net(indim=72)
    op = GetDataObj()
    df_good = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/benign_small_scts.csv', label='good')
    df_bad = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/malicious_small_scts.csv', label='bad')
    df = pd.concat([df_good, df_bad])
    train_dataloader, test_dataloader  = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)
    
    # 训练模型
    model_path = 'model/scts_model_CIC.pth'
    model_usr.train_test(model=model, 
                         train_dataloader=train_dataloader, 
                         test_dataloader=test_dataloader,
                         num_epochs=20, 
                         model_path=model_path,
                         per_print=20
                         )
    print('模型保存在 {}'.format(model_path))
    return


def main():
    
    flow_based_train()
    
    # scts_train()
    
    return


if __name__ == "__main__":
    print()
    main()
    
    