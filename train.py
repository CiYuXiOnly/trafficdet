'''
Description: 
version: 
Author: zlx
Date: 2023-12-09 14:14:33
LastEditors: zlx
LastEditTime: 2023-12-16 08:32:01
'''

'''
基于pytorch的训练代码
'''
import pandas as pd
from model import Net
from model_operate import ModelOperation
from utils.data.data_utils import GetDataObj
from utils.data.preprecess import precess_nan_and_scaler

def pkg_based_train():
    '''
    基于包的检测
    '''
    model_usr = ModelOperation()
    print('+++++++++++++基于包的检测+++++++++++++++')
    '''
    CIC-IDS-2017数据集
    '''
    print('==============CIC-IDS-2017数据集=============')
    model = Net(indim=23)
    op = GetDataObj()
    # 添加了标签的数据集，good和bad会指定为0和1
    df_good = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/benign_small_pkg.csv', label='good')
    df_bad = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/malicious_small_pkg.csv', label='bad')
    df = pd.concat([df_good, df_bad])
    # 标准化已经在GetFeature().make_features()中完成
    train_dataloader, test_dataloader  = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)

    # 训练模型
    model_path = 'model/pkg_model_CIC.pth'
    model_usr.train_test(model=model, 
                         train_dataloader=train_dataloader, 
                         test_dataloader=test_dataloader,
                         num_epochs=1,
                         model_path=model_path,
                         per_print=20
                         )
    print('模型保存在 {}'.format(model_path))

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

def unsw_train():
    model_op = ModelOperation()
    model = Net(indim=43)
    print('=============UNSW-NB15数据集=============')
    op = GetDataObj()
    df = pd.read_csv('data/unsw-nb15/unsw.csv')
    train_dataloader, test_dataloader  = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)
    
    # 训练模型
    model_path = 'model/model_UNSW.pth'
    model_op.train_test(model=model, 
                         train_dataloader=train_dataloader, 
                         test_dataloader=test_dataloader,
                         num_epochs=1, 
                         model_path=model_path,
                         per_print=20
                         )
    print('模型保存在 {}'.format(model_path))
    return

def sess_based_train():
    model_op = ModelOperation()
    print()
    print('++++++++++++++++基于会话检测+++++++++++++++')
    print('=============CIC-IDS-2017数据集=============')
    
    # 准备数据
    model = Net(indim=23)
    op = GetDataObj()
    # 提取特征时，已经添加了0或1标签的数据集
    df_good = op.get_df_from_featured_csv(featured_csv_path='data/featured_csv/benign_small_sess.csv')
    df_bad = op.get_df_from_featured_csv(featured_csv_path='data/featured_csv/malicious_small_sess.csv')
    df = pd.concat([df_good, df_bad])
    df = df.drop(["src_ip", "dst_ip", "sport", "dport"], axis=1)
    # print(df.columns)
    train_dataloader, test_dataloader  = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)
    
    # 训练模型
    model_path = 'model/sess_model_CIC.pth'
    model_op.train_test(model=model, 
                         train_dataloader=train_dataloader, 
                         test_dataloader=test_dataloader,
                         num_epochs=5, 
                         model_path=model_path,
                         per_print=20
                         )
    print('模型保存在 {}'.format(model_path))
    return

def tshark_based_train():
    model_op = ModelOperation()
    print()
    print('++++++++++++++++基于tshark检测+++++++++++++++')
    print('=============CIC-IDS-2017数据集=============')
    
    # 准备数据
    model = Net(indim=41)
    op = GetDataObj()
    # 提取特征时，已经添加了0或1标签的数据集
    df_good = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/benign_small_tshark.csv', label='good')
    df_bad = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/malicious_small_tshark.csv', label='bad')
    df = pd.concat([df_good, df_bad])
    df = df.drop(['src_ip', 'dest_ip', 'src_port', 'dest_port'], axis=1)
    # print(df.columns)
    train_dataloader, test_dataloader  = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)
    
    # 训练模型
    model_path = 'model/tshark_model_CIC.pth'
    model_op.train_test(model=model, 
                         train_dataloader=train_dataloader, 
                         test_dataloader=test_dataloader,
                         num_epochs=10, 
                         model_path=model_path,
                         per_print=20
                         )
    print('模型保存在 {}'.format(model_path))
    return

def main():
    # pkg_based_train()
    
    # flow_based_train()
    
    # unsw_train()
    
    # sess_based_train()
    
    tshark_based_train()
    
    return


if __name__ == "__main__":
    print()
    main()
    
    