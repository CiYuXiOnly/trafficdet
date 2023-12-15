
'''
Description: 
version: 
Author: zlx
Date: 2023-12-08 09:34:30
LastEditors: zlx
LastEditTime: 2023-12-15 21:03:24
'''
from sklearn.model_selection import train_test_split
from extractor.pkg_based.pcap2csv import Pcap2csvOp
from extractor.pkg_based.csv_feature import CsvfeatureExtractOp
from utils.data.data_utils import GetDataObj, CustomDataset
from model import Net
from model_operate import ModelOperation
import torch
from torch.utils.data import DataLoader  
import pandas as pd

from extractor.flow_based.pcap_flow_feature import FlowProcess
from extractor.sess_based.pcap_sess_feature import SessProcess
'''
此部分代码仅用于测试功能
'''

def test0():
    # op1 = Pcap2csvOp(pcapfilepath='data/pcap/test.pcap', csvfilepath='data/csv/test.csv', isadded=False)
    # # pcap生成csv
    # op1.generateCSV()
    
    op2 = CsvfeatureExtractOp(csvpath='data/csv/test.csv', featured_csvpath='data/featured_csv/test.csv', isadded=False)
    # 对生成的csv进行特征提取
    op2.extract()
    return

def test1():
    # op1 = Pcap2csvOp(pcapfilepath='data/pcap/benign_small.pcap', csvfilepath='data/csv/benign_small_pkg.csv', isadded=False)
    # op2 = CsvfeatureExtractOp(csvpath='data/csv/benign_small_pkg.csv', featured_csvpath='data/featured_csv/benign_small_pkg.csv', isadded=False)
    # # pcap生成csv
    # op1.generateCSV()
    # # 对生成的csv进行特征提取
    # op2.extract()
    
    op1 = Pcap2csvOp(pcapfilepath='data/pcap/malicious_small.pcap', csvfilepath='data/csv/malicious_small_pkg.csv', isadded=False)
    op2 = CsvfeatureExtractOp(csvpath='data/csv/malicious_small_pkg.csv', featured_csvpath='data/featured_csv/malicious_small_pkg.csv', isadded=False)
    # pcap生成csv
    op1.generateCSV()
    # 对生成的csv进行特征提取
    op2.extract()
    return

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


def test5():
    
    
    config = {  
        "run_mode": "flow",  
        "pcap_loc": "data/pcap",  
        "pcap_name": "benign_small.pcap",  
        "csv_path": "data/featured_csv/benign_small_flow.csv",  
        "print_colname": True,  
        "read_all": False
    }
    p = FlowProcess(config)
    p.extract_flow_feature_from_pcap()
    
    config = {  
        "run_mode": "flow",  
        "pcap_loc": "data/pcap",  
        "pcap_name": "malicious_small.pcap",  
        "csv_path": "data/featured_csv/malicious_small_flow.csv",  
        "print_colname": True,  
        "read_all": False
    }
    p = FlowProcess(config)
    p.extract_flow_feature_from_pcap()
    return

def test6():
    '''
    基于包的检测
    '''
    from model import Net
    model_usr = ModelOperation()
    print('+++++++++++++基于包的检测+++++++++++++++')
    '''
    原始数据集
    '''
    print('==============原始数据集=============')
    model = Net(indim=23)
    op = GetDataObj()
    df_good = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/good.csv', label='good')
    df_bad = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/bad.csv', label='bad')
    df = pd.concat([df_good, df_bad])
    train_dataloader, test_dataloader  = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)

    # 训练模型
    model_usr.train_test(model=model, train_dataloader=train_dataloader, test_dataloader=test_dataloader, model_path='model/pkg_model.pth')

    '''
    CIC-IDS-2017数据集
    '''
    print('==============CIC-IDS-2017数据集=============')
    model = Net(indim=23)
    op = GetDataObj()
    df_good = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/benign_small_pkg.csv', label='good')
    df_bad = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/malicious_small_pkg.csv', label='bad')
    df = pd.concat([df_good, df_bad])
    train_dataloader, test_dataloader  = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)

    # 训练模型
    model_usr.train_test(model=model, 
                         train_dataloader=train_dataloader, 
                         test_dataloader=test_dataloader, 
                         model_path='model/pkg_model_CIC.pth',
                         per_print=20
                         )

def test7():
    '''
    基于流的检测
    '''
    from model import Net
    model_usr = ModelOperation()
    print()
    print('++++++++++++++++基于流检测+++++++++++++++')
    print('=========原始数据集没有提供pcap文件, 跳过=============')
    print('=============CIC-IDS-2017数据集=============')
    
    model = Net(indim=72)
    op = GetDataObj()
    df_good = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/benign_small_flow.csv', label='good')
    df_bad = op.get_df_from_featured_csv_add_label(featured_csv_path='data/featured_csv/malicious_small_flow.csv', label='bad')
    df = pd.concat([df_good, df_bad])
    df = df.drop(["src", "sport", "dst", "dport"], axis=1)
    train_dataloader, test_dataloader  = op.get_splited_dataloader(df, num_classes=2, batch_size=32, train_ratio=0.8)

    # 训练模型
    model_usr.train_test(model=model, 
                         train_dataloader=train_dataloader, 
                         test_dataloader=test_dataloader, 
                         model_path='model/flow_model_CIC.pth',
                         per_print=20
                         )
    
def test8():
    '''
    给定一个pcap文件, 利用模型进行检测
    '''
    print()
    print('+++++++++++++基于包的检测+++++++++++++++')
    op = ModelOperation()
    detail, final_label, prob = op.pcap_predict(pcap_path='upload/malicious_sample.pcap', 
                    model_path='model/pkg_model.pth', 
                    extract_type='pkg', 
                    threshold=0.5)
    # print(detail)
    print()
    print('pcap文件类别是: ', final_label)
    print('属于该类别的可能性: ', prob)
    
    print()
    print('+++++++++++++基于流的检测+++++++++++++++')
    op = ModelOperation()
    detail, final_label, prob = op.pcap_predict(pcap_path='upload/malicious_sample.pcap', 
                    model_path='model/flow_model_CIC.pth', 
                    extract_type='flow', 
                    threshold=0.6)
    # print(detail)
    print()
    print('pcap文件类别是: ', final_label)
    print('属于该类别的可能性: ', prob)
    return

def test9():
    op = SessProcess()
    op.extract_sess_feature_from_pcap(pcap_path='data/pcap/test.pcap', 
                                      csv_path='data/featured_csv/test_sess.csv',
                                      label='0',
                                      per_print=10)
    return


def test10():
    '''
    测试exactor/tshark_flow
    '''
    from extractor.tshark_flow.tshark_feat_extract import TsharkExtractorProcess
    tp = TsharkExtractorProcess(pcap_path='upload/1.pcap', 
                                output_dir='./',
                                saved_file_type='json')
    tp.extract(target="tls", isall=False)

    
    return


if __name__=='__main__':
    print()
    
    # test0()
    
    # test1()
    
    # test2()
    
    # test3()
    
    # test4()
    
    # test5()
    
    # test6()

    # test7()
    
    # test8()
    
    # test9()
    
    test10()