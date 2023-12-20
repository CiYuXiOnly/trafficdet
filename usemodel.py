'''
Description: 
version: 
Author: zlx
Date: 2023-12-09 14:24:22
LastEditors: zlx
LastEditTime: 2023-12-20 15:57:42
'''

'''
使用模型判断pcap文件的恶意性
'''

from model_operate import ModelOperation

'''
this is for offline
'''

def analysis_pcap_offline_flow():
    '''
    给定一个pcap文件, 利用模型进行检测, 基于流的检测
    '''
    t = 0.85
    model_path = 'model/flow_model_CIC.pth'
    print()
    print('+++++++++++++基于流的检测+++++++++++++++')
    op = ModelOperation()
    file_path = 'upload/benign_sample.pcap'
    detail, final_label, prob, prefer = op.pcap_predict(pcap_path=file_path, 
                    model_path=model_path, 
                    extract_type='flow', 
                    threshold=t)
    # print(detail)
    print()
    print('pcap文件: {}, 模型: {}'.format(file_path, model_path))
    print('阈值: {}'.format(t))
    print('pcap文件类别是: ', final_label)
    print('属于{}类别的可能性: {}'.format(prefer, prob))
    
    print()
    op = ModelOperation()
    file_path = 'upload/malicious_sample.pcap'
    detail, final_label, prob, prefer = op.pcap_predict(pcap_path=file_path, 
                    model_path=model_path, 
                    extract_type='flow', 
                    threshold=t)
    # print(detail)
    print()
    print('pcap文件: {}, 模型: {}'.format(file_path, model_path))
    print('阈值: {}'.format(t))
    print('pcap文件类别是: ', final_label)
    print('属于{}类别的可能性: {}'.format(prefer, prob))
    
    return


if __name__ == '__main__':
    print()
    
    # analysis_pcap_offline_flow()
    
    