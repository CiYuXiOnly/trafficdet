'''
Description: 
version: 
Author: Zhang Lingxin
Date: 2023-12-09 14:24:22
LastEditors: zlx
LastEditTime: 2023-12-14 09:40:16
'''

'''
使用模型判断pcap文件的恶意性, 基于包的检测和基于流的检测
'''

from model_operate import ModelOperation

'''
this is for web api
'''
def analysis_pcap(pcap_path, model_path, extract_type, threshold):
    op = ModelOperation()
    detail, final_label, prob = op.pcap_predict(pcap_path=pcap_path, 
                    model_path=model_path, 
                    extract_type=extract_type, 
                    threshold=threshold)
    print('pcap文件类别是: ', final_label)
    print('属于该类别的可能性: ', prob)
    return detail, final_label, prob

'''
this is for offline
'''
def analysis_pcap_offline_pkg():
    '''
    给定一个pcap文件, 利用模型进行检测, 基于包的检测
    '''
    t = 0.5
    model_path = 'model/pkg_model_CIC.pth'
    print()
    print('+++++++++++++基于包的检测+++++++++++++++')
    op = ModelOperation()
    file_path = 'upload/benign_sample.pcap'
    detail, final_label, prob, prefer = op.pcap_predict(pcap_path=file_path, 
                    model_path=model_path, 
                    extract_type='pkg', 
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
                    extract_type='pkg', 
                    threshold=t)
    # print(detail)
    print()
    print('pcap文件: {}, 模型: {}'.format(file_path, model_path))
    print('阈值: {}'.format(t))
    print('pcap文件类别是: ', final_label)
    print('属于{}类别的可能性: {}'.format(prefer, prob))
    
    return

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

def analysis_pcap_offline_sess():
    '''
    给定一个pcap文件, 利用模型进行检测, 基于流的检测
    '''
    t = 0.5
    model_path = 'model/sess_model_CIC.pth'
    print()
    print('+++++++++++++基于会话的检测+++++++++++++++')
    op = ModelOperation()
    file_path = 'upload/benign_sample.pcap'
    detail, final_label, prob, prefer = op.pcap_predict(pcap_path=file_path, 
                    model_path=model_path, 
                    extract_type='sess', 
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
                    extract_type='sess', 
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
    
    # analysis_pcap_offline_pkg()
    
    # analysis_pcap_offline_flow()
    
    analysis_pcap_offline_sess()
    
    