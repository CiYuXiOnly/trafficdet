'''
Description: 
version: 
Author: zlx
Date: 2023-12-08 10:56:10
LastEditors: zlx
LastEditTime: 2023-12-21 10:50:14
'''
import os
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from model import Net
from utils.data.data_utils import GetDataObj
from extractor.flow_based.pcap_flow_feature import FlowProcess
from extractor.scts_extractor.main import SCTS_Extractor
'''
训练，测试，预测
'''

class ModelOperation():
    def __init__(self):
        pass

    # 训练模型
    def train_test(self, model, train_dataloader, test_dataloader, num_epochs=5, model_path='model/model.pth', per_print=100):
        
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(model.parameters(), lr=0.01)  # 使用Adam优化器 
        model.train()
        for epoch in range(num_epochs): # num_epochs表示训练的轮数
            for i, (inputs, targets) in enumerate(train_dataloader): # 前向传播

                outputs = model(inputs)
                
                loss = criterion(outputs, targets)  # 计算损失

                # 反向传播  
                optimizer.zero_grad()  
                loss.backward()  
                optimizer.step()  

                if (i + 1) % per_print == 0:  
                    print('Epoch [%d/%d], Iter [%d/%d] Loss: %.4f'  
                        % (epoch + 1, num_epochs, i + 1, len(train_dataloader), loss.item()))
            # end iter
        # end epoch
        torch.save(model.state_dict(), model_path) 

        # 训练循环结束后，进行测试  
        model.eval()
        test_loss = 0  # 用于累积测试损失  
        correct = 0  # 用于累积正确预测的数目  
        
        with torch.no_grad(): 
            for inputs, targets in test_dataloader: # 对于 test_dataloader 中的每个批次   
                outputs = model(inputs)  # 前向传播  
                
                loss = criterion(outputs, targets)  # 计算损失  
                test_loss += loss.item()  # 累积损失  
                
                # 对模型输出进行调整，将输出转换为一个包含两个元素的向量
                # 模型的最后一层没有softmax
                outputs = F.softmax(outputs, dim=1)
                # 获取最大概率的索引作为预测结果
                pred = outputs.argmax(dim=1, keepdim=True)
                
                correct += pred.eq(targets.argmax(dim=1, keepdim=True)).sum().item()  # 计算正确预测的数目
                
            test_loss /= len(test_dataloader)  # 计算平均测试损失    
            accuracy = 100. * correct / len(test_dataloader.dataset)  # 计算准确率并转化为百分比形式  
            print('\nTest set: Average loss: {:.4f}, Accuracy: {}/{} ({:.0f}%)\n'.format(    
                test_loss, correct, len(test_dataloader.dataset), accuracy))  # 打印测试损失和准确率  
        
        return

    # 预测
    def predict(self, model, df):
        mymodel = model
        
        input_tensor = torch.tensor(df.values, dtype=torch.float32)
        
        mymodel.eval()
        with torch.no_grad():
            output = mymodel(input_tensor)
        probabilities = F.softmax(output, dim=1)
        probabilities.tolist()
        _, predicted_classes = torch.max(probabilities, dim=1)
        predicted_labels = predicted_classes.tolist()
        
        return predicted_labels, probabilities
    
    '''
    根据pcap文件预测该pcap文件的类别
    输入: pcap_path, extract_type, model_path, threshold=0.5
    输出: detail, final_label, probability, prefer
    '''
    def pcap_predict(self, pcap_path, extract_type, model_path, threshold=0.5):
        label = None
        
        val_list = ['flow', 'scts']
        if extract_type not in val_list:
            print('不支持的特征提取方式！！！')
            return (detail, label, probability)
        
        if extract_type == 'flow':
            detail, final_label, probability, prefer = self._predict_flow(pcap_path, model_path, threshold)
        
        elif extract_type == 'scts':
            detail, final_label, probability, prefer = self._predict_scts(pcap_path, model_path, threshold)
            
        return detail, final_label, probability, prefer
    
    '''
    一个pcap文件会生成若干样本, 每个样本都有一个预测标签和概率
    需要根据这些信息, 得到该pcap文件的预测标签和概率
    '''
    def get_result(self, pred_label, preb, threshold):
    
        detail = []
        final_label = None
        probability =  None
        sum = torch.tensor(0.0)
        prefer = 0
        
        # 第二个表示属于恶意(label: 1)的概率
        ben_prob = [sublist[0] for sublist in preb]
        mal_prob = [sublist[1] for sublist in preb]
        
        # 生成detail
        # 每个内列表的第一个元素表示该样本的预测标签, 第二个元素表示属于0的概率, 第三个元素表示属于1的概率
        len = 0
        detail = []
        for a, b, c in zip(pred_label, ben_prob, mal_prob):
            if not 0 <= b <= 1:
                continue
            elif not 0 <= c <= 1:
                continue
            detail.append([a, b.item(), c.item()])
            len += 1
        print('该文件生成了 {} 个样本'.format(len))
        
        # 算法：实际发现，当模型总是偏向于预测为0,
        # 可以计算probability是属于0的平均概率, 也方便和阈值比较
        for item in ben_prob:
            sum.add_(item)
        # 这里的probability表示属于0的平均概率
        probability = sum.item()/len
        
        if probability > 0.5:
            # 偏向于预测为0
            if probability > threshold:
                final_label = 1
            else:
                final_label = 0
        else:
            # 偏向于预测为1
            probability = 1 - probability
            if probability > threshold:
                final_label = 0
            else:
                final_label = 1
            
        return detail, final_label, probability, prefer
    
    def _predict_flow(self, pcap_path, model_path, threshold=0.5):
        detail = None
        label = None
        probability = None
        prefer = 0
        
        dir_path, file_name = os.path.split(pcap_path)
        # 根据pcap文件生成特征csv文件
        config = {  
            "run_mode": "flow",  
            "pcap_loc": dir_path,  
            "pcap_name": file_name,  
            "csv_path": "data/featured_csv/example_flow.csv",  
            "print_colname": True,  
            "read_all": False
        }
        p = FlowProcess(config)
        p.extract_flow_feature_from_pcap()
        
        # 读取csv特征文件，获得dataframe
        op = GetDataObj()
        df = op.get_df_from_featured_csv(featured_csv_path='data/featured_csv/example_flow.csv')
        df = df.drop(["src", "sport", "dst", "dport"], axis=1)
        print(df.columns)
        # 实例化模型并加载模型
        model = Net(indim=72)
        if 'flow' not in model_path:
            print('指定的特征提取方式与模型不匹配！！！')
            return (detail, label, probability)
        model.load_state_dict(torch.load(model_path))
        
        # 预测，获得每个样本的预测标签和概率
        # pred_label [1, 0, 1]  preb [[0.3,0.7], [0.4,0.6], [0.2, 0.8]]
        pred_label, preb = self.predict(model, df)
        
        detail, final_label, probability, prefer = self.get_result(pred_label, preb, threshold)
        
        return detail, final_label, probability, prefer
    
    
    def _predict_scts(self, pcap_path, model_path, threshold=0.5):
        detail = None
        label = None
        probability = None
        prefer = 0
        
        # 根据pcap文件生成特征csv文件
        csv_path = 'data/featured_csv/example_scts.csv'
        e = SCTS_Extractor(pcap_path, csv_path)
        e.run()
        
        # 读取csv特征文件，获得dataframe
        op = GetDataObj()
        df = op.get_df_from_featured_csv(featured_csv_path='data/featured_csv/example_scts.csv')
        # print(df.columns)
        
        # 实例化模型并加载模型
        model = Net(indim=72)
        if 'scts' not in model_path:
            print('指定的特征提取方式与模型不匹配！！！')
            return (detail, label, probability)
        model.load_state_dict(torch.load(model_path))
        
        # 预测，获得每个样本的预测标签和概率
        # pred_label [1, 0, 1]  preb [[0.3,0.7], [0.4,0.6], [0.2, 0.8]]
        pred_label, preb = self.predict(model, df)
        
        detail, final_label, probability, prefer = self.get_result(pred_label, preb, threshold)
        
        return detail, final_label, probability, prefer