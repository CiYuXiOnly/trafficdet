import pandas as pd
from sklearn.preprocessing import MinMaxScaler

'''
两个csv文件合并, 规范化, 降维
'''
def merger_and_decom(statis_csvpath, tshark_csv_path, output_path):
    df1 = pd.read_csv(statis_csvpath, sep=',')
    df1 = df1.astype(float)
    
    df2 = pd.read_csv(tshark_csv_path, sep=';')
    
    # 处理特殊字段列
    df2_ = df2.copy() 
    # 使用groupby方法按'group'列的值划分组  
    grouped = df2_.groupby('tcp.stream', group_keys=False)  
    # 定义一个函数，将组中的某一列的值设置为该组中该列的unique个数  
    def set_column_values(group, col_name):  
        unique_count = len(group[col_name].unique())  
        group[col_name] = unique_count  
        return group 
    # 使用apply方法对每个组应用函数
    df2_tmp = grouped.apply(set_column_values, "dns.a") 
    grouped = df2_tmp.groupby('tcp.stream', group_keys=False)
    df2_1 = grouped.apply(set_column_values, "dns.aaaa")
    
    # 先排除特殊列的列名
    df2_2 = df2_1.copy()
    spec_names = ["dns.a", "dns.aaaa"]
    col_names = df2_2.columns.tolist()
    other_col_names = []
    for i in col_names:
        if i not in spec_names:
            other_col_names.append(i)
    df2_2tmp = df2_2.drop(spec_names, axis=1)

    # 其他字段按照dtype是否是object进行列名划分
    object_columns = df2_2tmp.columns[df2_2tmp.dtypes == object].tolist()
    # print("dtype是object的列名列表:", len(object_columns))
    non_object_columns = df2_2tmp.columns[df2_2tmp.dtypes != object].tolist()  
    # print("非object的列名列表:", len(non_object_columns))
    
    # 对object列进行类别编码
    df3 = df2_2.copy()
    for col in object_columns:  
        df3[col] = df3[col].astype(str)
    from sklearn.preprocessing import LabelEncoder
    for column in df3.columns:
        if df3[column].dtype == 'object':  
            le = LabelEncoder()  
            df3[column] = le.fit_transform(df3[column])
            
    # 用0填充nan
    for column in df3.columns:
        df3[column] = df3[column].fillna(0)
        
    # 对是原本非object的类型，按照双向流为组（tcp.stream ），替换为均值
    df4 = df3.copy()
    # print("非object的列名列表:", non_object_columns)
    # 根据目标列的值将记录分组  
    grouped = df4.groupby('tcp.stream')
    # 对特定的一些列名用组内的均值替换原本的值  
    for col in non_object_columns:  
        df4[col] = grouped[col].transform(lambda x: x.mean())
        
    df5 = df4.copy()
    df5 = df5.astype(float)
    
    # 将包特征转换为双向流特征，每个组中，列保留最大值
    # 按“tcp.stream”列划分组，并在每个组中取出所有列（除了“tcp.stream”）的最大值
    apply_dict = {}
    colnames = df5.columns.tolist()
    for i in colnames:
        if i != 'tcp.stream':
            apply_dict[i] = 'max'
    df6 = df5.groupby('tcp.stream').agg(apply_dict).reset_index()
    
    df7 = df6.copy()
    df7["stream_id"] = df7["tcp.stream"]
    df7 = df7.drop(["tcp.stream"], axis=1)
    # 合并
    merged_df = pd.merge(df1, df7, on='stream_id', how='outer')
    merged_df.fillna(0, inplace=True)
    # print(merged_df.isnull().any().unique())
    
    # 列规范化
    merged_df1 = merged_df.copy() 
        
    scaler = MinMaxScaler()  
    # 循环遍历DataFrame中的每一列，除了'stream_id'  
    for column in merged_df1.columns:  
        if column != 'stream_id':  # 排除要保留的列  
            merged_df1[column] = scaler.fit_transform(merged_df1[column].values.reshape(-1, 1))
    merged_df1
    
    # 降维
    merged_df2 = merged_df1.copy()
    from sklearn.decomposition import PCA
    pca = PCA(n_components=72)  # 将数据降维到72个主成分
    df_pca = pd.DataFrame(pca.fit_transform(merged_df2))
    
    df_pca.to_csv(output_path, index=False)
    return