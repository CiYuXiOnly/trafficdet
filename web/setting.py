'''
Description:
version: 
Author: zlx
Date: 2023-12-09 14:51:46
LastEditors: zlx
LastEditTime: 2023-12-12 15:16:51
'''
# 配置数据库连接

#调试模式是否开启
DEBUG = True

# key
SECRET_KEY='hguyigyfgtyuftuf98hy'

# 上传文件配置
UPLOAD_FOLDER ='web/upload/'        # 定义上传文件夹的路径
MAX_CONTENT_LENGTH = 300000     # 指定要上传的文件的最大大小（以字节为单位）