'''
Description:
version: 
Author: Zhang Lingxin
Date: 2023-12-09 14:51:46
LastEditors: Zhang Lingxin
LastEditTime: 2023-12-09 15:21:26
'''
# 配置数据库连接

#调试模式是否开启
DEBUG = True

# key
SECRET_KEY='hguyigyfgtyuftuf98hy'

# mysql数据库连接信息
# SQLALCHEMY_DATABASE_URI = 'sqlite:///students.sqlite3'

UPLOAD_FOLDER ='upload/'        # 定义上传文件夹的路径
MAX_CONTENT_LENGTH = 300000     # 指定要上传的文件的最大大小（以字节为单位）