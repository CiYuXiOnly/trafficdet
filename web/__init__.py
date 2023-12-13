'''
Description: 
version: 
Author: zlx
Date: 2023-12-09 14:47:14
LastEditors: zlx
LastEditTime: 2023-12-12 18:53:59
'''
# -*- coding: utf-8 -*-
from flask import Flask

app=Flask(__name__)

# 查看环境变量是否配置成功
import  os

# 环境变量
current_directory = os.getcwd()
app.config.from_object('web.setting') 
os.environ['FLASKR_SETTINGS'] = current_directory + '\\web\\setting.py'  # Set the environment variable here.
print(os.environ.get('FLASKR_SETTINGS'))

# 设置上传文件大小限制为10MB
app.config['MAX_CONTENT_LENGTH'] = 30 * 1024 * 1024  # 30MB in bytes