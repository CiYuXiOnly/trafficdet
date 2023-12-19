'''
Description: 
version: 
Author: Zhang Lingxin
Date: 2023-12-09 14:47:14
LastEditors: Zhang Lingxin
LastEditTime: 2023-12-09 15:40:33
'''
# -*- coding: utf-8 -*-
from flask import Flask

app=Flask(__name__)

import views

# 查看环境变量是否配置成功
import  os

# 环境变量
current_directory = os.getcwd()
app.config.from_object('web.setting') 
os.environ['FLASKR_SETTINGS'] = current_directory + '\\web\\setting.py'  # Set the environment variable here.
print(os.environ.get('FLASKR_SETTINGS'))

# 设置上传文件大小限制为10MB
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB in bytes