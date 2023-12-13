'''
Description: 
version: 
Author: zlx
Date: 2023-12-09 14:49:12
LastEditors: zlx
LastEditTime: 2023-12-12 13:19:55
'''
from web import app
from web.views import *

def run():
    app.run(debug=True)