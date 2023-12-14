'''
Description: 
version: 
Author: Zhang Lingxin
Date: 2023-12-09 15:06:00
LastEditors: Zhang Lingxin
LastEditTime: 2023-12-09 15:42:16
'''
import os
from web import app
from flask import request,render_template,flash,abort,url_for,redirect,session,Flask
from werkzeug.utils import secure_filename
from usemodel import analysis_pcap

@app.route('/')
def upload():
    return render_template('upload.html')

@app.route('/error',methods=['POST','GET'])
def show_error():
    if request.method == 'POST':
        return redirect(url_for("upload"))
    else:
        return render_template('show_error.html')

@app.route('/detection',methods = ['POST','GET'])
def detection():
    error=None 
    if request.method == 'POST':      
        
        # 检查是否有文件被提交
        if 'file' not in request.files:
            return redirect(request.url)
        try:
            f = request.files['file']
        except:
            print('get file error')
            return redirect(url_for('show_error'))
        ftype=secure_filename(f.filename).split('.')[-1]
        if ftype!='pcap':
            # error='Invalid filetype'
            flash ('请检查文件类型是否正确！')
            return  redirect(url_for('show_error'))
        else:
            pcap_save_path=os.path.join(app.config['UPLOAD_FOLDER'],secure_filename(f.filename))
            f.save(pcap_save_path) 
            flash('upload file is successfully saved !')
            
            pcap_path = pcap_save_path
            model_path = 'model/pkg_model_CIC.pth'
            extract_type  = 'pkg'
            threshold = 0.5
            detail, final_label, prob = analysis_pcap(pcap_path, 
                                                      model_path, 
                                                      extract_type, 
                                                      threshold)
            
            if not final_label:
                return render_template('result.html',content='The file is safe')
            else:
                return render_template('result.html',content='The file is dangerous')
            # 后续需要更改此处的逻辑，以更加合适的方式返回！！！！
    elif request.method=="GET":
        return redirect(url_for('upload'))


@app.route('/result',methods=['POST','GET'])
def result():
    if request.method == 'POST':
        return redirect(url_for("upload"))
    else:
        return render_template('show_error.html')