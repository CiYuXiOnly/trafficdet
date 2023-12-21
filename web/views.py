'''
Description: 
version: 
Author: zlx
Date: 2023-12-12 13:20:05
LastEditors: zlx
LastEditTime: 2023-12-21 10:37:42
'''  
from flask import request,render_template,url_for,redirect,session, flash
from web import app
from werkzeug.utils import secure_filename
from usemodel import analysis_pcap
import os

@app.route('/')
def index():
    return redirect(url_for("upload"))

@app.route('/upload',methods=['POST','GET'])
def upload():
    return render_template('upload.html')

@app.route('/upload_error',methods=['POST','GET'])
def upload_error():
    if request.method == 'POST':
        return redirect(url_for("upload"))
    else:
        return render_template('upload_error.html')

@app.route('/file_detection',methods = ['POST'])
def file_detection():
    # 检查是否有文件被提交
    if 'file' not in request.files:
        return redirect(request.url)
    try:
        f = request.files['file']
    except:
        print('get file error !')
        return redirect(url_for('upload_error'))
    
    # 获取模型类型  
    model_type = request.form['model_type']
    
    # 检查文件类型
    ftype=secure_filename(f.filename).split('.')[-1]
    if ftype!='pcap':
        # 该函数会在下一个请求中传递前端消息，前端用get_flashed_messages()获取
        # 多数时候用于redirect和render_template
        flash('请检查文件类型是否正确！')
        return  redirect(url_for('upload_error'))
    
    # 保存上传文件
    pcap_save_path=os.path.join(app.config['UPLOAD_FOLDER'],secure_filename(f.filename))
    f.save(pcap_save_path)
    print('upload file is successfully saved !')
    
    model_path = None
    extract_type = None
    threshold = None
    
    if model_type == 'flow_CIC-IDS-2017':
        model_path = 'model/flow_model_CIC.pth'
        extract_type = 'flow'
        threshold = 0.85
    
    elif model_type == 'scts_CIC-IDS-2017':
        model_path = 'model/scts_model_CIC.pth'
        extract_type = 'scts'
        threshold = 0.5
    
    else:
        flash('不支持的模型类型！')
        return  redirect(url_for('upload_error'))
    
    # 预测
    file_name, sample_num, final_label, model_name, prob, detail = analysis_pcap(pcap_path = pcap_save_path, 
                                                                                 model_path = model_path, 
                                                                                 extract_type = extract_type, 
                                                                                 threshold = threshold)
    # 返回前端字典
    result_dict = {'file_name':file_name, 
                   'sample_num':sample_num, 
                   'final_label':final_label, 
                   'model_name':model_name, 
                   'prob':prob, 
                   'detail':detail}
    
    return render_template('detection_result.html', result_dict=result_dict)


@app.route('/detection_result',methods=['POST'])
def detection_result():
    # detection_result.html中点击返回按钮，会发送POST请求，此处接收
    print('预测结果返回成功！')
    return redirect(url_for("upload"))

