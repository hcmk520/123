from flask import Flask, request, jsonify, send_from_directory
import pandas as pd
import os
from datetime import datetime
from filelock import FileLock

app = Flask(__name__)
EXCEL_FILE = 'travel_records.xlsx'
LOCK_FILE = 'travel_records.xlsx.lock'
lock = FileLock(LOCK_FILE, timeout=10)
GLOBAL_PASSWORD = 'hello'         # 所有员工进入网页必须先输入的访问密码
ADMIN_PASSWORD = 'hcmk'
STANDARD_COLUMNS = ['序号', '区域', '区域经理', '分公司', '姓名', 
                   '从许昌出发日期', '返回许昌日期', '出差天数', '出差地点', 
                   '出差事由', '备注', '最后更新时间', '无需更新确认']

def init_or_read_df():
    if not os.path.exists(EXCEL_FILE):
        df = pd.DataFrame(columns=STANDARD_COLUMNS)
        df.to_excel(EXCEL_FILE, index=False)
        return df
    return pd.read_excel(EXCEL_FILE)

def format_records(df):
    records = df.fillna('').to_dict('records')
    for r in records:
        for col in ['从许昌出发日期', '返回许昌日期']:
            val = r.get(col)
            if val and isinstance(val, datetime):
                r[col] = val.strftime('%Y-%m-%d')
            elif val and isinstance(val, str):
                try:
                    r[col] = pd.to_datetime(val).strftime('%Y-%m-%d')
                except:
                    r[col] = val
    return records

def calculate_days(start, end):
    if start and end and end != '暂未结束':
        try:
            d1 = datetime.strptime(start, '%Y-%m-%d')
            d2 = datetime.strptime(end, '%Y-%m-%d')
            return (d2 - d1).days + 1
        except:
            pass
    return ''

def get_dynamic_pwd():
    hour_stamp = int(datetime.now().timestamp() // 3600)
    return str((hour_stamp * 9301 + 49297) % 10000).zfill(4)

def safe_update(update_logic_func):
    try:
        with lock:
            df = init_or_read_df()
            df = df.fillna('')
            df, status, msg = update_logic_func(df)
            if status == "success":
                df.to_excel(EXCEL_FILE, index=False)
            return {"status": status, "msg": msg}
    except Exception as e:
        return {"status": "error", "msg": f"系统繁忙: {str(e)}"}

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

@app.route('/api/verify_access', methods=['POST'])
def verify_access():
    data = request.json
    if data.get('password') == GLOBAL_PASSWORD:
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "msg": "访问密码错误！"})

@app.route('/api/admin/verify', methods=['POST'])
def verify_admin():
    data = request.json
    if data.get('password') == ADMIN_PASSWORD:
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "msg": "密码错误或无权限"})

@app.route('/api/user/<name>', methods=['GET'])
def get_user_records(name):
    with lock:
        df = init_or_read_df()
    user_records = format_records(df[df['姓名'] == name])
    return jsonify(user_records)

@app.route('/api/user/add', methods=['POST'])
def add_record():
    data = request.json
    def logic(df):
        new_id = 1 if df.empty else int(df['序号'].max()) + 1
        start_date = data.get('从许昌出发日期', '')
        end_date = data.get('返回许昌日期', '')
        new_row = {
            '序号': new_id,
            '区域': data.get('区域', ''),
            '区域经理': data.get('区域经理', ''),
            '分公司': data.get('分公司', ''),
            '姓名': data.get('姓名', ''),
            '从许昌出发日期': start_date,
            '返回许昌日期': end_date,
            '出差天数': calculate_days(start_date, end_date),
            '出差地点': data.get('出差地点', ''),
            '出差事由': data.get('出差事由', ''),
            '备注': data.get('备注', ''),
            '最后更新时间': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            '无需更新确认': ''
        }
        df.loc[len(df)] = new_row
        return df, "success", "新增成功"
    return jsonify(safe_update(logic))

@app.route('/api/user/update', methods=['POST'])
def update_record():
    data = request.json
    def logic(df):
        row_idx = df.index[df['序号'] == data['序号']].tolist()
        if not row_idx:
            return df, "error", "未找到该记录"
        idx = row_idx[0]
        start_date = data.get('从许昌出发日期', '')
        end_date = data.get('返回许昌日期', '')
        
        df.at[idx, '区域'] = data.get('区域', '')
        df.at[idx, '区域经理'] = data.get('区域经理', '')  # 新增：允许修改负责经理
        df.at[idx, '分公司'] = data.get('分公司', '')
        df.at[idx, '出差地点'] = data.get('出差地点', '')
        df.at[idx, '从许昌出发日期'] = start_date
        df.at[idx, '返回许昌日期'] = end_date
        df.at[idx, '出差天数'] = calculate_days(start_date, end_date)
        df.at[idx, '出差事由'] = data.get('出差事由', '')
        df.at[idx, '备注'] = data.get('备注', '')
        df.at[idx, '最后更新时间'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        df.at[idx, '无需更新确认'] = ''
        return df, "success", "更新成功"
    return jsonify(safe_update(logic))

@app.route('/api/user/delete', methods=['POST'])
def delete_record():
    data = request.json
    if data.get('password') != get_dynamic_pwd():
        return jsonify({"status": "error", "msg": "删除失败：动态密码错误或已过期"})
        
    def logic(df):
        row_idx = df.index[df['序号'] == data['序号']].tolist()
        if not row_idx:
            return df, "error", "未找到该记录"
        df = df.drop(index=row_idx[0])
        return df, "success", "删除成功"
    return jsonify(safe_update(logic))

@app.route('/api/admin/pwd', methods=['GET'])
def admin_pwd():
    return jsonify({"password": get_dynamic_pwd()})

@app.route('/api/admin/overview', methods=['GET'])
def admin_overview():
    with lock:
        df = init_or_read_df()
    return jsonify(format_records(df))

@app.route('/api/admin/confirm', methods=['POST'])
def admin_confirm():
    data = request.json
    def logic(df):
        row_idx = df.index[df['序号'] == data['序号']].tolist()
        if row_idx:
            df.at[row_idx[0], '无需更新确认'] = '是'
            return df, "success", "已确认"
        return df, "error", "记录不存在"
    return jsonify(safe_update(logic))

if __name__ == '__main__':
    init_or_read_df()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
