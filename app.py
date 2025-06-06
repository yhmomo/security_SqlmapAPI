import sqlite3
from datetime import datetime

import pandas as pd
from flask import Flask, render_template

app = Flask(__name__)


def get_scan_data():
    """从数据库获取所有扫描数据"""
    conn = sqlite3.connect('scan_results.db')
    try:
        df = pd.read_sql('''
            SELECT scan_time, target_url, parameter, vuln_type, risk_level 
            FROM scan_results
            ORDER BY scan_time DESC
        ''', conn)
        return df
    finally:
        conn.close()


def process_data(df):
    """处理图表需要的数据格式"""
    risk_dist = df['risk_level'].value_counts().to_dict()
    vuln_dist = df['vuln_type'].value_counts().to_dict()

    return {
        'risk_labels': list(risk_dist.keys()),
        'risk_values': list(risk_dist.values()),
        'vuln_labels': list(vuln_dist.keys()),
        'vuln_values': list(vuln_dist.values()),
        'vulnerabilities': df.to_dict('records'),
        'scan_info': {
            'target': df['target_url'].iloc[0] if not df.empty else '暂无数据',
            'time': df['scan_time'].max() if not df.empty else datetime.now().strftime('%Y-%m-%d %H:%M'),
            'total': len(df)
        }
    }


@app.route('/')
def dashboard():
    df = get_scan_data()
    data = process_data(df)
    return render_template('dashboard_v2.html', **data)
