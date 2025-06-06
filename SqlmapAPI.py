import datetime
import json
import sqlite3
import time

import requests

from visualize_report import _calc_risk_level


# === 数据库操作模块 ===
def save_scan_results(scan_data, url):
    """将扫描结果保存到数据库"""
    try:
        conn = sqlite3.connect('scan_results.db')
        c = conn.cursor()

        for entry in scan_data.get('data', []):
            if entry.get('type') == 1:
                for param_data in entry.get('value', []):
                    for vuln_id, detail in param_data.get('data', {}).items():
                        c.execute('''INSERT INTO scan_results 
                                   (scan_time, target_url, parameter, vuln_type, payload, dbms, risk_level)
                                   VALUES (?,?,?,?,?,?,?)''',
                                  (datetime.datetime.now(),
                                   url,
                                   param_data.get('parameter'),
                                   detail.get('title'),
                                   detail.get('payload'),
                                   param_data.get('dbms', 'N/A'),
                                   _calc_risk_level(detail.get('title', ''))))
        conn.commit()
    except sqlite3.Error as e:
        print(f"数据库操作失败: {str(e)}")
    finally:
        if conn:
            conn.close()


class SqlmapScanner:
    def __init__(self):
        self.base_url = "http://127.0.0.1:8775"
        self.headers = {
            'Authorization': '4a216edf8d9dc283de841e1b9ac8e6f1',
            'Content-Type': 'application/json'
        }

    def _api_request(self, method, endpoint, data=None):
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.request(
                method,
                url,
                headers=self.headers,
                data=json.dumps(data) if data else None
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API请求失败: {str(e)}")
            return None

    def scan_url(self, target_url):
        task = self._api_request('GET', '/task/new')
        if not task or 'taskid' not in task:
            return None

        task_id = task['taskid']
        print(f"创建扫描任务成功，任务ID: {task_id}")

        scan_config = {
            'url': target_url,
            'level': 5,
            'risk': 3
        }
        config_response = self._api_request('POST', f'/option/{task_id}/set', scan_config)
        if not config_response or 'success' not in config_response:
            return None

        # 启动扫描
        start_response = self._api_request('POST', f'/scan/{task_id}/start', scan_config)
        if not start_response or 'success' not in start_response:
            return None

        # 监控扫描进度
        start_time = time.time()
        timeout = 600  # 超时
        while time.time() - start_time < timeout:
            status = self._api_request('GET', f'/scan/{task_id}/status')
            if status and status.get('status') == 'terminated':
                break
            time.sleep(5)
        else:
            print("扫描超时，任务未完成")
            return None

        # 获取扫描结果
        result = self._api_request('GET', f'/scan/{task_id}/data')
        if result:
            save_scan_results(result, target_url)  # 保存到数据库
        return result
