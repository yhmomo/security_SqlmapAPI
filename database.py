import sqlite3


def init_db():
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()

    # 创建扫描结果表
    c.execute('''CREATE TABLE IF NOT EXISTS scan_results
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_time DATETIME,
                  target_url TEXT,
                  parameter TEXT,
                  vuln_type TEXT,
                  payload TEXT,
                  dbms TEXT,
                  risk_level TEXT)''')
    conn.commit()
    conn.close()


def clear_database():
    """清空扫描结果数据库"""
    try:
        conn = sqlite3.connect('scan_results.db')
        c = conn.cursor()
        c.execute("DELETE FROM scan_results")


        conn.commit()
        print("数据库已成功清空")
    except sqlite3.Error as e:
        print(f"数据库清空失败: {str(e)}")
    finally:
        if conn:
            conn.close()
