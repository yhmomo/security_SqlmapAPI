import os
import threading
import time

from IP存活 import IPCF
from SqlmapAPI import SqlmapScanner
from app import app  # 导入Flask应用实例
from database import clear_database
from visualize_report import visualize_report
from 目录爆破 import dir_blast_main
from 端口扫描 import IPdaunko


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_menu():
    print(" === 网络安全扫描系统 === ")
    print("1. IP存活扫描")
    print("2. 端口扫描")
    print("3. 目录爆破")
    print("4. 靶场扫描")
    print("5. 启动Web仪表盘")
    print("6. 清空数据库")
    print("0. 退出系统")
    print("=======================")

def run_flask():
    """在新线程中运行Flask应用"""
    print("\n正在启动Web仪表盘...")
    print("访问地址: http://localhost:5000")
    app.run(debug=False, use_reloader=False)  # 关闭调试模式避免双重启动

def main():
    while True:
        clear_screen()
        display_menu()
        choice = input("请选择要执行的操作: ")
        if choice == '1':
            IPCF()
        elif choice == '2':
            IPdaunko()
        elif choice == '3':
            dir_blast_main()
        elif choice == '4':
            url = "http://192.168.75.130/MCIR/sqlol/select.php?sanitization_level=none&sanitization_type=keyword&sanitization_params=&query_results=all_rows&error_level=verbose&inject_string=1&location=where_string&submit=Inject%21"
            # 直接使用扫描器实例
            scanner = SqlmapScanner()
            result = scanner.scan_url(url)

            if result:  # 添加结果判断
                visualize_report(result, url)
                print("可视化报告已生成")
            else:
                print("扫描失败，无法生成报告")
            time.sleep(4)
        elif choice == '5':
            flask_thread = threading.Thread(target=run_flask, daemon=False)
            flask_thread.start()
            input("Web服务已在后台启动，按回车返回主菜单...")
        elif choice == '6':
            clear_database()
            input("按回车键返回主菜单...")
        elif choice == '0':
            print("退出系统。")
            break
        else:
            print("无效的选择，请重新输入。")
        input("\n按回车键继续...")

if __name__ == "__main__":
    main()