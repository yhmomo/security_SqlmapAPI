import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import nmap


def IPdaunko():
    def os_detection_nmap(target):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments='-O')

            if 'osmatch' in nm[target]:
                best_guess = nm[target]['osmatch'][0]
                return f"检测到操作系统: {best_guess['name']} (准确度: {best_guess['accuracy']}%)"
            return "未检测到明确的操作系统信息"

        except Exception as e:
            return f"扫描出错: {str(e)}"

    def check_port(domain, port, open_list, lock):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                result = s.connect_ex((domain, port))
                if result == 0:
                    service = get_service_name(port)
                    with lock:
                        open_list.append((port, service))
        except Exception as e:
            print(f"Error scanning {port}: {str(e)}")

    def get_service_name(port):
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            443: 'HTTPS', 3306: 'MySQL'
        }
        return service_map.get(port, 'Unknown')

    def get_port(domain, max_workers=200):
        ports = list(range(1, 1000))
        open_list = []
        lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_port, domain, port, open_list, lock)
                       for port in ports]

            for future in futures:
                future.result()

        sorted_ports = sorted(open_list, key=lambda x: x[0])
        return [port_info[0] for port_info in sorted_ports], sorted_ports

    f = open("ip.txt", "r+")
    iplist = f.read().split("\n")
    for ip in iplist[:-1]:
        print(os_detection_nmap(ip))
        port_numbers, detailed_list = get_port(ip)
        print("扫描IP为：", ip)
        print("\n=== 扫描结果汇总 ===")
        print(f"开放端口数量: {len(port_numbers)}")
        print(f"端口列表: {port_numbers}")

        print("\n=== 详细服务信息 ===")
        for port, service in detailed_list:
            print(f"端口 {port}: {service}")
        f.close()
