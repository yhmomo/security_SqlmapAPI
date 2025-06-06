import concurrent.futures
import ipaddress

from pythonping import ping


def IPCF():
    def ping_ip(ip):
        try:
            response = ping(ip, count=2, timeout=1.5)  # 发送2次ping，超时时间为1.5秒
            if response.success():
                print(f"{ip} 是存活的")
                return ip  # 返回存活的IP地址
            else:
                # print(f"{ip} 无响应")
                return None
        except Exception as e:
            print(f"扫描 {ip} 时出错: {e}")
            return None

    def scan_ip_range(start_ip, end_ip, max_threads=1000):
        start_ip_int = int(ipaddress.ip_address(start_ip))
        end_ip_int = int(ipaddress.ip_address(end_ip))

        ip_range = [str(ipaddress.ip_address(ip)) for ip in range(start_ip_int, end_ip_int + 1)]
        print(f"正在扫描IP范围：从 {start_ip} 到 {end_ip}...")
        # 存储存活的IP地址
        alive_ips = []

        # 使用线程池并发执行ping操作
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(ping_ip, ip) for ip in ip_range]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()  # 获取线程返回的结果
                if result:  # 如果返回了IP地址，说明该IP存活
                    alive_ips.append(result)
        return alive_ips  # 返回存活的IP列表

    start_ip = input("请输入起始IP地址: ")
    end_ip = input("请输入结束IP地址: ")
    max_threads = int(input("请输入最大线程数（默认为100）: ") or 100)
    alive_ips = scan_ip_range(start_ip, end_ip, max_threads)

    print("\n存活的IP地址列表：\n", alive_ips)
    f = open("ip.txt", "w+")
    for ip in alive_ips:
        f.write(ip + '\n')
    print("\n已写入ip.txt")
    f.close()