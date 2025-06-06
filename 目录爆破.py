import queue
import sys
import threading
import time

import urllib3


def dir_blast_main():
    def main(url, threadNum):
        # 以队列的形式获取爆破路径
        pathQueue = getPath(url)

        # 通过多线程进行爆破
        threads = []
        for i in range(threadNum):
            t = threading.Thread(target=blastingUrl, args=(pathQueue,))
            threads.append(t)
            t.start()
        # join（[timeout]）等到线程终止。这将阻塞调用线程，直到调用join（）方法的线程终止 - 通常或通过未处理的异常 - 或直到发生可选的超时。
        # 多线程多join的情况下，依次执行各线程的join方法，前头一个结束了才能执行后面一个
        for t in threads:
            t.join()

    # 爆破目录地址
    def blastingUrl(pathQueue):
        while not pathQueue.empty():
            try:
                url = pathQueue.get()
                http = urllib3.PoolManager()
                response = http.request("GET", url)

                # 输出能访问到的目录
                if response.status == 200:
                    print("[%d] => %s" % (response.status, url))
            except:
                pass
        else:
            sys.exit()

    # 把目录字典添加到队列中去
    def getPath(url, file="C:\\Users\\JBWang\\Desktop\\字典\\爆破字典\\目录.txt"):
        pathQueue = queue.Queue()
        f = open(file, "r", encoding="gbk")
        for i in f.readlines():
            path = url + i.strip()
            pathQueue.put(path)
        f.close()
        return pathQueue

    f = open("ip.txt", "r+")
    iplist = f.read().split("\n")[:-1]
    for ip in iplist:
        url = ip
        print(url)
        threadNum =200
        sTime = time.time()
        main(url,int(threadNum))
        eTime = time.time()
        print("共耗时%.2f s" % (eTime - sTime))