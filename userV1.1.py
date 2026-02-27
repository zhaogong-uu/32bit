import json
import getpass
import socket
from datetime import datetime
import json
import psutil
import time
import collections
import argparse
import json
from collections import defaultdict
import requests
import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests, urllib3, os
import xiaokang

# urllib3.disable_warnings()
# os.environ["http_proxy"] = os.environ["https_proxy"] = "http://127.0.0.1:8080"


def get_mac_address_wmi():
    """使用WMI获取MAC地址"""
    try:
        import wmi

        c = wmi.WMI()
        for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if interface.MACAddress:
                return interface.MACAddress
        return "无法获取MAC地址"
    except ImportError:
        return "请安装wmi库: pip install wmi"


def get_system_info():
    """获取系统信息"""
    info = {
        "用户名": getpass.getuser(),
        "计算机名": socket.gethostname(),
        "MAC地址": get_mac_address_wmi(),
        # "时间戳": datetime.now().isoformat(),
    }
    return info


def save_system_info(filename=f"system_info_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"):
    """保存系统信息到JSON文件"""
    info = get_system_info()
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    print(f"系统信息已保存到 {filename}")
    return info


class NetworkMonitor:
    def __init__(self):
        self.connection_history = collections.defaultdict(list)

    def get_connections(self):
        """获取当前所有网络连接"""
        connections = []

        for conn in psutil.net_connections(kind="tcp"):
            try:
                if not conn.raddr:
                    continue

                    # 获取连接信息
                local_ip = conn.laddr.ip if conn.laddr else "N/A"
                local_port = conn.laddr.port if conn.laddr else "N/A"
                remote_ip = conn.raddr.ip if conn.raddr else "N/A"
                remote_port = conn.raddr.port if conn.raddr else "N/A"

                # 进一步过滤无效的远程IP
                if remote_ip in ["N/A", "0.0.0.0", "::", "127.0.0.1", "::1"]:
                    continue

                # 获取进程信息
                process_name = "Unknown"
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = "Terminated/AccessDenied"

                connection_info = {
                    "本地IP": local_ip,
                    "本地端口": local_port,
                    "目的IP": remote_ip,
                    "目的端口": remote_port,
                    "state": conn.status,
                    "进程id": conn.pid,
                    "进程名": process_name,
                    "监听时间": datetime.now().isoformat(),
                }

                connections.append(connection_info)

            except Exception as e:
                continue

        return connections

    def monitor(self, interval=5, duration=200, output_file=f"network_monitor_{int(time.time())}.json"):
        """执行监控"""
        all_data = []
        start_time = time.time()

        print(f"🚀 开始监控网络连接...")
        print(f"⏰ 间隔: {interval}秒 | ⏱️ 时长: {duration}秒")
        print("Press Ctrl+C to stop\n")

        try:
            while time.time() - start_time < duration:
                current_time = datetime.now().strftime("%H:%M:%S")
                connections = self.get_connections()
                established = connections

                print(f"[{current_time}] 连接数: {len(established)}", end=" | ")

                # 按进程分组统计
                process_stats = {}
                for conn in established:
                    proc_name = conn["进程名"]
                    process_stats[proc_name] = process_stats.get(proc_name, 0) + 1

                # 显示前3个最活跃的进程
                top_processes = sorted(process_stats.items(), key=lambda x: x[1], reverse=True)[:3]
                for proc, count in top_processes:
                    print(f"{proc}:{count}", end=" ")

                print()  # 换行

                all_data.extend(connections)
                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n\n监控被用户中断")
        grouped = defaultdict(list)
        if all_data:
            self.save_data(all_data, output_file)
            print(f"\n✅ 监控完成！共记录 {len(all_data)} 个连接")
            print(f"📁 文件已保存: {output_file}")

    def save_data(self, data, filename):
        """保存数据到JSON文件"""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"保存文件时出错: {e}")

    def analyze_connections(self, data):
        """分析连接数据"""
        print("\n📊 连接分析:")

        # 统计各类信息
        states = collections.Counter([conn["state"] for conn in data])
        processes = collections.Counter([conn["process_name"] for conn in data])

        print("连接状态统计:")
        for state, count in states.most_common():
            print(f"  {state}: {count}")

        print("\n最活跃的进程:")
        for process, count in processes.most_common(10):
            print(f"  {process}: {count}")


def main_getinfo():
    parser = argparse.ArgumentParser(description="Windows网络连接监控工具")
    parser.add_argument(
        "--interval", "-i", type=float, default=float(input("输入监控间隔(秒)，建议为5") or 5), help="监控间隔(秒)"
    )
    parser.add_argument(
        "--duration", "-d", type=float, default=float(input("监控时长(秒)，建议为300") or 100), help="监控时长(秒)"
    )
    parser.add_argument(
        "--output", "-o", default=f"network_monitor_{datetime.now().strftime('%Y%m%d%H%M%S')}.json", help="输出文件名"
    )
    parser.add_argument("--scan", "-s", action="store_true", help="单次扫描模式")

    args = parser.parse_args()

    monitor = NetworkMonitor()

    if args.scan:
        # 单次扫描模式
        data = monitor.get_connections()
        established = [c for c in data if c["state"] == "ESTABLISHED"]
        print(f"找到 {len(established)} 个已建立的连接")
        monitor.save_data(data, args.output)
        monitor.analyze_connections(data)
    else:
        # 监控模式
        monitor.monitor(interval=args.interval, duration=args.duration, output_file=args.output)


def encrypt_data(data, key):
    return data
    """加密数据"""
    # 生成随机IV
    iv = os.urandom(16)
    # 创建AES加密器
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv)
    # 加密数据
    encrypted = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
    # 返回base64编码的IV+密文
    return base64.b64encode(iv + encrypted).decode("utf-8")


def send(server_url, encrypted_data):
    """发送加密数据"""
    try:
        payload = {
            "data": encrypted_data,
            "timestamp": int(time.time()),
            "ID": system_info,
        }

        # json_data = json.dumps(payload, ensure_ascii=False).encode("GBK")

        response = requests.post(
            server_url,
            json=payload,
            headers = {"Content-Type": "application/json; charset=GBK"},
            timeout=60 * 10
        )  # 10分钟超时

        response.raise_for_status()
        return response.text

    except Exception as e:
        raise Exception(f"发送失败: {e}")

def show(json_data):
    # 解析 JSON
    data = json.loads(json_data)
    if data['code']==200:
       print("未发现明显恶意进程")
    else:
        print("=== 发现高危信息 ===")
        # print(data)
    # 逐行显示用户数据
        for target in data['发现高危情况']:
            print(f"进程名: {target[6]},进程ID: {target[5]}, 本机IP: {target[0]},本机端口: {target[1]},目的IP: {target[2]},目的端口: {target[3]}")
            print(f"请及时清理ID为{target[5]}的进程{target[6]}在本地的依赖文件\n")
###定义配置####

服务器_ip = "127.0.0.1"
服务器_ip = "121.37.247.246"
服务器_端口 = 9395
通联api = f"http://{服务器_ip}:{服务器_端口}/api-1"
获取高危api=f"http://{服务器_ip}:{服务器_端口}/api-wxfh"
SECRET_KEY = "1111111111111111"  # 16字节密钥
monitor = NetworkMonitor()


####主函数####

system_info = get_system_info()
# system_info = json.dumps(get_system_info(), ensure_ascii=False)
# date1=encrypt_data(system_info, SECRET_KEY)
# send(SERVER_URL,system_info)


interval_minutes=int(input('输入监控间隔(秒)，建议为5秒:') or 5)
total_executions=round(int(input('监控时长(秒)，建议为300秒：') or 300)/interval_minutes)

# interval_minutes = 5
# total_executions = 2
print(f"开始监控: 每{interval_minutes}分钟执行一次，共执行{total_executions}次")

for i in range(total_executions):
    print(f"\n=== 第{i+1}/{total_executions}次执行 ===")
    try:
        # net_info=json.dumps(monitor.get_connections(), ensure_ascii=False)
        # date2=encrypt_data(net_info, SECRET_KEY)
        # date2=net_info
        print(send(通联api, monitor.get_connections()))

    except Exception as e:
        print(f"❌ 执行失败: {e}")

    # 如果不是最后一次执行，则等待
    if i < total_executions - 1:
        print(f"⏳ 等待{interval_minutes}秒...")
        time.sleep(interval_minutes)

    print(f"\n🎉 监控完成！共执行{total_executions}次")

show(send(获取高危api,xiaokang.时间_日志()))

input("按回车退出")