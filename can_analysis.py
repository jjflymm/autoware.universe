# -*- coding: utf-8 -*-
"""
Created on Wed Sep 13 09:21:12 2023
@author: du

Description:
    读取底盘反馈的 can 数据，对照协议表进行解析。
    支持利用 can bus 工具直接读取；也支持读取 candump 采集的 .log 文件。
Usage:
    1. 解析终端当前的 can 报文，如需解析所有报文，则不指定 -c 参数即可：
        python3 ~/DiAPP/tools/ros_tools/can_analysis.py -I can1 -s 0 -F 0 -c "0CF605B0|18F616B0|18F616C0|18EA64FF"
    2. 解析 candump 采集的 log 文件：
        python3 ~/DiAPP/tools/ros_tools/can_analysis.py -F 1 -s 1 -i ./candump-2023-12-12_135810.log
Notes:
    pip3 install python-can
    sudo modprobe vcan && sudo ip link add vcan0 type vcan && sudo ip link set up vcan0
    python3 can_tools.py -i vcan0 -f 50 -c -1 -C -F ./test_msg.txt
TODO:
    1. 在读取 .log 文件时，可以指定需要解析的 can id, 并 print 出来
"""
import argparse
import datetime
import os
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import time
import can
import tqdm
# from can_tools import setup_vcan_interface
from control_feedback_read import control_feedback_read_core


def stamp_to_date(timestamp:float):
    """ 将时间戳转换为datetime对象
    """
    dt = datetime.datetime.fromtimestamp(timestamp)
    # 将datetime对象格式化为指定的日期时间字符串
    dt_str = dt.strftime('%Y-%m-%d_%H-%M-%S.%f')[:-3]
    return dt_str


def receive_msg_from_canbus(
        interface:str, timeout:float, fps:int, analysis_can_id:str, print_can_msg: bool,
        save_flag:bool, output_file_path:str, can_id_protocol_dict:dict, protocol_file_path:str,
):
    """ 利用 can bus 读取 can 报文并分析
    """
    all_result_str = ""
    # setup_vcan_interface(interface)
    bus = can.interface.Bus(channel=interface, bustype='socketcan')

    if os.path.isdir(output_file_path):
        output_file_path = output_file_path + f"/can_analysis_{stamp_to_date(time.time())}.txt"
    else:
        output_file_path = f"./can_analysis_{stamp_to_date(time.time())}.txt"

    while True:
        can_frame = bus.recv(timeout)
        if can_frame is None:
            continue
        # 从 CAN 数据中提取 CAN ID 和 CAN 数据
        can_id = can_frame.arbitration_id
        if can_id > 0x7FF:  # 判断是否是扩展帧
            can_id = format(can_id, '08x')
        else:
            can_id = format(can_id, '03x')
        can_id = can_id.upper()

        # 只分析 analysis_can_id 中的数据
        analysis_can_id_list = analysis_can_id.split("|")
        if analysis_can_id == "" or can_id in analysis_can_id_list:
            # 格式转换
            can_data_hex = ' '.join(format(x, '02x') for x in can_frame.data)
            time_str = stamp_to_date(time.time())
            result_str, can_id_protocol_dict = control_feedback_read_core(
                can_id, can_data_hex, time_str, print_can_msg, can_id_protocol_dict=can_id_protocol_dict, protocol_file_path=protocol_file_path
            )
            all_result_str += result_str
        if save_flag:
            with open(output_file_path, 'a') as file:
                file.write(all_result_str)
        # time.sleep(1.0/fps)
    return can_id_protocol_dict

def receive_msg_from_log_file(
        print_can_msg, save_flag, input_file_path, output_file_path, can_id_protocol_dict, analysis_can_id, protocol_file_path
):
    """ 从 candump 采集的 log 文件中读取 can 报文并分析
    @print_can_msg: int, 是否打印
    @save_flag:int,是否保存所有结果
    @input_file_path: str,Input candump log file path
    @output_file_path: str, Save output file path
    @can_id_protocol_dict: can id 协议字典，默认设置为{}
    @anlysis_can_id: str, The can id that you want to analysis. It can be single or multiple id(default: "18F60431 18FF9B91").
    @protocol_file_path: str, Chassis protocol xlsx file path
    (1708855506.972461) llcecan6 0CF00300#FD00FFFFFFFFFFFF
    (1708855506.972510) llcecan6 0CFE6CEE#FFFFFFFF00000000
    """
    all_result_str = ""
    if input_file_path == "":
        # 打开文件选择对话框
        root = Tk()  # 创建Tk窗口
        root.withdraw()  # 隐藏Tk窗口
        log_path = askopenfilename()
    else:
        log_path = input_file_path
    print(f"--Reading file {log_path}")

    # 读取.log文件
    if ".log" in log_path:
        with open(log_path, 'r') as file:
            lines = file.readlines()
    else:
        print("--Please import candumpxxx.log file.")
        return

    for line in tqdm.tqdm(lines):
        # 解析时间戳和内容
        parts = line.strip().split(' ')
        timestamp = float(parts[0][1:-1])
        content = parts[2]
        content1 = content.split("#")[0]
        content2 = content.split("#")[1]
        # 将时间戳转换为正常时间
        dt = datetime.datetime.fromtimestamp(timestamp)
        time_str = f"{dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}"
        can_id = content1
        can_data_hex = ' '.join([content2[i:i+2] for i in range(0, len(content2), 2)])

        # 只分析 analysis_can_id 中的数据
        analysis_can_id_list = analysis_can_id.split(" ")
        if analysis_can_id == "" or can_id in analysis_can_id_list:
            result_str, can_id_protocol_dict = control_feedback_read_core(
                can_id, can_data_hex, time_str, print_can_msg,
                can_id_protocol_dict=can_id_protocol_dict
            )
            all_result_str += result_str
    if save_flag:
        # 如果输出文件夹路径为空，那么使用输入文件夹相同的名字
        if output_file_path == '':
            output_file_path = log_path.split('.log')[0] + '.txt'
        else:
          # 如果只给了文件夹路径
          if os.path.isdir(output_file_path):
              output_file_path = os.path.join(output_file_path, f"can_analysis_{stamp_to_date(time.time())}.txt")
          else:
              output_file_path = f"./can_analysis_{stamp_to_date(time.time())}.txt"
        with open(output_file_path, 'w') as file:
            file.write(all_result_str)
        print(f"\n--Finished! File saving path: {output_file_path}")
    return can_id_protocol_dict

def get_args():
    # python3 can_tools.py -i can1 -f 50 -c -1 -C -F ./AD_MODE2.txt
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description='Simulate CAN message publishing')
    parser.add_argument('-I', '--interface', type=str, default='can1', help='CAN interface name (default: can1)')
    parser.add_argument('-t', '--timeout', type=float, default=3.0, help='can receive timeout in seconds(record mode only)')
    parser.add_argument('-f', '--fps', type=int, default=1, help='CAN message sending frequency (default: 50)')
    parser.add_argument('-i', '--input_file_path', type=str, default='', help='Input candump log file path')
    parser.add_argument('-o', '--output_file_path', type=str, default='', help='Save output file path')
    parser.add_argument('-x', '--protocol_file_path', type=str, default='', help='Chassis protocol xlsx file path')
    parser.add_argument('-p', '--print_can_msg', type=int, default=1, help='Whether to printing.')
    parser.add_argument('-s', '--save_flag', type=int, default=1, help='Whether to saving all result.')
    parser.add_argument('-c', '--analysis_can_id', type=str, default='',
        help='The can id that you want to analysis. It can be single or multiple id(default: "18F60431 18FF9B91").'
    )

    parser.add_argument('-F', '--read_file_flag', type=int, default=1, help='Whether to receive can data from candump log file.')

    # 解析命令行参数
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = get_args()

    can_id_protocol_dict = {}
    # 从 can bus 实时读取 can 数据
    if not args.read_file_flag:
        can_id_protocol_dict = receive_msg_from_canbus(
            interface=args.interface,
            timeout=args.timeout,
            fps=args.fps,
            analysis_can_id=args.analysis_can_id,
            print_can_msg=args.print_can_msg,
            save_flag=args.save_flag,
            output_file_path=args.output_file_path,
            can_id_protocol_dict=can_id_protocol_dict,
            protocol_file_path=args.protocol_file_path,
        )
    # 从 candump 采集的 log 文件中读取 can 数据
    else:
        args.print_can_msg = False
        can_id_protocol_dict = receive_msg_from_log_file(
            print_can_msg=args.print_can_msg,
            save_flag=args.save_flag,
            input_file_path=args.input_file_path,
            output_file_path=args.output_file_path,
            can_id_protocol_dict=can_id_protocol_dict,
            analysis_can_id=args.analysis_can_id,
            protocol_file_path=args.protocol_file_path,
        )
    # 输出协议中未匹配的 can id
    for key, value in can_id_protocol_dict.items():
        # print(key)
        if value is None:
            print(f"--Can id {key} is not existing in the protocol!")
