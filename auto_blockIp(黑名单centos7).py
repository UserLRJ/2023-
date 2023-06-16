#!/usr/bin/env python3

import re
import subprocess
import time

#安全日志
logFile = "/var/log/secure"
#黑名单
hostDeny = "/etc/hosts.deny"
#封禁阈值
password_wrong_num = 3

#获取已经加入黑名单的ip，转换为字典
def getDenies():
    deniesDict = {}
    list = open(hostDeny).readlines()
    for ip in list:
        group = re.search(r'(\d+\.\d+\.\d+\.\d+)',ip)
        if group:
            deniesDict[group[1]] = '1'      #判断是否为真
    return deniesDict

#监控方法
def monitorLog(Logfile):
    #统计密码错误的次数
    tempIp = {}
    #已经拉黑的ip
    deniesDict = getDenies()
    #读取安全日志
    popen = subprocess.Popen("tail -f "+logFile,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    #开始监控
    while True:
        time.sleep(0.1)
        line = popen.stdout.readline().strip()
        if line:         
            #不存在用户直接封禁
            group = re.search('Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)',str(line))
            if group and not deniesDict.get(group[1]):
                subprocess.getoutput('echo sshd:{} >> {}'.format(group[1],hostDeny))
                deniesDict[group[1]] = '1'
                time_str = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
                print('{} --- add ip:{} to hosts.deny for Invalid user'.format(time_str,group[1]))
                continue
            #用户名合法（有这个用户）密码错误
            group = re.search('Failed password for \w+ from (\d+\.\d+\.\d+\.\d+)',str(line))
            if group:
                ip = group[1]
                #统计ip 错误次数
                if not tempIp.get(ip):
                    tempIp[ip] = 1
                else:
                    tempIp[ip] += 1
                #如果错误次数大于阈值的时候，直接封禁
                if tempIp[ip] > password_wrong_num and not deniesDict.get(ip):
                    del tempIp[ip]  #删除临时ip
                    subprocess.getoutput('echo sshd:{} >> {}'.format(ip,hostDeny))
                    deniesDict[ip] = '1'
                    time_str = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
                    print('{} --- add ip:{} to hosts.deny for Failed password for root'.format(time_str,ip))
                    
                    
if __name__ == '__main__':
    monitorLog(logFile)