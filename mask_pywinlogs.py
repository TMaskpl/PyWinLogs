import wmi
import re
import sys
import os
import codecs

# c = wmi.WMI("MachineB", user=r"MachineB\fred", password="secret")

c = wmi.WMI()


def removeOldFile(file):
    try:
        os.remove(file)
    except OSError as e:
        print("Error: %s - %s." % (e.filename, e.strerror))


def checkEventLogSecurity(id):
    c = wmi.WMI()
    file = (f'sec_{id}_logs.txt')
    print(file)
    removeOldFile(str(file))
    d = []
    for log in c.Win32_NTLogEvent(EventCode=id, Logfile='Security'):
        data = re.sub('[^a-zA-Z0-9 \n\.\[\]\(\)\{\}]', '', str(log))
        with open(file, mode='a', encoding='UTF-8', errors='strict', buffering=1) as plik:
            d = data.split('\n')
            dd = (d[4:10], d[14:15])
            plik.write(str(dd))
            plik.write('\n')
                        
def checkEventLogApplication():
    c = wmi.WMI()
    file = (f'app_err_logs.txt')
    print(file)
    removeOldFile(str(file))
    d = []
    for log in c.Win32_NTLogEvent(Type="error", Logfile="Application"):
        data = re.sub('[^a-zA-Z0-9 \n\.\[\]\(\)\{\}]', '', str(log))
        with open(file, mode='a', encoding='UTF-8', errors='strict', buffering=1) as plik:
            d = data.split('\n')
            dd = (d[4:10], d[14:15])
            plik.write(str(dd))
            plik.write('\n')
            
def checkEventLogSystem():
    c = wmi.WMI()
    file = (f'sys_err_logs.txt')
    print(file)
    removeOldFile(str(file))
    d = []
    for log in c.Win32_NTLogEvent(Type="error", Logfile="System"):
        data = re.sub('[^a-zA-Z0-9 \n\.\[\]\(\)\{\}]', '', str(log))
        with open(file, mode='a', encoding='UTF-8', errors='strict', buffering=1) as plik:
            d = data.split('\n')
            dd = (d[4:10], d[14:15])
            plik.write(str(dd))
            plik.write('\n')
          
#checkEventLogSecurity(4625)

# # Security 4625 - Falied LogOn

# # Security 4660 - Delete file/folder

# # Security 4670 - Change permision

# # Security 4688 - Run as Administrator


# for os in c.Win32_OperatingSystem():
#     print(os.Caption)

try:
    checkEventLogApplication()
except OSError as e:
    print("Error: " + e)
try:
    checkEventLogSystem()
except OSError as e:
    print("Error: " + e)
try:
    checkEventLogSecurity(4625)
except OSError as e:
    print("Error: " + e)
try:
    checkEventLogSecurity(4660)
except OSError as e:
    print("Error: " + e)
try:
    checkEventLogSecurity(4670)
except OSError as e:
    print("Error: " + e)
try:
    checkEventLogSecurity(4688)
except OSError as e:
    print("Error: " + e)
    
