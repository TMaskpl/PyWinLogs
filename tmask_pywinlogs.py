import wmi
import re
import sys
import os
import os.path
import codecs
from shutil import move

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
    old = (f'sec_{id}_logs_old.txt')
    diff = (f'sec_{id}_logs_diff.txt')
    print(file)
    removeOldFile(str(old))
    if os.path.isfile(str(file)):
        move(str(file), str(old))
    d = []
    for log in c.Win32_NTLogEvent(EventCode=id, Logfile='Security'):
        data = re.sub('[^a-zA-Z0-9 \n\.\[\]\(\)\{\}]', '', str(log))
        with open(file, mode='a+', encoding='UTF-8', errors='strict', buffering=1) as plik:
            d = data.split('\n')
            dd = (d[4], d[5], d[9], d[10], d[11], d[14], d[16])
            plik.write(str(dd))
            plik.write('\n')

    if os.path.isfile(str(old)):
        with open(file, mode='r') as plik:
            with open(old, mode='r') as plik2:
                difference = set(plik).difference(plik2)
        difference.discard('\n')

        with open(diff, mode='w') as plik_out:
            for line in difference:
                plik_out.write(line)


def checkEventLogApplication():
    c = wmi.WMI()
    file = (f'app_err_logs.txt')
    old = (f'app_err_logs_old.txt')
    diff = (f'app_err_logs_diff.txt')
    print(file)
    removeOldFile(str(old))
    if os.path.isfile(str(file)):
        move(str(file), str(old))
    d = []
    for log in c.Win32_NTLogEvent(Type="error", Logfile="Application"):
        data = re.sub('[^a-zA-Z0-9 \n\.\[\]\(\)\{\}]', '', str(log))
        with open(file, mode='a+', encoding='UTF-8', errors='strict', buffering=1) as plik:
            d = data.split('\n')
            #dd = d[0:]
            dd = (d[4], d[5], d[9], d[10], d[14], d[16])
            plik.write(str(dd))
            plik.write('\n')

    if os.path.isfile(str(old)):
        with open(file, mode='r') as plik:
            with open(old, mode='r') as plik2:
                difference = set(plik).difference(plik2)
        difference.discard('\n')

        with open(diff, mode='w') as plik_out:
            for line in difference:
                plik_out.write(line)


def checkEventLogSystem():
    c = wmi.WMI()
    file = (f'sys_err_logs.txt')
    old = (f'sys_err_logs_old.txt')
    diff = (f'sys_err_logs_diff.txt')
    print(file)
    # removeOldFile(str(old))

    if os.path.isfile(str(file)):
        move(str(file), str(old))

    d = []

    for log in c.Win32_NTLogEvent(Type="error", Logfile="System"):
        data = re.sub('[^a-zA-Z0-9 \n\.\[\]\(\)\{\}]', '', str(log))
        with open(file, mode='a+', encoding='UTF-8', errors='strict', buffering=1) as plik:
            d = data.split('\n')
            dd = d[4:]
            dd = (d[4], d[11], d[12], d[13])
            plik.write(str(dd))
            plik.write('\n')

    if os.path.isfile(str(old)):
        with open(file, mode='r') as plik:
            with open(old, mode='r') as plik2:
                difference = set(plik).difference(plik2)
        difference.discard('\n')

        with open(diff, mode='w') as plik_out:
            for line in difference:
                plik_out.write(line)


if __name__ == "__main__":

    # try:
    #     checkEventLogApplication()
    # except OSError as e:
    #     print("Error: " + e)
    try:
        checkEventLogSystem()
    except OSError as e:
        print("Error: " + e)
    # try:
    #     checkEventLogSecurity(4625)
    # except OSError as e:
    #     print("Error: " + e)
    # try:
    #     checkEventLogSecurity(4660)
    # except OSError as e:
    #     print("Error: " + e)
    # try:
    #     checkEventLogSecurity(4670)
    # except OSError as e:
    #     print("Error: " + e)
    # try:
    #     checkEventLogSecurity(4688)
    # except OSError as e:
    #     print("Error: " + e)
