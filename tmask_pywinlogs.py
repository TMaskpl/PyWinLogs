import wmi
import re
import sys
import os
import os.path
import codecs
from shutil import move

# c = wmi.WMI("MachineB", user=r"MachineB\fred", password="secret")

c = wmi.WMI()

# 4624	Successful account log on
# 4625	Failed account log on
# 4634	An account logged off
# 4648	A logon attempt was made with explicit credentials
# 4719	System audit policy was changed.
# 4964	A special group has been assigned to a new log on
# 1102	Audit log was cleared. This can relate to a potential attack
# 4720	A user account was created
# 4722	A user account was enabled
# 4723	An attempt was made to change the password of an account
# 4725	A user account was disabled
# 4728	A user was added to a privileged global group
# 4732	A user was added to a privileged local group
# 4756	A user was added to a privileged universal group
# 4738	A user account was changed
# 4740	A user account was locked out
# 4767	A user account was unlocked
# 4735	A privileged local group was modified
# 4737	A privileged global group was modified
# 4755	A privileged universal group was modified
# 4772	A Kerberos authentication ticket request failed
# 4777	The domain controller failed to validate the credentials of an account.
# 4782	Password hash an account was accessed
# 4616	System time was changed
# 4657	A registry value was changed
# 4697	An attempt was made to install a service
# 4698, 4699, 4700, 4701, 4702	Events related to Windows scheduled tasks being created, modified, deleted, enabled or disabled
# 4946	A rule was added to the Windows Firewall exception list
# 4947	A rule was modified in the Windows Firewall exception list
# 4950	A setting was changed in Windows Firewall
# 4954	Group Policy settings for Windows Firewall has changed
# 5025	The Windows Firewall service has been stopped
# 5031	Windows Firewall blocked an application from accepting incoming traffic
# 5152, 5153	A network packet was blocked by Windows Filtering Platform
# 5155	Windows Filtering Platform blocked an application or service from listening on a port
# 5157	Windows Filtering Platform blocked a connection
# 5447	A Windows Filtering Platform filter was changed

EventId = [4624	,
           4625	,
           4634	,
           4648	,
           4660,
           4670,
           4688,
           4719	,
           4964	,
           1102	,
           4720	,
           4722	,
           4723	,
           4725	,
           4728	,
           4732	,
           4756	,
           4738	,
           4740	,
           4767	,
           4735	,
           4737	,
           4755	,
           4772	,
           4777	,
           4782	,
           4616	,
           4657	,
           4697	,
           4698, 4699, 4700, 4701, 4702	,
           4946	,
           4947	,
           4950	,
           4954	,
           5025	,
           5031	,
           5152, 5153	,
           5155	,
           5157	,
           5447	,
           ]


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
            #dd = (d[4], d[5], d[9], d[10], d[11], d[14], d[16])
            dd = d[4:]
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

    try:
        checkEventLogApplication()
    except OSError as e:
        print("Error: " + e)
    try:
        checkEventLogSystem()
    except OSError as e:
        print("Error: " + e)

    for id in EventId:
        try:
            checkEventLogSecurity(id)
        except OSError as e:
            print("Error: " + e)
