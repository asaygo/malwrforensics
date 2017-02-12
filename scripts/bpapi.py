#!python
 
__VERSION__  = '1.00'
ProgName     = 'bpapi'
ProgVers     = __VERSION__
 
import immlib
 
def main(args):
    imm = immlib.Debugger()

    imm.setBreakpoint(imm.getAddress("ZwRaiseHardError"))
    x = imm.getAddress("ZwRaiseHardError")
    imm.log("ZwRaiseHardError: %x" % x)

    imm.setBreakpoint(imm.getAddress("bind"))
    x = imm.getAddress("bind")
    imm.log("bind: %x" % x)

    imm.setBreakpoint(imm.getAddress("listen"))
    x = imm.getAddress("listen")
    imm.log("listen: %x" % x)

    imm.setBreakpoint(imm.getAddress("socket"))
    x = imm.getAddress("socket")
    imm.log("socket: %x" % x)

    imm.setBreakpoint(imm.getAddress("DeviceIoControl"))
    x = imm.getAddress("DeviceIoControl")
    imm.log("DeviceIoControl: %x" % x)

    imm.setBreakpoint(imm.getAddress("ZwCreateFile"))
    x = imm.getAddress("ZwCreateFile")
    imm.log("ZwCreateFile: %x" % x)

    imm.setBreakpoint(imm.getAddress("ZwCreateSection"))
    x = imm.getAddress("ZwCreateSection")
    imm.log("ZwCreateSection: %x" % x)

    imm.setBreakpoint(imm.getAddress("ZwQueryInformationFile"))
    x = imm.getAddress("ZwQueryInformationFile")
    imm.log("ZwQueryInformationFile: %x" % x)

    imm.setBreakpoint(imm.getAddress("ZwQueryAttributesFile"))
    x = imm.getAddress("ZwQueryAttributesFile")
    imm.log("ZwQueryAttributesFile: %x" % x)

    imm.setBreakpoint(imm.getAddress("ZwCreateUserProcess"))
    x = imm.getAddress("ZwCreateUserProcess")
    imm.log("ZwCreateUserProcess: %x" % x)

    imm.setBreakpoint(imm.getAddress("ZwOpenKeyEx"))
    x = imm.getAddress("ZwOpenKeyEx")
    imm.log("ZwOpenKeyEx: %x" % x)

    imm.setBreakpoint(imm.getAddress("ZwOpenKey"))
    x = imm.getAddress("ZwOpenKey")
    imm.log("ZwOpenKey: %x" % x)

    imm.setBreakpoint(imm.getAddress("ResumeThread"))
    x = imm.getAddress("ResumeThread")
    imm.log("ResumeThread: %x" % x)

    imm.setBreakpoint(imm.getAddress("CopyFileA"))
    x = imm.getAddress("CopyFileA")
    imm.log("CopyFileA: %x" % x)

    imm.setBreakpoint(imm.getAddress("CopyFileExW"))
    x = imm.getAddress("CopyFileExW")
    imm.log("CopyFileExW: %x" % x)

    imm.setBreakpoint(imm.getAddress("CopyFileW"))
    x = imm.getAddress("CopyFileW")
    imm.log("CopyFileW: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateDirectoryA"))
    x = imm.getAddress("CreateDirectoryA")
    imm.log("CreateDirectoryA: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateDirectoryW"))
    x = imm.getAddress("CreateDirectoryW")
    imm.log("CreateDirectoryW: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateMutexA"))
    x = imm.getAddress("CreateMutexA")
    imm.log("CreateMutexA: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateMutexW"))
    x = imm.getAddress("CreateMutexW")
    imm.log("CreateMutexW: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateFileA"))
    x = imm.getAddress("CreateFileA")
    imm.log("CreateFileA: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateFileW"))
    x = imm.getAddress("CreateFileW")
    imm.log("CreateFileW: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateProcessA"))
    x = imm.getAddress("CreateProcessA")
    imm.log("CreateProcess: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateProcessW"))
    x = imm.getAddress("CreateProcessW")
    imm.log("CreateProcessW: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateProcessInternalA"))
    x = imm.getAddress("CreateProcessInternalA")
    imm.log("CreateProcessInternalA: %x" % x)

    imm.setBreakpoint(imm.getAddress("CreateRemoteThread"))
    x = imm.getAddress("CreateRemoteThread")
    imm.log("CreateRemoteThread: %x" % x)

    imm.setBreakpoint(imm.getAddress("WinExec"))
    x = imm.getAddress("WinExec")
    imm.log("WinExec: %x" % x)

    imm.setBreakpoint(imm.getAddress("OpenProcess"))
    x = imm.getAddress("OpenProcess")
    imm.log("OpenProcess: %x" % x)

    imm.setBreakpoint(imm.getAddress("Sleep"))
    x = imm.getAddress("Sleep")
    imm.log("Sleep: %x" % x)

    imm.setBreakpoint(imm.getAddress("IsDebuggerPresent"))
    x = imm.getAddress("IsDebuggerPresent")
    imm.log("IsDebuggerPresent: %x" % x)

    imm.setBreakpoint(imm.getAddress("WriteProcessMemory"))
    x = imm.getAddress("WriteProcessMemory")
    imm.log("WriteProcessMemory: %x" % x)

    imm.setBreakpoint(imm.getAddress("_write"))
    x = imm.getAddress("_write")
    imm.log("_write: %x" % x)

    imm.setBreakpoint(imm.getAddress("ZwWriteFile"))
    x = imm.getAddress("ZwWriteFile")
    imm.log("ZwWriteFile: %x" % x)

    imm.setBreakpoint(imm.getAddress("ZwWriteVirtualMemory"))
    x = imm.getAddress("ZwWriteVirtualMemory")
    imm.log("ZwWriteVirtualMemory: %x" % x)

    imm.setBreakpoint(imm.getAddress("SetThreadContext"))
    x = imm.getAddress("SetThreadContext")
    imm.log("SetThreadContext: %x" % x)

    imm.setBreakpoint(imm.getAddress("RegOpenKeyExA"))
    x = imm.getAddress("RegOpenKeyExA")
    imm.log("RegOpenKeyExA: %x" % x)

    imm.setBreakpoint(imm.getAddress("SysFreeString"))
    x = imm.getAddress("SysFreeString")
    imm.log("SysFreeString: %x" % x)

    imm.setBreakpoint(imm.getAddress("RtlFillMemory"))
    x = imm.getAddress("RtlFillMemory")
    imm.log("RtlFillMemory: %x" % x)

    imm.setBreakpoint(imm.getAddress("InternetCrackUrlA"))
    x = imm.getAddress("InternetCrackUrlA")
    imm.log("InternetCrackUrlA: %x" % x)

    imm.setBreakpoint(imm.getAddress("InternetConnectA"))
    x = imm.getAddress("InternetConnectA")
    imm.log("InternetConnectA: %x" % x)

    imm.setBreakpoint(imm.getAddress("InternetOpenUrlA"))
    x = imm.getAddress("InternetOpenUrlA")
    imm.log("InternetOpenUrlA: %x" % x)

    imm.setBreakpoint(imm.getAddress("InternetSetOptionW"))
    x = imm.getAddress("InternetSetOptionW")
    imm.log("InternetSetOptionW: %x" % x)

    imm.setBreakpoint(imm.getAddress("HttpOpenRequestW"))
    x = imm.getAddress("HttpOpenRequestW")
    imm.log("HttpOpenRequestW: %x" % x)

    imm.setBreakpoint(imm.getAddress("HttpSendRequestW"))
    x = imm.getAddress("HttpSendRequestW")
    imm.log("HttpSendRequestW: %x" % x)

    imm.setBreakpoint(imm.getAddress("UrlDownloadToFileA"))
    x = imm.getAddress("UrlDownloadToFileA")
    imm.log("UrlDownloadToFileA: %x" % x)

    imm.setBreakpoint(imm.getAddress("UrlDownloadToFileW"))
    x = imm.getAddress("UrlDownloadToFileW")
    imm.log("UrlDownloadToFileW: %x" % x)

    imm.setBreakpoint(imm.getAddress("connect"))
    x = imm.getAddress("connect")
    imm.log("connect: %x" % x)

    imm.setBreakpoint(imm.getAddress("send"))
    x = imm.getAddress("send")
    imm.log("send: %x" % x)

    imm.setBreakpoint(imm.getAddress("__vbaFreeStr"))
    x = imm.getAddress("__vbaFreeStr")
    imm.log("__vbaFreeStr: %x" % x)

    imm.setBreakpoint(imm.getAddress("__vbaFreeStrList"))
    x = imm.getAddress("__vbaFreeStrList")
    imm.log("__vbaFreeStrList: %x" % x)

    imm.setBreakpoint(imm.getAddress("__vbaStrMove"))
    x = imm.getAddress("__vbaStrMove")
    imm.log("__vbaStrMove: %x" % x)

    imm.setBreakpoint(imm.getAddress("__vbaStrCopy"))
    x = imm.getAddress("__vbaStrCopy")
    imm.log("__vbaStrCopy: %x" % x)

    imm.setBreakpoint(imm.getAddress("__vbaStrCat"))
    x = imm.getAddress("__vbaStrCat")
    imm.log("__vbaStrCat: %x" % x)

    imm.log("", focus=1)    
    return "Done!"
