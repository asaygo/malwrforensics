#! python
###############################################
#   .c/.cpp banned windows API checker        #
#   Author: malwrforensics                    #
#   Contact: malwr at malwrforensics dot com  #
###############################################

import os
import sys

banned_apis = ["strcpy", "strcpyA", "strcpyW", "wcscpy", "_tcscpy", "_mbscpy", "StrCpy", "StrCpyA", "StrCpyW", "lstrcpy", "lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy", "_ftcscpy", "strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", "lstrcpyn", "lstrcpynA", "lstrcpynW",
"strcat", "strcatA", "strcatW", "wcscat", "_tcscat", "_mbscat", "StrCat", "StrCatA", "StrCatW", "lstrcat", "lstrcatA", "lstrcatW", "StrCatBuff", "StrCatBuffA", "StrCatBuffW", "StrCatChainW", "_tccat", "_mbccat", "_ftcscat", "strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat", "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", "lstrncat", "lstrcatnA", "lstrcatnW", "lstrcatn",
"sprintfW", "sprintfA", "wsprintf", "wsprintfW", "wsprintfA", "sprintf", "swprintf", "_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf", "vswprintf",
"wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf", "vswprintf",
"strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", "lstrcpyn", "lstrcpynA", "lstrcpynW", "_fstrncpy",
"strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat", "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", "lstrncat", "lstrcatnA", "lstrcatnW", "lstrcatn", "_fstrncat",
"gets", "_getts", "_gettws", "memcpy", "RtlCopyMemory", "CopyMemory", "wmemcpy"]

def contains_banned_api(s):
    global banned_apis
    for api in banned_apis:
        if api in s:
            return 1
    return 0

def check_banned_api(fname):
    try:
        if len(fname) < 3:
            return

        counter_line = 0
        with open(fname, "r") as f:
            for line in f:
                counter_line = counter_line + 1
                if contains_banned_api(line) == 1:
                    print(fname + ":(L" + str(counter_line) +"):" + line)
    except:
        print("check_banned_api(): Error reading from file " + str(fname))
    return

def get_files(path):
  for root, subdirs, files in os.walk(path):
    for file in os.listdir(root):
        filePath = os.path.join(root, file)
        if os.path.isdir(filePath):
            pass
        else:
            if len(filePath) > 3:
                if ".c" in filePath[-2:] or ".h" in filePath[-2:] or ".cpp" in filePath[-4:]:
                    check_banned_api(filePath)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        print("malwrforensics.com - Banned Windows API checker v1.0\n")
        get_files(sys.argv[1])
        print("[+] Done")
    else:
        print("program [folder]")
