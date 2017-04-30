#!/usr/bin/python
###############################################
#   Static Byte FUZZer			              #
#   Author: malwrforensics                    #
#   Conact: malwr at malwrforensics dot com   #
###############################################

import os
import subprocess
import time
import sys

JUST_GENERATE	= 1     #just generate the files
IS_CMDLN        = 0     #don't try to kill the target app as it exited
DEBUG           = 0     #show the command line arguments (for debugging purposes)
TIMEOUT         = 1     #no of seconds to wait for the target program to load

ignore_list = ['Caption', 'SystemIdleProcess', 'System', 'smss.exe', 'csrss.exe', 'wininit.exe', 'csrss.exe', 'winlogon.exe', 'services.exe',
'lsass.exe', 'lsm.exe', 'spoolsv.exe', 'taskhost.exe', 'dwm.exe', 'explorer.exe', 'SearchIndexer.exe', 'svchost.exe', 'wmpnetwk.exe',
'audiodg.exe', 'sppsvc.exe', 'PresentationFontCache.exe', 'taskhost.exe', 'conhost.exe', 'WmiPrvSE.exe', 'python.exe', 'cmd.exe', 'WMIC.exe']

def get_size(fname):
    f = open(fname, 'rb')
    f.seek(0,2) # move the cursor to the end of the file
    size = f.tell()
    f.close()
    return size

def get_running_processes_windows():
    global ignore_list
    try:
        plist = []
        cmd = "wmic /output:process.lst process get caption"
        os.system(cmd)
        with open("process.lst", "r") as f:
            for line in f:
                line = line.replace('\x00', "")
                line = line.replace('\n', "")
                line = line.replace('\r', "")
                line = line.replace(' ', "")
                line = line.replace('\xff', "")
                line = line.replace('\xfe', "")
            if len(line) > 0 and line not in ignore_list:
                plist.append(line)
            os.remove("process.lst")
    except:
        print "[-] Error getting the process list"
    return plist

def generate_files(fileName, val, bytesToReplace, fuzzExt, fuzzFolder):
    try:
        if len(fileName) > 0:
            with open(fileName, "rb") as f:
                buff = f.read()

            print "[+] Generate " + str(len(buff)-bytesToReplace) + " files"
            for i in range(1, len(buff)-bytesToReplace):
                b = buff

                #replace byte(s) with new value(s)
                mid = chr(val)*bytesToReplace
                end = b[i+bytesToReplace:]

                if i > 0:
                    start = b[:i-1]
                else:
                    start = ""
                b = start + mid + end

                #write the a new file with the bytes changed
                name = fuzzFolder + "\\fuzz_" + str(i) + "." + str(fuzzExt)
                with open(name, "wb") as f:
                    f.write(b)
                i=i+1
    except:
        print "[-] generate_files(): Error generating files"

def set_startupinfo():
    startupinfo = None
    if os.name == 'nt':
        startupinfo = subprocess.STARTUPINFO()
        #hide the window of the new process
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return startupinfo
    return startupinfo

def byte_fuzz(fileName, val, fuzzExt, fuzzFolder, bytesToReplace, programToExecute, procName, noOfVariations):
    global JUST_GENERATE
    global IS_CMDLN
    global TIMEOUT
    try:
        if len(fileName) <=0  or len(programToExecute) <= 0 or len(procName) <=0 or noOfVariations == 0:
            print "[-] Invalid option"
            return

        fsize = get_size(fileName)
        plist_orig = get_running_processes_windows()
        if (bytesToReplace > 0 and bytesToReplace < fsize and val >= 0 and val <= 0xff):
            generate_files(fileName, val, bytesToReplace, fuzzExt, fuzzFolder)
        if JUST_GENERATE == 1:
            exit()

        print "[*] Check " + str(fsize-bytesToReplace) + " files"
        sys.stdout.write("Variant: ")
        sys.stdout.flush()
        for i in range(1, fsize-bytesToReplace):
            vSize = len(str(i))
            sys.stdout.write(str(i))
            sys.stdout.flush()
            name = fuzzFolder + "\\fuzz_" + str(i) + "." + str(fuzzExt)

	        #hide the window of the new process
            startupinfo = set_startupinfo()
            with open(os.devnull, 'w') as temp:
                proc = subprocess.Popen([programToExecute, name], startupinfo=startupinfo, stdout=temp, stderr=temp)
                time.sleep(TIMEOUT) #give the process time to load te file

            #check the number of processes to see if there is a crash
            try:
                flag_crash = 0 #will be 1 if a crash is detected
                plist_new = get_running_processes_windows()
                if IS_CMDLN == 0:
                    if len(plist_new) != len(plist_orig) + 1:
                        flag_crash = 1
                    else:
                        if len(plist_new) != len(plist_orig):
                            flag_crash = 1

                #crash was detected,
                #show the list of processes, before and after
                if flag_crash == 1:
                    print "\n[+] Possible crash at " + str(i)
                    print plist_orig
                    print plist_new
                    exit()

                #kill the process
                if IS_CMDLN == 0:
                    os.system("taskkill /f /im " + procName + " > " + os.devnull + " 2>&1")
                if noOfVariations > 0 and i>noOfVariations:
                    print "\n[*] Max tries reached"
                    exit()
                sys.stdout.write("\b" * vSize)
                sys.stdout.flush()
                i=i+1
            except Exception, e:
                print "\n[-] Error at offset " + str(i) + "\n" + str(e)
    except Exception, e:
        print "[-] Error " + str(e)

def usage():
    print "Usage: program [path] [ext] [value] [bytes] [executable] [caption] [variations]"
    print "\tpath\t\tpath and file name of the file to fuzz"
    print "\text\t\tfile extension of the fuzzed files"
    print "\tvalue\t\tthe value (between 0x0 and 0xff) that will be used to replace the bytes in the original file"
    print "\tbytes\t\thow many bytes to replace at a time, usually between 1 and 4"
    print "\texecutable\tthe path and name of the executable used to open the fuzzed files"
    print "\tcaption\t\tthe caption name of the process that is used to open the fuzzed files (usually the name of the executable)"
    print "\tvariations\thow many variations you want to test (if 0 then the size of the fuzzed file will be used)"
    print '\nExample: program test.pdf pdf 0xff 1 "C:\Program Files (x86)\Adobe\Bin\Acrord32.exe" Acrord32.exe 100'
    return

###MAIN###
if __name__ == "__main__":
    print "static BYTE FUZZer v1.0"
    if len(sys.argv) != 8:
        usage()
        exit()
    else:
	fileName = sys.argv[1]
	fuzzExt = sys.argv[2]

	if sys.argv[3].find("0x") != 0:
	    print "[-] The value has to be in hex"
	    exit()

	val = int(sys.argv[3], 16)
 	if val < 0:
	    val = 0

	bytesToReplace = int(sys.argv[4])
	if bytesToReplace <= 0:
	    print "[-] Nothing to replace"
	    exit()

	programToExecute = sys.argv[5]
	procName = sys.argv[6]
	noOfVariations = int(sys.argv[7])
	if noOfVariations <= 0:
	    noOfVariations = 600

	#create fuzz folder
	fuzzFolder = "fuzzfiles"
	if not os.path.exists(fuzzFolder):
	    os.makedirs(fuzzFolder)

	if DEBUG != 0:
	    print "[*] Debug info:"
	    print "\tfileName = " + fileName
	    print "\tfuzzExt = " + fuzzExt
	    print "\tval = " + str(val)
	    print "\tbytesToReplace = " + str(bytesToReplace)
	    print "\tprogramToExecute = " + programToExecute
	    print "\tprocName = " + procName
	    print "\tnoOfVariations = " + str(noOfVariations)

	byte_fuzz(fileName, val, fuzzExt, fuzzFolder, bytesToReplace, programToExecute, procName, noOfVariations)
	print "[*] Done"
