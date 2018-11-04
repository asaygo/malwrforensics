#!/usr/bin/python
###############################################
#   Byte FUZZer                 		      #
#   Author: malwrforensics                    #
#   Contact: malwr at malwrforensics dot com  #
###############################################

import os
import subprocess
import time
import sys
import struct
import re
import utils
import codecs
#from pydbg import *
#from pydbg.defines import *

TARGET_OS           = "LINUX"
VERSION             = "1.3"
FUZZ_FILE_PREFIX    = "fuzz"

verbose             = 1         #show the command line arguments (for debugging purposes)
fuzz_type           = 1         #get type of fuzzing: 0 - overwrite, 1 - append, 2 - delete
generate_only       = 0         #just generate the files
scan_only           = 0         #do not generate the files (useful to reproduce a crash)
timeout             = 2         #no of seconds to wait for the target program to load
ignore_flag         = 0         #value that won't be replaced; eg: 0s are just padding
ignore_value        = 0x0       #value that won't be replaced; eg: 0s are just padding
filename            = ""        #input file for program
fileext             = ""        #input file extension
program             = ""        #program to launch
mutation_value      = 0xff      #the bytes in the file will be overwritten with this value
bytes_replace       = 1         #number of consecutive bytes to overwrite
mutations           = 0         #how many mutations (0 = size of the file)
use_subp_popen      = 0         #use subprocess.popen and then kill (useful for GUIs)
scan_folder_only    = 0         #will be set if the program is run only with one parameter,
                                #the path to the folder containing mutated files

#not supported in LINUX
debug_program       = 0         #set to 1 if you want to pydbg the program; 0 will just use os.system

def load_config_file(fname):
    global verbose
    global fuzz_type
    global generate_only
    global scan_only
    global timeout
    global ignore_flag
    global ignore_value
    global filename
    global fileext
    global program
    global mutation_value
    global bytes_replace
    global mutations
    global use_subp_popen
    global debug_program

    try:
        print("[+] Read config file")
        with open(fname, 'r') as f:
            for line in f:
                if len(line) > 4:
                    if line[0:1] != "#":
                        m = re.match(r'\s*fuzz_type\s*=\s*(\d+).*', line, re.M|re.I)
                        if m:
                            fuzz_type = int(m.group(1))

                        m = re.match(r'\s*generate_only\s*=\s*(\d+).*', line, re.M|re.I)
                        if m:
                            generate_only = int(m.group(1))

                        m = re.match(r'\s*scan_only\s*=\s*(\d+).*', line, re.M|re.I)
                        if m:
                            scan_only = int(m.group(1))

                        m = re.match(r'\s*timeout\s*=\s*(\d+).*', line, re.M|re.I)
                        if m:
                            timeout = int(m.group(1))

                        m = re.match(r'\s*ignore_flag\s*=\s*(\d+).*', line, re.M|re.I)
                        if m:
                            ignore_flag = int(m.group(1))

                        m = re.match(r'\s*ignore_value\s*=\s*([0-9a-fx])[\r\n]*', line, re.M|re.I)
                        if m:
                            val = str(m.group(1))
                            ignore_value = int(val, 16)
                            if ignore_value < 0 or ignore_value > 255:
                                ignore_value = 0

                        m = re.match(r'\s*debug_program\s*=\s*(\d+).*', line, re.M|re.I)
                        if m:
                            debug_program = int(m.group(1))

                        m = re.match(r'filename\s*=\s*(.*)[\r\n]*', line, re.M|re.I)
                        if m:
                            filename = str(m.group(1))

                        m = re.match(r'\s*fileext\s*=\s*(\w+)[\r\n]*', line, re.M|re.I)
                        if m:
                            fileext = str(m.group(1))

                        m = re.match(r'\s*mutation_value\s*=\s*([0-9a-fx]+)[\r\n]*', line, re.M|re.I)
                        if m:
                            val = str(m.group(1))
                            mutation_value = int(val, 16)

                        m = re.match(r'\s*program\s*=\s*(.*)[\r\n]*', line, re.M|re.I)
                        if m:
                            program = str(m.group(1))

                        m = re.match(r'\s*bytes_replace\s*=\s*(\d+).*', line, re.M|re.I)
                        if m:
                            bytes_replace = int(m.group(1))

                        m = re.match(r'\s*mutations\s*=\s*(\d+).*', line, re.M|re.I)
                        if m:
                            mutations = int(m.group(1))

                        m = re.match(r'\s*use_subp_popen\s*=\s*(\d+).*', line, re.M|re.I)
                        if m:
                            use_subp_popen = int(m.group(1))

    except:
        print("[-] Can't read from file")
        return -1
    return 0

def get_size(fname):
    f = open(fname, 'rb')
    f.seek(0,2) # move the cursor to the end of the file
    size = f.tell()
    f.close()
    return size

def fuzztype_to_name():
    global fuzz_type
    if fuzz_type == 0:
        return "owr"

    if fuzz_type == 1:
        return "ins"

    if fuzz_type == 2:
        return "del"

    return "unk"

def generate_files(fname, val, n_bytes, fuzz_file_ext, fuzz_folder, n_mutations):
    global ignore_flag
    global ignore_value
    global fuzz_type
    global FUZZ_FILE_PREFIX

    counter = 0
    print ("[+] Generate mutations based on " + fname)

    if 1:
        if len(fname) > 0:
            with open(fname, "rb") as f:
                buff = f.read()
                f.close()

            if fuzz_type != 1 and len(buff) > n_bytes:
                size = str(len(buff)-n_bytes)
                if size > n_mutations:
                    size = n_mutations
            else:
                size = len(buff)

            print("[+] Generate " + str(size) + " files")
            for i in range(0, size):

                #skip values that aren't important
                if ignore_flag == 1:
                    if int(ord(buff[i])) == ignore_value:
                        continue

                counter = counter+1
                mid = []
                for j in range(0,n_bytes):
                    mid.append(val)

                #overwrite
                if fuzz_type == 0:
                    end = buff[i+n_bytes:]

                #insert
                if fuzz_type == 1:
                    end = buff[i:]

                #delete
                if fuzz_type == 2:

                    #if no bytes are to be removed
                    #then delete the last byte
                    if n_bytes == 0:
                        end = buff[0:size-i-n_bytes]
                    else:
                        end = buff[i+n_bytes:]

                start = []
                if i > 1:
                    for j in range(0,i):
                        start.append(buff[j])
                else:
                    if i==1:
                        start.append(buff[0])
                    else:
                        start = []

                if fuzz_type == 2:
                    mid = []
                    if n_bytes == 0:
                        start = []

                b = []
                if i>0:
                    for c in start:
                        b.append(c)
                for c in mid:
                    b.append(c)
                for c in end:
                    b.append(c)

                name = fuzz_folder + "\\" + FUZZ_FILE_PREFIX + "_" + fuzztype_to_name() + "_" + str(hex(val)) + "_" + str(i) + "." + str(fuzz_file_ext)
                with open(name, "wb") as f_out:
                    f_out.write(bytearray(b))
                    f_out.close()

    return counter

#def exception_handle(dbg):
#    print(dbg.dump_context())
#    raw_input("[+] Crash detected! Press a key to continue...")
#    return DBG_EXCEPTION_NOT_HANDLED

#def debug(exe_path, params):
#    dbg = pydbg()
#    pid = dbg.load(exe_path, params)
#    #dbg.attach(int(pid))
#    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, exception_handle)
#    dbg.set_callback(EXCEPTION_GUARD_PAGE, exception_handle)
#    dbg.run()
#    return

def HasCrashed(pname):
    global TARGET_OS
    try:
        os.remove("list.txt")
    except:
        print("[-] Can't find process list")

    #only for GUIs
    if "LINUX" in TARGET_OS:
        if os.path.isfile("core"):
            #core dump detected
            return 1
        os.system("ps aux | grep " + pname + " > list.txt")
        try:
            with open("list.txt", "r") as f:
                for p in f:
                    if pname.lower() in p.lower():
                        #if the process is there, it hasn't crashed
                        return 0
        except:
            print("[-] Can't read process list")

        #the process isn't in the list, so it has crashed
        return 1

    else:
        os.system("wmic /output:list.txt PROCESS get Caption,Commandline")
        try:
            with codecs.open("list.txt", encoding='utf-16', mode='r') as f:
                for p in f:
                    if "WerFault".lower() in p.lower():
                        return 1
        except:
            print("[-] Can't read proces list")
    return 0

def set_startupinfo():
    startupinfo = None
    if os.name == 'nt':
        startupinfo = subprocess.STARTUPINFO()
        #hide the window of the new process
        #startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return startupinfo
    return startupinfo

def launch_program_w_popen(target_program, name, output_folder):
    global timeout
    global TARGET_OS

    ###YOU MAY WANT TO CHANGE THIS###
    params = []
    params.append(name)
    #params.append(output_folder)

    pname = ""
    startupinfo = set_startupinfo()
    with open(os.devnull, 'w') as temp:
        if "WINDOWS" in TARGET_OS:
            proc = subprocess.Popen([target_program, params], startupinfo=startupinfo, stdout=temp, stderr=temp, shell=False)
            pname = "WerFault".lower()
        if "LINUX" in TARGET_OS:
            print(params)
            proc = subprocess.Popen([target_program, name], stdout=temp, stderr=temp, shell=False)
            pname = target_program
        time.sleep(timeout) #give the process time to load the file

        if HasCrashed(pname) == 1:
            raw_input("[+] Crash detected! Press a key to continue...")

        print("\n[*] Terminate process")
        if "WINDOWS" in TARGET_OS:
            proc.kill()
            #you may want to change this
            #os.system("taskkill /F /IM calc.exe")

        if "LINUX" in TARGET_OS:
            os.system("killall " + pname)
        time.sleep(1)

def launch_program(target_program, name, output_folder):
    global TARGET_OS
    global timeout
    #global debug_program

    ###YOU MAY WANT TO CHANGE THIS###
    params = " " + name

    #if debug_program == 1:
    #    debug(target_program, params)
    #else:
    print("[*] Launch " + target_program + params)
    os.system(target_program + params)
    time.sleep(timeout)

    print("\n[*] Terminate process")
    #you may want to change this
    if "WINDOWS" in TARGET_OS:
        os.system("taskkill /F /IM calc.exe")

    if "LINUX" in TARGET_OS:
        #disable the following check if there is no GUI
        if HasCrashed(target_program) == 1:
            raw_input("[+] Crash detected! Press a key to continue...")
        os.system("killall midori")

    time.sleep(1)

def byte_fuzz(fname, val, fuzz_file_ext, fuzz_folder, n_bytes, target_program, n_mutations, output_folder):
    global generate_only
    global scan_only
    global verbose
    global fuzz_type
    global FUZZ_FILE_PREFIX

    counter = 0
    try:
        if len(fname) <=0 or len(target_program) <= 0:
            print("[-] Invalid option")
            return

        if n_mutations == 0 and scan_only == 0:
            print("[-] Invalid option")
            return

        if scan_folder_only == 0:
            fsize = get_size(fname)
            if n_mutations < fsize:
                fsize = n_mutations

        if (n_bytes >= 0 and val >= 0 and val <= 0xff and scan_only == 0 and scan_folder_only == 0):
            counter = generate_files(fname, val, n_bytes, fuzz_file_ext, fuzz_folder, n_mutations)
            print("[+] Files generated: " + str(counter))

        if generate_only == 1 and scan_folder_only == 0:
            exit()

        if scan_folder_only == 0:
            if fuzz_type != 1:
                size = fsize-n_bytes
            else:
                size = fsize

            for i in range(1, size):
                name = fuzz_folder + "\\" + FUZZ_FILE_PREFIX + "_" + fuzztype_to_name() + "_" + str(hex(val)) + "_" + str(i) + "." + str(fuzz_file_ext)

                if not os.path.isfile(name):
                    continue

                vSize = len(str(i))
                sys.stdout.write(str(i))
                sys.stdout.flush()

                if use_subp_popen == 1:
                    launch_program_w_popen(target_program, name, output_folder)
                else:
                    launch_program(target_program, name, output_folder)

                sys.stdout.write("\b" * vSize)
                sys.stdout.flush()
        else:
            if use_subp_popen == 1:
                launch_program_w_popen(target_program, fname, output_folder)
            else:
                launch_program(target_program, fname, output_folder)
            os.system("mv " + fname + " " + output_folder + "/")

    except Exception as e:
        print("[-] Error byte_fuzz(): " + str(e))

def usage():
    print ("Usage: program [path] [ext] [value] [bytes] [executable] [caption] [variations]")
    print ("\tpath\t\tpath and file name of the file to fuzz")
    print ("\text\t\tfile extension of the fuzzed files")
    print ("\tvalue\t\tthe value (between 0x0 and 0xff) that will be used to replace the bytes in the original file")
    print ("\tbytes\t\thow many bytes to replace at a time, usually between 1 and 4")
    print ("\texecutable\tthe path and name of the executable used to open the fuzzed files")
    print ("\tcaption\t\tthe caption name of the process that is used to open the fuzzed files (usually the name of the executable)")
    print ("\tvariations\thow many variations you want to test (if 0 then the size of the fuzzed file will be used)")
    print ('\nExample: program test.pdf pdf 0xff 1 "C:\Program Files (x86)\Adobe\Bin\Acrord32.exe" Acrord32.exe 100')
    print ('\nExample: program /home/user/fuzzfiles')
    return

###MAIN###
if __name__ == "__main__":
    fuzz_folder = ""
    scan_folder_only = 0

    print ("ByteFUZZer v" + VERSION)
    if "LINUX" in TARGET_OS:
        print("[+] Enable core dumps")
        os.system("ulimit -c unlimited")

    if len(sys.argv) != 7:
        if load_config_file("bytefuzz.conf") == -1:
            usage()
            exit()
        if len(sys.argv) == 2:
            fuzz_folder = sys.argv[1]
            if not os.path.exists(fuzz_folder):
                print("[-] Invalid folder")
                exit()
            scan_only = 1
            scan_folder_only = 1
    else:
        filename = sys.argv[1]
        fileext = sys.argv[2]
        val = sys.argv[3]
        if val.find("0x") != 0:
            print ("[-] The value has to be in hex")
            exit()
        mutation_value = int(val, 16)

        bytes_replace = int(sys.argv[4])
        if bytes_replace <= 0:
            print ("[-] Nothing to replace")
            exit()

        program = sys.argv[5]
        mutations = int(sys.argv[6])


    if scan_folder_only == 0:
        if mutation_value < 0 or mutation_value > 255:
            mutation_value = 0

        if mutations <= 0:
            mutations = get_size(filename)

        #create fuzz folder
        fuzz_folder = "fuzzfiles"
        if not os.path.exists(fuzz_folder):
            os.makedirs(fuzz_folder)

    #create output files folder
    output_folder = "outfiles"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    print("[*] Don't forget to change the \"parameters\" value in launch_program()")

    if verbose != 0:
        print ("[*] Debug info:")
        if scan_folder_only == 0:
            print ("\tfile = " + filename)
            print ("\text = " + fileext)
            print ("\tbytes to replace = " + str(bytes_replace))
            print ("\tmutation value = " + str(mutation_value))
            print ("\tmax mutations = " + str(mutations))
            print ("\tfuzz_type = " + str(fuzz_type))
            print ("\tscan_only = " + str(scan_only))
            print ("\tgenerate_only = " + str(generate_only))

        print ("\tprogram = " + program)
        print("\tuse_subp_popen = " + str(use_subp_popen))

    if scan_folder_only == 0:
        byte_fuzz(filename, mutation_value, fileext, fuzz_folder, bytes_replace, program, mutations, output_folder)
    else:
        counter = 0
        for root, dirs, files in os.walk(fuzz_folder):
            for filename in files:
                byte_fuzz(root + "/" + filename, mutation_value, fileext, fuzz_folder, bytes_replace, program, mutations, output_folder)
                counter = counter + 1
        print("[*] Fuzzed " + str(counter) + " files")
    print ("[+] Done")
