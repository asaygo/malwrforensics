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
from pydbg import *
from pydbg.defines import *
import utils

VERSION             = "1.2"

verbose             = 1     	#show the command line arguments (for debugging purposes)
fuzz_type           = 1     	#get type of fuzzing: 0 - overwrite, 1 - append, 2 - delete
generate_only       = 0     	#just generate the files
scan_only           = 0     	#do not generate the files (useful to reproduce a crash)
timeout             = 2     	#no of seconds to wait for the target program to load
ignore_flag         = 0     	#value that won't be replaced; eg: 0s are just padding
ignore_value        = 0x0     	#value that won't be replaced; eg: 0s are just padding
debug_program       = 1		#set to 1 if you want to pydbg the program; 0 will just use os.system
filename            = ""	#input file for program
fileext             = ""	#input file extension
program             = ""	#program to launch
mutation_value      = 0xff	#the bytes in the file will be overwritten with this value
bytes_replace       = 1		#number of consecutive bytes to overwrite
mutations           = 0		#how many mutations (0 = size of the file)
use_subp_popen      = 0         #use subprocess.popen and then kill (useful for GUIs)

def load_config_file(fname):
    global verbose
    global fuzz_type
    global generate_only
    global scan_only
    global timeout
    global ignore_flag
    global ignore_value
    global debug_program
    global filename
    global fileext
    global program
    global mutation_value
    global bytes_replace
    global mutations
    global use_subp_popen

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

def generate_files(fname, val, n_bytes, fuzz_file_ext, fuzz_folder, n_mutations):
    global ignore_flag
    global ignore_value
    global fuzz_type
    counter = 0
    print ("[+] Generate mutations based on " + fname)

    if 1:
        if len(fname) > 0:
            with open(fname, "rb") as f:
                buff = f.read()
                f.close()

            if fuzz_type != 1 and len(buff) < n_bytes:
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

                name = fuzz_folder + "\\fuzz_" + str(hex(val)) + "_" + str(i) + "." + str(fuzz_file_ext)
                with open(name, "wb") as f_out:
                    f_out.write(bytearray(b))
                    f_out.close()

    return counter

def exception_handle(dbg):
    print(dbg.dump_context())
    raw_input("[+] Crash detected! Press a key to continue...")
    return DBG_EXCEPTION_NOT_HANDLED

def debug(exe_path, params):
    dbg = pydbg()
    pid = dbg.load(exe_path, params)
    #dbg.attach(int(pid))
    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, exception_handle)
    dbg.set_callback(EXCEPTION_GUARD_PAGE, exception_handle)
    dbg.run()
    return

def set_startupinfo():
    startupinfo = None
    if os.name == 'nt':
        startupinfo = subprocess.STARTUPINFO()
        #hide the window of the new process
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return startupinfo
    return startupinfo

def launch_program_w_popen(target_program, name, output_folder):
    global timeout

    ###YOU MAY WANT TO CHANGE THIS###
    params = []
    params.append("x")
    params.append("-y")
    params.append("-or")
    params.append(name)
    params.append(output_folder)

    startupinfo = set_startupinfo()
    with open(os.devnull, 'w') as temp:
        proc = subprocess.Popen([programToExecute, params], startupinfo=startupinfo, stdout=temp, stderr=temp, shell=False)
        time.sleep(timeout) #give the process time to load the file
        proc.kill()

def launch_program(target_program, name, output_folder):
    global timeout
    global debug_program

    ###YOU MAY WANT TO CHANGE THIS###
    params = " x -y -or " + name + " " + output_folder

    exe_path = target_program
    if debug_program == 1:
        debug(exe_path, params)
    else:
        os.system(exe_path + params)
    time.sleep(timeout)

def byte_fuzz(fname, val, fuzz_file_ext, fuzz_folder, n_bytes, target_program, n_mutations, output_folder):
    global generate_only
    global scan_only
    global verbose
    global fuzz_type

    counter = 0
    try:
        if len(fname) <=0  or len(target_program) <= 0 or n_mutations == 0:
            print("[-] Invalid option")
            return

        fsize = get_size(fname)
        if n_mutations < fsize:
            fsize = n_mutations

        if (n_bytes >= 0 and val >= 0 and val <= 0xff and scan_only == 0):
            counter = generate_files(fname, val, n_bytes, fuzz_file_ext, fuzz_folder, n_mutations)
            print("[+] Files generated: " + str(counter))

        if generate_only == 1:
            exit()

        if fuzz_type != 1:
            size = fsize-n_bytes
        else:
            size = fsize

        for i in range(1, size):
            name = fuzz_folder + "\\fuzz_" + str(hex(val)) + "_" + str(i) + "." + str(fuzz_file_ext)

            #if verbose == 1:
                #print("Val = " + str(val))
                #print("\tWork on " + name)

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
    except Exception as e:
        print("[-] Error: " + str(e))

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
    return

###MAIN###
if __name__ == "__main__":
    print ("static BYTE FUZZer v" + VERSION)
    if len(sys.argv) != 7:
        if load_config_file("bytefuzz.conf") == -1:
            usage()
            exit()
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
        print ("\tfile = " + filename)
        print ("\text = " + fileext)
        print ("\tprogram = " + program)
        print ("\tbytes to replace = " + str(bytes_replace))
        print ("\tmutation value = " + str(mutation_value))
        print ("\tmax mutations = " + str(mutations))
        print ("\tfuzz_type = " + str(fuzz_type))
        print ("\tscan_only = " + str(scan_only))
        print ("\tgenerate_only = " + str(generate_only))

    byte_fuzz(filename, mutation_value, fileext, fuzz_folder, bytes_replace, program, mutations, output_folder)
    print ("[+] Done")
