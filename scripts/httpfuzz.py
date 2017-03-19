#!/usr/bin/python
###############################################
#   HTTP Fuzzer                               #
#   Author: malwrforensics                    #
#   Contact: malwr at malwrforensics dot com  #
###############################################

import socket
import os
import sys
import time
from random import randint

def write_random_poc(fname,limit):
    poc = ""
    junk = ""
    i=0
    while i<limit: 
            junk += chr(randint(0x41, 0x5a))
            i=i+1

    poc = junk
    #name = fname + "_" + str(limit)
    #fhandle = open(name, 'wb')
    #fhandle.write(poc)
    #fhandle.close()
    return poc

def fuzz_req_type(server, port):
        indx = 100
	while indx<1000:
		crash = "\x41" * indx
		buffer= crash + " /index.html HTTP/1.1\r\n"
		buffer+="Host: 127.0.0.1\r\n"
		buffer+="Referrer: http://127.0.0.1\r\n"
		buffer+="Content-Type: text/html\r\n"
		buffer+="User-Agent: Mozilla/5.0\r\n"
		buffer+="Cookie: mycookie123\r\n"
		buffer+="Content-Length: 1048576\r\n\r\n"
		print "[*] Sending fuzz_req HTTP request (len:" + str(len(crash)) + ")"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect((server, port))
		expl.send(buffer)
		expl.close()
		time.sleep(0.5)
		indx = indx + 5

def fuzz_page(server, port):
        indx = 100
	while indx<1000:
		crash = "\x41" * indx
		buffer= "GET /" + crash + " HTTP/1.1\r\n"
		buffer+="Host: 127.0.0.1\r\n"
		buffer+="Referrer: http://127.0.0.1\r\n"
		buffer+="Content-Type: text/html\r\n"
		buffer+="User-Agent: Mozilla/5.0\r\n"
		buffer+="Cookie: mycookie123\r\n"
		buffer+="Content-Length: 1048576\r\n\r\n"
		print "[*] Sending fuzz_page HTTP request (len:" + str(len(crash)) + ")"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect((server, port))
		expl.send(buffer)
		expl.close()
		time.sleep(0.5)
		indx = indx + 5

def fuzz_protocol(server, port):
        indx = 100
	while indx<1000:
		crash = "\x41" * indx
		buffer= "GET /index.html " + crash + "/1.1\r\n"
		buffer+="Host: 127.0.0.1\r\n"
		buffer+="Referrer: http://127.0.0.1\r\n"
		buffer+="Content-Type: text/html\r\n"
		buffer+="User-Agent: Mozilla/5.0\r\n"
		buffer+="Cookie: mycookie123\r\n"
		buffer+="Content-Length: 1048576\r\n\r\n"
		print "[*] Sending fuzz_prot HTTP request (len:" + str(len(crash)) + ")"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect((server, port))
		expl.send(buffer)
		expl.close()
		time.sleep(0.5)
		indx = indx + 5

def fuzz_host(server, port):
        indx = 100
	while indx<1000:
		crash = "\x41" * indx
		buffer= "GET /index.html HTTP/1.1\r\n"
		buffer+="Host: " + crash + "\r\n"
		buffer+="Referrer: http://127.0.0.1\r\n"
		buffer+="Content-Type: text/html\r\n"
		buffer+="User-Agent: Mozilla/5.0\r\n"
		buffer+="Cookie: mycookie123\r\n"
		buffer+="Content-Length: 1048576\r\n\r\n"
		print "[*] Sending fuzz_host HTTP request (len:" + str(len(crash)) + ")"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect((server, port))
		expl.send(buffer)
		expl.close()
		time.sleep(0.5)
		indx = indx + 5

def fuzz_referrer(server, port):
        indx = 100
	while indx<1000:
		crash = "\x41" * indx
		buffer= "GET /index.html HTTP/1.1\r\n"
		buffer+="Host: 127.0.0.1\r\n"
		buffer+="Referrer: http://" + crash + "\r\n"
		buffer+="Content-Type: text/html\r\n"
		buffer+="User-Agent: Mozilla/5.0\r\n"
		buffer+="Cookie: mycookie123\r\n"
		buffer+="Content-Length: 1048576\r\n\r\n"
		print "[*] Sending fuzz_ref HTTP request (len:" + str(len(crash)) + ")"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect((server, port))
		expl.send(buffer)
		expl.close()
		time.sleep(0.5)
		indx = indx + 5

def fuzz_content_type(server, port):
        indx = 100
	while indx<1000:
		crash = "\x41" * indx
		buffer= "GET /index.html HTTP/1.1\r\n"
		buffer+="Host: 127.0.0.1\r\n"
		buffer+="Referrer: http://127.0.0.1\r\n"
		buffer+="Content-Type: " + crash + "\r\n"
		buffer+="User-Agent: Mozilla/5.0\r\n"
		buffer+="Cookie: mycookie123\r\n"
		buffer+="Content-Length: 1048576\r\n\r\n"
		print "[*] Sending fuzz_ctype HTTP request (len:" + str(len(crash)) + ")"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect((server, port))
		expl.send(buffer)
		expl.close()
		time.sleep(0.5)
		indx = indx + 5

def fuzz_user_agent(server, port):
        indx = 100
	while indx<1000:
		crash = "\x41" * indx
		buffer= "GET /index.html HTTP/1.1\r\n"
		buffer+="Host: 127.0.0.1\r\n"
		buffer+="Referrer: http://127.0.0.1\r\n"
		buffer+="Content-Type: text/html\r\n"
		buffer+="User-Agent: " + crash + "\r\n"
		buffer+="Cookie: mycookie123\r\n"
		buffer+="Content-Length: 1048576\r\n\r\n"
		print "[*] Sending fuzz_ua HTTP request (len:" + str(len(crash)) + ")"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect((server, port))
		expl.send(buffer)
		expl.close()
		time.sleep(0.5)
		indx = indx + 5

def fuzz_content_length(server, port):
        indx = 100
	while indx<1000:
		crash = "\x41" * indx
		buffer= "GET /index.html HTTP/1.1\r\n"
		buffer+="Host: 127.0.0.1\r\n"
		buffer+="Referrer: http://127.0.0.1\r\n"
		buffer+="Content-Type: text/html\r\n"
		buffer+="User-Agent: Mozilla/5.0\r\n"
		buffer+="Cookie: mycookie123\r\n"
		buffer+="Content-Length: " + crash + "\r\n\r\n"
		print "[*] Sending fuzz_clen HTTP request (len:" + str(len(crash)) + ")"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect((server, port))
		expl.send(buffer)
		expl.close()
		time.sleep(0.5)
		indx = indx + 5

def fuzz_cookie(server, port):
        indx = 100
	while indx<1000:
		crash = "\x41" * indx
		buffer= "GET /index.html HTTP/1.1\r\n"
		buffer+="Host: 127.0.0.1\r\n"
		buffer+="Referrer: http://127.0.0.1\r\n"
		buffer+="Content-Type: text/html\r\n"
		buffer+="User-Agent: Mozilla/5.0\r\n"
		buffer+="Cookie: " + crash + "\r\n"
		buffer+="Content-Length: 1048576\r\n\r\n"
		print "[*] Sending fuzz_cookie HTTP request (len:" + str(len(crash)) + ")"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect((server, port))
		expl.send(buffer)
		expl.close()
		time.sleep(0.5)
		indx = indx + 5

###MAIN###
myserver = "127.0.0.1"
myport = 9090
print "[+] Fuzz request type"
fuzz_req_type(myserver, myport)

print "[+] Fuzz page"
fuzz_page(myserver, myport)

print "[+] Fuzz protocol"
fuzz_protocol(myserver, myport)

print "[+] Fuzz host"
fuzz_host(myserver, myport)

print "[+] Fuzz referrer"
fuzz_referrer(myserver, myport)

print "[+] Fuzz content type"
fuzz_content_type(myserver, myport)

print "[+] Fuzz user agent"
fuzz_user_agent(myserver, myport)

print "[+] Fuzz content length"
fuzz_content_length(myserver, myport)

print "[+] Fuzz cookie"
fuzz_cookie(myserver, myport)
