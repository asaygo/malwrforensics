#!python
###############################################
#   POP3 Fuzzer                               #
#   Author: malwrforensics                    #
#   Contact: malwr at malwrforensics dot com  #
###############################################

import sys, socket
from random import randint

MIN_LIMIT = 50
MAX_LIMIT = 3000

def send_random_err(s):   
	global MIN_LIMIT
	global MAX_LIMIT
	try:
		f = open("commands.txt" ,"w")
		for i in range(MIN_LIMIT, MAX_LIMIT):
			buf = ""
			j=1
			for j in range(1,i):
	    			buf = buf + chr(randint(0x41, 0x5a))
			sploit = "-ERR " + buf
			f.write(str(i) + "|" + sploit + "\n")
  			conn.send(sploit)
		conn.close()
		f.close()
	except:
    		print ("[*] Client err.")
    		f.close()

def send_data_from_file(s, pocfile):   
	global MIN_LIMIT
	global MAX_LIMIT
	try:
		f = open(pocfile ,"r")
		buf = f.read()
		f.close()
		sploit = "-ERR " + buf
		conn.send(sploit)
		conn.close()
	except:
    		print ("[*] Client err.")

###MAIN###
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 110))
s.listen(1)
print ("[+] Listening on port 110.")
conn, addr = s.accept()
print '[*] Received connection from: ', addr
#send_random_err(s)
send_data_from_file(s, "poc.txt")
