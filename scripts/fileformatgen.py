#!/usr/bin/python
###############################################
#   File Format Generator		      #
#   Author: malwrforensics                    #
#   Conact: malwr at malwrforensics dot com   #
###############################################

from random import randint

def write_jpeg_header(fname):
	header = chr(0xFF) + chr(0xD8)	#SOI marker
	header += chr(0xFF) + chr(0xE0)	#App use marker
	header += chr(0x00) + chr(10)	#Len of APP0 field
	header += chr(0x4A) + chr(0x46) + chr(0x49) + chr(0x46) +chr(0x0)	#JFIF
	fhandle = open(fname , 'ab')
	fhandle.write(header)
	fhandle.close()

def write_gif_header(fname):
	header = chr(0x47) + chr(0x49) + chr(0x46)	#GIF
	header += chr(0x38) + chr(0x39)	+ chr(0x61)	#version
	fhandle = open(fname , 'ab')
	fhandle.write(header)
	fhandle.close()

def write_png_header(fname):
	header = chr(137) + chr(80) + chr(78) + chr(71) + chr(13) + chr(10) + chr(26) + chr(10)
	fhandle = open(fname , 'ab')
	fhandle.write(header)
	fhandle.close()

def write_bmp_header(fname):
	#BM+size(4)+reserved(4)+starting addr
	header = "BM" + chr(0xff) + chr(0xff) + chr(0xff) + chr(0xff) + chr(0x41) + chr(0x41) + chr(0x41) + chr(0x41) + "\x00\x00\x00\x0E"
	fhandle = open(fname , 'ab')
	fhandle.write(header)
	fhandle.close()

def write_pdf_header(fname):
	header = chr(0x25) + chr(0x50) + chr(0x44) + chr(0x46) + chr(0x2d) + chr(0x31) + chr(0x2e)
	header +=  chr(0x33) + chr(0x0a) + chr(0x25) + chr(0xc4) + chr(0xe5) + chr(0xf2) + chr(0xe5)
	header +=  chr(0xeb) + chr(0xa7)
	fhandle = open(fname , 'ab')
	fhandle.write(header)
	fhandle.close()

def write_cue_file(fname, buffer):
	header = "FILE \""
	header += buffer
	header += "\" BINARY\n"
	header += "  INDEX 01 00:00:00\n"
	header += "  INDEX 01 00:00:00"
	fhandle = open(fname , 'wb')
	fhandle.write(header)
	fhandle.close()

def write_avi_header(fname):
	#RIFF size AVI
	header = "\x52\x49\x46\x46" + "\xFF\xFF\xFF\xFF" + "\x41\x56\x49\x20"
	fhandle = open(fname , 'ab')
	fhandle.write(header)
	fhandle.close()

def write_random_poc(fname, limit):
	junk = ""
	i=0
	while i<limit:
		junk += chr(randint(0x41, 0x5a))
		i=i+1

	poc = junk
	fhandle = open(fname , 'ab')
	fhandle.write(poc)
	fhandle.close()

def write_constant_poc(fname, val):
	poc = val * 10000
	fhandle = open(fname , 'ab')
	fhandle.write(poc)
	fhandle.close()


fname="poc.txt"
#write_jpeg_header(fname)
#write_gif_header(fname)
#write_png_header(fname)
#write_pdf_header(fname)

write_random_poc(fname, 0x300)
#write_constant_poc(fname, chr(0x0))
