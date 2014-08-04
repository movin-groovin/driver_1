#!/usr/bin/python
#-*- encoding:utf-8 -*-

#xxxDEAD-BEAFxxx

import sys, os
from os import getuid, geteuid, setreuid



def main ():
	if len (sys.argv) < 2:
		print ("Need args")
	
	print ("Reid: {0}, Euid: {1}".format (getuid (), geteuid ()))
	try:
		setreuid (1234, 12345)
	except OSError as Exc:
		print (Exc)
	os.system ("cat /etc/shadow")
	print ("Ruid: {0}, Euid: {1}".format (getuid (), geteuid ()))
	
	return



main ()
