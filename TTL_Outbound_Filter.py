import socket
import argparse
import sys
from Texts import *
import platform
import re

# http://www.shelliscoming.com/2014/11/getting-outbound-filtering-rules-by.html
# "The idea is to launch a TCP connection to a public IP (this IP does not need to be under your control) with a low TTL value" -  Borja Merino 
# Based on his ruby version : https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/recon/outbound_ports.rb

# TODO 
# Port Range (9800-9850)
# TCP and ICMP support
# Fix TTL auto discovery
# MutliThreading


# Create ICMP Socket to receive feedback from node
def ICMP_Socket(timeout):
	try:
		Socket =  socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname('icmp'))
		Socket.settimeout(timeout)
		#Socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
		WRITE_GREEN("ICMP Socket successfully created !")
		return Socket
	except Exception as e:
		WRITE_ERROR("Cannot bind ICMP socket : ")
		raise
		
# Create a non blocking socket in TCP/UDP/ICMP
# WARNING : Only UDP is working at the moment
def Non_Blocking_Socket(protocol):
	try:
		Socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname(protocol))
		#Socket.setblocking(0)
		WRITE_GREEN("Non-blocking socket successfully created !")
		return Socket
	except Exception as e:
		WRITE_ERROR("Cannot bind non-blocking socket : ")
		raise
	
# Print infos
def Write_Infos(options):
	WRITE_BLUE("Informations : ")
	WRITE_BLUE("Public IP : " + options.IP)
	WRITE_BLUE("Port(s) : " + options.Ports)
	WRITE_BLUE("TTL (small values may raise false positives): " + str(options.TTL))
	WRITE_BLUE("ICMP socket timeout : " + str(options.Timeout))
	print()
	
# Convert string to array
def Ports_Array(Ports):
	Ports_Array = Ports.split(',')
	Ret_Ports_Array = []
	try:
		for i in Ports_Array:
			if '-' in i:
				for j in list(range(int(i.split('-')[0]), int(i.split('-')[1])+1)):
					Ret_Ports_Array.append(int(j))				
			else:
				int(i)
				Ret_Ports_Array.append(int(i))
				
	except Exception as e:
		WRITE_ERROR("Ports are not well set : " + Ports)
		raise
	return Ret_Ports_Array

	
# Regex to determine if IP are public or local
def Reg_Intern_IP(IP):
	if (re.match("^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$", IP)):
		return 0
	elif (re.match("^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$", IP)):
		return 0
	elif (re.match("^192\.168\.\d{1,3}\.\d{1,3}$", IP)):
		return 0
	elif (re.match("^172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}$", IP)):
		return 0
	else:
		return 1

# Main function, try to reach the internet via a port and wait for a feedback on the ICMP socket to determine if we reach the internet yet
def Trace_Port(Port, IP, S_ICMP, S_NonBlock, TTL):
	S_ICMP.bind(('', Port))
	route = []
	for i in range(1, TTL):
		S_NonBlock.setsockopt(socket.SOL_IP, socket.IP_TTL, i)
		
		try:
			S_NonBlock.sendto(b'', (IP, Port))
			_, current_address = S_ICMP.recvfrom(512)
			route.append(current_address[0])
			if (Reg_Intern_IP(current_address[0])):
				WRITE_GREEN("Port : " + str(Port) + " looks open !")
				return route
		except:
			pass
	WRITE_ERROR("Port : " + str(Port) + " looks closed !")
	print(route)
	return

# print route like a traceroute
def Print_route(route):
	for i in range(0, len(route)):
		if not(i == (len(route) -1)):
			print( route[i] + " ===> ", end='')
		else:
			print(route[i] + "\n")


			
# main
if __name__ == '__main__':
	# Windows may block ICMP feedback
	if (platform.system() == "Windows"):
		print("Please avoid using Windows, it does not work well with this script (firewall must be configured to accept ICMP input)")
		exit(-1)
	else:
		if not os.geteuid()==0:
			WRITE_ERROR("You need to be root to create a RAW_SOCKET. Please restart as root.")
			exit(-2)
	
	# The following is used to look like a UNIX command line tool
	parser = argparse.ArgumentParser(description="The purpose of this PoC is to detect outbound filtering rules in a network", usage=(sys.argv[0] + "--help"))
	parser.add_argument("-I", "--IP", type=str, default="8.8.8.8", help ="Destination public IP address") 
	parser.add_argument('-p', '-P', action="store", dest="Ports", help="Ports must be like : XX,YY,ZZ,AA-BB", default="80,443")
	parser.add_argument('--ttl', '--TTL', action="store", type=int, dest="TTL", help="Define minimum TTL", default=4)
	parser.add_argument("--timeout", '--TIMEOUT', type=int, dest="Timeout", default=2, help ="timeout for ICMP socket") 
	parser.add_argument("-s", '-S', "--stop", default=False, dest="Stop", action='store_true', help ="Boolean arg. Stop at first port not filtered (when it reaches a public IP)") 
	parser.add_argument("-t", '-T', "--threads", type=int, default=10, help ="Number of threads to test ports. (Work in progress)") 
	parser.add_argument("-q", '-q', "--protocol", type=str, default="udp", dest="Protocol", help ="Protocol to determine open ports (TCP,UDP,ICMP) (Work in progress)") 
	parser.add_argument("-a", '-A', "--all", default=False, dest="all", action='store_true', help ="Boolean arg. Check all ports (takes time)") 

	options = parser.parse_args()
	# In case we decide to test all ports
	WRITE_HEADER("\nOutbound filtering rules tester - CVO - HERNAULT Paul")
	if (options.all):
		Ports = list(range(1,65535))
	else:
		Ports = Ports_Array(options.Ports)
	S_ICMP = ICMP_Socket(options.Timeout)
	Write_Infos(options)
	
	
	S_NonBlock = Non_Blocking_Socket(options.Protocol)
	# Trace for all ports
	for i in Ports:
		r = Trace_Port(i,options.IP, S_ICMP, S_NonBlock, options.TTL)
		if (r!= None):
			Print_route(r)
			if(options.Stop):
				WRITE_BLUE("Stop option enabled, now exiting")
				exit()

	
