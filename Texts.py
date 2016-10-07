import platform

ERROR = '\033[91m'
ENDC = '\033[0m'
OKGREEN = '\033[92m'
OKBLUE = '\033[94m'
WARNING = '\033[93m'
HEADER = '\033[95m'

System = platform.system()


# This file is used to write with color under UNIX systems

def WRITE_ERROR(msg):
	if (System == "Windows"):
		print("[-] " + msg)
	else:
		print (ERROR + "[-] " +  msg + ENDC)


def WRITE_WARNING(msg):
	if (System == "Windows"):
		print("[WARNING]\t" + msg)
	else:
		print (WARNING + "[WARNING]\t" + msg + ENDC)
		
def WRITE_GREEN(msg):
	if (System == "Windows"):
		print("[+] " + msg)
	else:
		print (OKGREEN + "[+] " + msg + ENDC)

def WRITE_BLUE(msg):
	if (System == "Windows"):
		print(msg)
	else:
		print (OKBLUE + msg + ENDC)
		
def WRITE_HEADER(msg):
	if (System == "Windows"):
		print(msg)
	else:
		print (HEADER + msg + ENDC)

if __name__ == '__main__':
	print("in")
	WRITE_BLUE("test")
	WRITE_ERROR("test")
	WRITE_GREEN("test")
	WRITE_HEADER("test")
	WRITE_WARNING("test")
