import nmap



def main():
	nm = nmap.PortScanner()
	nm.scan('127.0.0.1', '22-443')
	a = nm.command_line()
	return a 

print(main())
