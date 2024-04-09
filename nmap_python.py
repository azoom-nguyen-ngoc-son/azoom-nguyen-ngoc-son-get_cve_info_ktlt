import nmap
import requests
import re
import json

def get_version_apa(host,port):
	# send head request to host ip
		req = requests.head("http://{}".format(host))
		#filter result to get version of apache server 
		filter_req = re.search(r"/.* ",req.headers['Server']).group()
		return filter_req[1:-1:]


def regex_version_id(ver_apa):
	#send request to cvedetails.com to get version_id of apache on website
	 
	for n in range(1,12):
	#send request from page 1 to page 2 to get reponse
		
		headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
	
		req_get_response = requests.get("https://www.cvedetails.com/version-list/45/66/{}/Apache-Http-Server.html?order=1".format(n),headers=headers)
		# regex the reponse to get output 
		# output will look like:  [/vulnerability-list/vendor_id-45/product_id-66/version_id-323322/Apache-Http-Server-2.4.50.html]
		get_ver_id = re.findall(r'href="/version/....../Apache-Http-Server-{}.html"'.format(str(ver_apa)),str(req_get_response.content))
		
		return get_ver_id


def nmap_scan_port():

	try:
		host = input("input host : ")
		begin_port = int(input("Begining port : "))
		end_port = int(input("Ending port: "))
		min_port = 1
		max_port = 65535
		
		
		if (begin_port >= min_port and end_port <= max_port):
			for i in range(begin_port, end_port + 1 ):
				sc = nmap.PortScanner()
				result = sc.scan(host,'{}'.format(i))
				result = json.dumps(result, indent = 4) 	
				print(result)
		else:
			print("Invalid Port")
	except ValueError:
		print("Invalid input")
	menu()

def get_cve_info(apache_version):
    url = "https://vulners.com/api/v3/burp/software/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Content-Type": "application/json"
    }
    data = {
        "software": f"cpe:/a:apache:http_server:{apache_version}",
        "version": apache_version,
        "type": "cpe"
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    cve_info = response.json()

    # Extract data from the JSON object
    cve_list = []
    for item in cve_info['data']['search']:
        cve_list.append({
            'cvelist': item['_source']['cvelist']
        })

    return cve_list

def nmap_scan_vul():
	host = input("input host : ")
	port = input("input port ")

	ver_apa = get_version_apa(host,port)
	lst_ver_id = regex_version_id(ver_apa)

	if len(lst_ver_id) >= 1:
		for i in lst_ver_id:
			filtered = re.search(r"\bversion.*/",i).group()		
			ver_id =re.search(r'(\d+\.\d+\.\d+)', i).group(1)
			sc = nmap. PortScanner()
			result = get_cve_info(ver_id)
			unique_cves = set()  # Sử dụng set để loại bỏ các giá trị trùng lặp
			for item in result:
				unique_cves.update(item['cvelist'])
			print(list(unique_cves))
			print("Total CVE found: ", len(list(unique_cves)))
	else:
		 print("Not found CVE for apache version {}".format(ver_apa))
	

def menu():
	try:
		print("-----------------------NMAP SCANNING TOOL---------------------------")
		print("1. Scan open port  ")
		print("2. Scan CVE of version Apache version")
		print("3. Exit ")
		answer = int(input("please input an answer "))
		match answer:
			case 1: 
				nmap_scan_port(),
			case 2: 
				nmap_scan_vul(),
			case 3:
				exit()
	except ValueError:
		print("Invalid input")
	menu()
	
if __name__ == "__main__":
	menu()
