#Author: Dragon
#Filename：One click IP address blocking script
import requests
import urllib3
import re
import json
from urllib3.exceptions import InsecureRequestWarning

# Function to read IP addresses from a file
def read_ip_list(file_path):
    ip_list = []
    with open(file_path, 'r') as file:
        for line in file:
            ip = line.strip()
            if ip:
                ip_list.append(ip)
    return ip_list

# Read the blacklist IP addresses from the file
blacklist_ip_file_path = 'blacklist_ips.txt'
blacklist_ip_list = read_ip_list(blacklist_ip_file_path)
# Convert IP list to the required JSON format for blists
blacklist_ips_json = json.dumps([{"blist": ip} for ip in blacklist_ip_list])

# IP addresses to process
IpList = ['192.168.2.168','192.168.2.169','.....'] 

common_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

# Disable insecure request warnings
urllib3.disable_warnings(InsecureRequestWarning)

# Function to process each IP
def process_ip(ip):
    with requests.Session() as s:
        url_1 = f'https://{ip}/login.html'
        url_2 = f'https://{ip}/webui/?g=sec_ad_blacklist_add'
        url_3 = f'https://{ip}/logout.php'
        
        headers_1 = {
            **common_headers,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': ip,
            'Origin': f'https://{ip}',
            'Referer': f'https://{ip}/login.html',
        }
        
        data_1 = {
            'USER': 'admin',
            'PASSWORD': 'admin,
            'lang': '2'
        }
        
        response = s.post(url_1, data=data_1, headers=headers_1, verify=False, allow_redirects=False)
        print(f"Login status for {ip}: {response.status_code}")
        
        if response.status_code == 200:
            set_cookie = response.headers.get('Set-Cookie')
            if set_cookie:
                cookie_value = re.search(r'[a-z0-9]+(?=;)', set_cookie)
                if cookie_value:
                    cookie_value = cookie_value.group()
                    s.cookies.set('USGSESSID', cookie_value)
                    print(f"Cookie set for {ip}: {cookie_value}")
        
        headers_2 = {
            **common_headers,
            'Host': ip,
            'Referer': f'https://{ip}/webui/?g=sec_ad_blacklist_show',
        }
        
        response = s.get(url_2, headers=headers_2, verify=False)
        print(f"Access blacklist add page status for {ip}: {response.status_code}")
        
        if response.status_code == 200:
            html_content = response.text
            token_value = re.search(r'(?<=value=")[a-zA-Z0-9]+(?="\s/>)', html_content)
            if token_value:
                token_value = token_value.group()
                print(f"Token retrieved for {ip}: {token_value}")
        
        blacklist_data = {
            'enable': '1',
            'blists': blacklist_ips_json,
            'age': '-1',
            'custom': '0',
            'reason': '手动添加',
            'submit_post': 'sec_ad_blacklist_addsave',
            'token': token_value
        }
        
        response = s.post(url_2, headers=headers_2, data=blacklist_data, verify=False)
        print(f"Blacklist add request for {ip}: {response.status_code}")
        print(f"Response content: {response.content.decode('utf-8')}")
        if response.status_code == 200:
            print(f"Successfully added blacklist entries for {ip}.")
        else:
            print(f"Failed to add blacklist entries for {ip}.")
        
        response = s.get(url_3, headers=headers_2, verify=False)
        print(f"Logout status for {ip}: {response.status_code}")

for ip in IpList:
    process_ip(ip)
