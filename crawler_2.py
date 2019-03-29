import requests
import re
import json


burp0_url = "https://uncoder.io:443/"
burp0_cookies = {"theme": "1", "PHPSESSID": "a969cbebb9be062e7a87e0377f3a4962"}
burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
content = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
content = content.content.decode("utf-8")
pattern = re.compile(r'value="(.*)"')

words_array = []
for words in re.findall(pattern, content):
    words_array.append(words)

response_1_arr = []
for i in words_array:
    burp0_url = "https://uncoder.io:443/index/load-document/" + i
    burp0_cookies = {"theme": "1", "PHPSESSID": "a969cbebb9be062e7a87e0377f3a4962"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0",
                     "Accept": "application/json, text/javascript, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5",
                     "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest",
                     "Referer": "https://uncoder.io/", "Connection": "close"}
    response_1 = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies).content.decode("utf-8")
    response_1_arr.append(response_1)

response_data = json.loads(json.dumps(response_1_arr))
pattern_2 = re.compile(r'(?<=sigma_text":")(.*)(?=\","g)')

words_array_2 = []
for words_2 in response_data:
    for k in re.findall(pattern_2, words_2):
        words_array_2.append(k)  # words_array_2 gerekli elementleri barındırıyor.

new_words_array = []
for line in words_array_2:
    line = line.replace('\\n', '\n')
    line = line.replace('\\u003E', r'>')
    line = line.replace('\\u003C', r'<')
    line = line.replace('\\u0027', r"'")
    line = line.replace('\\u0022', r'"')
    line = line.replace('\\u0026', r'&')
    line = line.replace('\\\\', '\\')
    new_words_array.append(line)

last_array = []
for lines in new_words_array:
    lines = lines.replace("\'", r"'")
    lines = lines.replace('\"', r'"')
    lines = lines.replace("\\/", r"/")
    last_array.append(lines)


son = []
for m in range(0, 159):
    burp0_url = "https://uncoder.io:443/index/processing/"
    burp0_cookies = {"theme": "1", "PHPSESSID": "a969cbebb9be062e7a87e0377f3a4962"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0", "Accept": "application/json, text/javascript, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "X-Requested-With": "XMLHttpRequest", "Referer": "https://uncoder.io/", "Connection": "close"}
    burp0_data = {'"siemTo": "qradar", "siemFrom": "sigma", "shareQuery": "false","text:" "' + last_array[m]}
    burp1_data = {"text": "title: Network Scans\ndescription: Detects many failed connection attempts to different ports or hosts\nauthor: Thomas Patzke\nlogsource:\n    category: firewall\ndetection:\n    selection:\n        action: denied\n    timeframe: 24h\n    condition:\n        - selection | count(dst_port) by src_ip > 10\n        - selection | count(dst_ip) by src_ip > 10\nfields:\n    - src_ip\n    - dst_ip\n    - dst_port\nfalsepositives:\n    - Inventarization systems\n    - Vulnerability scans\n    - Penetration testing activity\nlevel: medium\n", "shareQuery": "false", "siemFrom": "sigma", "siemTo": "qradar"}
    response_son = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=b'burp0_data').content.decode("utf-8")
    son.append(response_son)

