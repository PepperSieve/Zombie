import requests

proxies = {"http": "http://127.0.0.1:65432", "https": "http://127.0.0.1:65432"}
# requests.get("https://1.1.1.1//dns-query?dns=B-QBAAABAAAAAAAAA3d3dwViYWlkdQNjb20AAAEAAQ", proxies=proxies, verify=False)
# response = requests.get("https://1.1.1.1//dns-query?dns=B-QBAAABAAAAAAAAA3d3dwViYWlkdQNjb20AAAEAAQ")
requests.get("https://1.1.1.1/dns-query?name=www.baidu.com", headers={'Accept': 'application/dns-json'}, proxies=proxies, verify=False)
# print(response)