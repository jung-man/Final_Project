import requests
from requests.models import HTTPError
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
from colorama import Fore, Back, Style

class Check_proxyLogon:
    def __init__(self, target):
        self.target = target
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0)"
    def check_proxyLogon(self):
        try:
            rq = requests.get("https://%s/ecp/x.js" % self.target, headers={"Cookie": "X-BEResource=localhost~1942062522","User-Agent": self.user_agent}, verify=False, timeout=2)
            if "X-CalculatedBETarget" in rq.headers and "X-FEServer" in rq.headers:
                print(Fore.RED,"ProxyLogon vulnerability exists ")
                return "x"
            else:
                print(Fore.GREEN,"ProxyLogon vulnerability not exists ")
                return " "
        except HTTPError as http_err:
            print(Fore.YELLOW,f'HTTP error occurred: {http_err}')  
        except Exception as err:
            print(Fore.YELLOW,f'Other error occurred: {err}')

# def main():
#     target = '101.99.20.181'
#     check = Check_proxyLogon(target)
#     check.check_proxyLogon()       
    
# main()