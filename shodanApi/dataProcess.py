from colorama import Fore, Back, Style
import csv
import sys
import re
from terminaltables import SingleTable

class Table:
    def __init__(self, verify=False):
        self.data = [
    ['IP', 'Domain' , 'Vulnerability']
    ]

    def table_csv(self):
        regexOfDomain = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
        regexOfCVE = "CVE-\d{4}-\d{4,7}"

        ex1 = open('test.csv')
        ex1 = csv.reader(ex1)
        list_IP = []
        list_domain = []
        list_CVE = []

        for i in ex1:
            list_IP.append(str(i[0]))
            list_domain.append(str(i[1]))
            list_CVE.append(str(i[2]))

        ## Get ip
        lisOf_ip = []
        for x in list_IP:
            lisOf_ip.append(x) 

        ## Get representatives of CVE
        repre_cve = []
        for cve in list_CVE:
            if cve == " ":
                repre_cve.append(" ")
            else:
                com_cve = re.findall(regexOfCVE,cve)
                repre_cve.append(com_cve[0])

        # Get representatives of domain
        first_domain = []
        for domain in list_domain:
            if domain == "[]" or domain == " ":
                first_domain.append(" ")
            else:
                com_domain = re.findall(regexOfDomain,domain)
                first_domain.append(com_domain[0])

        # Put first elements of api to table
        for i in range(0,50):
            self.data.append([lisOf_ip[i],first_domain[i],repre_cve[i]])

        table = SingleTable(self.data)
        print(Fore.GREEN,table.table)

# def check_proxyLogon(target):
#     user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0)"
#     try:
#         rq = requests.get("https://%s/ecp/x.js" % target, headers={"Cookie": "X-BEResource=localhost~1942062522","User-Agent": user_agent}, verify=False, timeout=2)
#         if "X-CalculatedBETarget" in rq.headers and "X-FEServer" in rq.headers:
#             print(Fore.RED,"ProxyLogon vulnerability exists ")
#             return "x"
#         else:
#             print(Fore.GREEN,"ProxyLogon vulnerability not exists ")
#             return " "
#     except HTTPError as http_err:
#         print(Fore.YELLOW,f'HTTP error occurred: {http_err}')  
#     except Exception as err:
#         print(Fore.YELLOW,f'Other error occurred: {err}')