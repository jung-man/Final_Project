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
        list_proxyLogon = []
        for i in ex1:
            list_IP.append(str(i[0]))
            list_domain.append(str(i[1]))
            list_CVE.append(str(i[2]))
            list_proxyLogon.append(str(i[3]))

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

        #Get infor proxyLogon
        logon = []
        for ex in list_proxyLogon:
            logon.append(ex)

        # Put first elements of api to table
        for i in range(0,50):
            self.data.append([lisOf_ip[i],first_domain[i],repre_cve[i],logon[i]])

        table = SingleTable(self.data)
        print(table.table)
    
