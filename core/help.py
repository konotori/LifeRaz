from tabulate import tabulate


def home():
    print("")
    print("Core Commands")
    print("=============")
    print("")
    print("Command         Description")
    print("-------         -----------")
    print("help            Print out help")
    print("scan            Scan url information and vulnerability")
    print("exploit         Exploit vulnerability")
    print("clr             Clear screen")
    print("clean           Clean log files")
    print("exit            Exit framework")
    print("")

def scan():
    print("")
    print("Core Commands")
    print("=============")
    print("set                  Set url to scan")
    print("execute              Execute scanning")
    print("show options         Show options of scanning")
    print("clr                  Clear screen")
    print("back                 Back to home")
    print("clean                Clean log files")
    print("exit                 Exit framework")
    print("")

def exploit():
    print("")
    print("Core Commands")
    print("=============")
    print("show [option]        Show information of payload")
    print("                     [all] - List payloads")
    print("                     [order] - Information of payload")
    print("use                  Choose payload to exploit")
    print("clr                  Clear screen")
    print("back                 Back to home")
    print("clean                Clean log files")
    print("exit                 Exit framework")
    print("")


def payload_list():
    print("")
    header = ["Order", "Name", "Description"]
    data = [(1, "Java Deserialization", "Exploit through Java Serialization Vulnerability"),
            (2, "Json Unauthenticated", "Create admin account illegal")]
    print(tabulate(data, headers=header))
    print("")

def use_payload():
    print("")
    print("Core Commands")
    print("=============")
    print("show options                 Show options of payload")
    print("set [options] [value]        Set value for payload's options")
    print("execute        		Execute the payload")
    print("clr                          Clear screen")
    print("back                         ack to exploit function")
    print("clean                        Clear log files")
    print("exit                         exit framework")
    print("")
