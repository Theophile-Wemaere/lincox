from src import toolbox

import socket
import re
import ping3
import threading
import nmap

def get_domain(url)-> str:
    """
    take a URL str as arg
    return domain as str
    """

    ip_regex = r"^(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})$"
    domain_regex = r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)"


    if re.match(ip_regex,url):
        address = re.match(ip_regex,url).group(1)
    # else try domain name
    elif re.match(domain_regex,url):
        address = re.match(domain_regex,url).group(1) # isdomain
    else:
        address = -1

    return address
    


def ping_target(address: str)-> bool:
    """
    check if target is alive
    """

    if address == None:
        toolbox.exit_error("Error, trying to ping but no address specified",1)
    
    response = ping3.ping(address)
    if response:
        return True
    return False

def scan_ports(address:str, ports:list)-> list:
    """
    scan for open ports
    address is a str (ip or domain)
    ports in an array of int
    return the array of port open
    """

    open_ports = []

    if len(ports) == 0:
        toolbox.debug("Warning, no ports to scan specified")
        return None

    def TCP_connect(ip, port):

        delay = 3 # 3 sec timeout
        TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCPsock.settimeout(delay)
        try:
            TCPsock.connect((ip, port))
            toolbox.debug(f"Port {port} open")
            open_ports.append(port)
        except:
            pass
            # toolbox.debug(f"Port {port} not open")

    threads = []

    for port in ports: 
        t = threading.Thread(target=TCP_connect, args=(address, port))
        threads.append(t)

    # Starting threads
    for i in range(len(ports)):
        threads[i].start()

    # Locking the main thread until all threads complete
    for i in range(len(ports)):
        threads[i].join()

    return open_ports

def nmap_scan(address: str, ports: str)-> dict:
    """
    perform NMAP scans on given ports
    address is a str (ip or domain)
    ports is a nnmap friendly str of ports
    return dict with open ports and service detected
    """

    open_ports = {}

    address = socket.gethostbyname(address)

    nm = nmap.PortScanner()
    nm.scan(address, ports)

    for port in nm[address]['tcp'].keys():
        data = nm[address]['tcp'][port]
        if data["state"] == "open":
            open_ports[port] = {}
            open_ports[port]["name"] = data["name"]
            open_ports[port]["product"] = data["product"]
            toolbox.tprint(f"Port {port} is open : {data['name']}/{data['product']}")

    return open_ports