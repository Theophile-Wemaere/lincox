from src import toolbox

import socket
import re
import ping3
import nmap
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    
    response = ping3.ping(address,timeout=2)
    if response:
        return True
    return False

class PortScanner:

    def __init__(self,address:str):
        """
        address is an ip or a domain name
        """
        self.address = address

    def __tcp_connect(self, port:int):
        """
        test if a port is open by connecting to it
        """
        delay = 1 # 1 sec timeout
        TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCPsock.settimeout(delay)
        try:
            TCPsock.connect((self.address, port))
            return port
        except:
            return False

    def run(self,ports:list)-> list:
        """
        scan for open ports
        ports in an array of int
        return the array of port open
        """

        open_ports = []

        if len(ports) == 0:
            toolbox.debug("Warning, no ports to scan specified")
            return None

        num_concurrent = 300
        title = toolbox.get_header("INFO")+f"Testing ports on {self.address}"
        with alive_bar(len(ports), title=title, enrich_print=False) as bar:
            with ThreadPoolExecutor(max_workers=num_concurrent) as executor:
                
                future_to_line = {executor.submit(self.__tcp_connect, port): port for port in ports}

                for future in as_completed(future_to_line):
                    line = future_to_line[future]
                    result = future.result()
                    if result:
                        toolbox.debug(f"Port {result} is open")
                        open_ports.append(result)
                    bar()

        return open_ports

def nmap_scan(address: str, ports: str)-> dict:
    """
    perform NMAP scans on given ports
    address is a str (ip or domain)
    ports is a nnmap friendly str of ports
    return dict with open ports and service detected
    """

    open_ports = {}

    try:
        address = socket.gethostbyname(address)
    except Exception as e:
        toolbox.warn(f"{address} : {str(e)}")
        return {}

    nm = nmap.PortScanner()
    nm.scan(address, ports)

    for port in nm[address]['tcp'].keys():
        data = nm[address]['tcp'][port]
        if data["state"] == "open":
            open_ports[port] = {}
            open_ports[port]["name"] = data["name"]
            open_ports[port]["product"] = data["product"]
            open_ports[port]["version"] = data["version"]
            open_ports[port]["cpe"] = data["cpe"]
            toolbox.tprint(f"Port {port} is open : {data['name']}/{data['product']}")

    return open_ports